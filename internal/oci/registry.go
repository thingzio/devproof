// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/thingzio/devproof/internal/version"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

const registryOp = "oci.registry"

// Registry is an OCI Distribution transport.
type Registry struct {
	credentials artifact.CredentialProvider
	client      *orasauth.Client
	// PlainHTTP disables TLS. Opt-in and prominent: it exists for a local
	// test registry, and using it against anything else sends credentials
	// and content in the clear.
	plainHTTP bool

	mu    sync.Mutex
	repos map[string]*remote.Repository
}

var (
	_ artifact.Transport         = (*Registry)(nil)
	_ artifact.ReferrerTransport = (*Registry)(nil)
)

// RegistryOptions configures a registry transport.
type RegistryOptions struct {
	// Credentials supplies per-host credentials. Nil means anonymous.
	Credentials artifact.CredentialProvider
	// PlainHTTP disables TLS.
	PlainHTTP bool
	// Timeout bounds a single request attempt.
	Timeout time.Duration
}

// defaultAttemptTimeout bounds one request. An overall operation deadline
// comes from the caller's context; this stops a single wedged connection from
// consuming all of it.
const defaultAttemptTimeout = 60 * time.Second

// NewRegistry returns a registry transport.
func NewRegistry(opts RegistryOptions) *Registry {
	credentials := opts.Credentials
	if credentials == nil {
		credentials = artifact.AnonymousCredentials
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultAttemptTimeout
	}

	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}

	r := &Registry{
		credentials: credentials,
		plainHTTP:   opts.PlainHTTP,
		repos:       make(map[string]*remote.Repository),
	}

	r.client = &orasauth.Client{
		// retry.NewClient applies bounded exponential backoff with jitter to
		// the classified-transient statuses only: 429 and 5xx. A 401 or a
		// 404 is never retried, because repeating an authentication failure
		// is how an account gets locked out.
		Client: &http.Client{Transport: retry.NewTransport(base), Timeout: timeout},
		Header: http.Header{"User-Agent": []string{version.UserAgent()}},
		Cache:  orasauth.NewCache(),
		Credential: func(ctx context.Context, host string) (orasauth.Credential, error) {
			// Host-scoped by construction: ORAS asks for the host it is about
			// to talk to, and a credential fetched for one host is never
			// offered to another.
			cred, err := r.credentials.Credential(ctx, host)
			if err != nil {
				return orasauth.EmptyCredential, fault.Wrap(fault.CodeAuthentication, registryOp,
					fmt.Sprintf("obtaining credentials for %s", host), err)
			}
			if cred.IsZero() {
				return orasauth.EmptyCredential, nil
			}
			return orasauth.Credential{
				Username:    cred.Username,
				Password:    cred.Password,
				AccessToken: cred.Token,
			}, nil
		},
	}
	return r
}

// Scheme is the reference scheme this transport handles.
func (r *Registry) Scheme() string { return artifact.SchemeRegistry }

// repository returns a cached client for a reference's repository.
func (r *Registry) repository(ref artifact.Reference) (*remote.Repository, error) {
	if ref.Scheme != artifact.SchemeRegistry {
		return nil, fault.New(fault.CodeInvalidInput, registryOp,
			fmt.Sprintf("reference scheme %q is not a registry reference", ref.Scheme))
	}
	key := ref.Locator()

	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.repos[key]; ok {
		return cached, nil
	}

	repo, err := remote.NewRepository(key)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, registryOp,
			fmt.Sprintf("addressing repository %s", key), err)
	}
	repo.Client = r.client
	repo.PlainHTTP = r.plainHTTP

	// The referrers API is used and nothing else, so that a registry without
	// one reports an error this package handles rather than a result it
	// silently produced another way.
	//
	// Left unset, oras-go probes for the API, falls back to the referrers tag
	// schema on its own, and returns success. Both modes then looked identical
	// here: every Referrers call reported StorageReferrers, including against a
	// registry whose referrers endpoint returns 404. That made
	// evidence.allowTagFallback -- the rule whose whole purpose is refusing the
	// fallback's replace-rather-than-accumulate semantics -- fire nowhere it
	// mattered, and made the fallback branch below unreachable (DP-028).
	if err := repo.SetReferrersCapability(true); err != nil {
		return nil, fault.Wrap(fault.CodeInternal, registryOp,
			"fixing the referrers capability", err)
	}

	r.repos[key] = repo
	return repo, nil
}

// Resolve freezes a reference to one descriptor.
func (r *Registry) Resolve(ctx context.Context, ref artifact.Reference) (artifact.Descriptor, error) {
	repo, err := r.repository(ref)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	target := ref.Target()
	if target == "" {
		return artifact.Descriptor{}, fault.New(fault.CodeInvalidInput, registryOp,
			"reference names neither a tag nor a digest")
	}

	descriptor, err := repo.Resolve(ctx, target)
	if err != nil {
		return artifact.Descriptor{}, classifyRegistryError(err,
			fmt.Sprintf("resolving %s", ref.Locator()))
	}

	resolved := fromOCIDescriptor(descriptor)

	// A digest reference must come back as itself. A registry that answered
	// with different content for a digest is either broken or hostile, and
	// either way nothing it says afterwards can be trusted.
	if ref.IsDigest() && resolved.Digest != ref.Digest {
		return artifact.Descriptor{}, fault.New(fault.CodeDigestMismatch, registryOp,
			fmt.Sprintf("asked for %s and the registry answered with %s", ref.Digest, resolved.Digest))
	}
	return resolved, nil
}

// Fetch returns the content a descriptor names.
func (r *Registry) Fetch(ctx context.Context, ref artifact.Reference, target artifact.Descriptor) (io.ReadCloser, error) {
	repo, err := r.repository(ref)
	if err != nil {
		return nil, err
	}
	if validateErr := target.Validate(); validateErr != nil {
		return nil, validateErr
	}

	descriptor, err := toOCIDescriptor(target)
	if err != nil {
		return nil, err
	}

	// A manifest and a blob are different endpoints in the distribution API,
	// so the media type decides which store answers.
	var reader io.ReadCloser
	if isManifestMediaType(target.MediaType) {
		reader, err = repo.Manifests().Fetch(ctx, descriptor)
	} else {
		reader, err = repo.Blobs().Fetch(ctx, descriptor)
	}
	if err != nil {
		return nil, classifyRegistryError(err,
			fmt.Sprintf("fetching %s", target.Digest))
	}
	return reader, nil
}

// Push stores content under its descriptor. Content that is already present
// is not an error.
func (r *Registry) Push(ctx context.Context, ref artifact.Reference, target artifact.Descriptor, content io.Reader) error {
	repo, err := r.repository(ref)
	if err != nil {
		return err
	}
	if validateErr := target.Validate(); validateErr != nil {
		return validateErr
	}

	descriptor, err := toOCIDescriptor(target)
	if err != nil {
		return err
	}

	store := repo.Blobs()
	if isManifestMediaType(target.MediaType) {
		store = repo.Manifests()
	}

	if err := store.Push(ctx, descriptor, content); err != nil {
		// Storage is content-addressed, so content already present under
		// this digest is the same content. Treating that as success makes a
		// retried publication idempotent rather than fatal.
		if stderrors.Is(err, errdef.ErrAlreadyExists) {
			return nil
		}
		return classifyRegistryError(err, fmt.Sprintf("pushing %s", target.Digest))
	}
	return nil
}

// Tag assigns a mutable name to an already-stored manifest.
func (r *Registry) Tag(ctx context.Context, ref artifact.Reference, target artifact.Descriptor, tag string) error {
	repo, err := r.repository(ref)
	if err != nil {
		return err
	}
	if tag == "" {
		return fault.New(fault.CodeInvalidInput, registryOp, "tag must not be empty")
	}
	if tagErr := validateTag(tag); tagErr != nil {
		return tagErr
	}

	descriptor, err := toOCIDescriptor(target)
	if err != nil {
		return err
	}
	if err := repo.Tag(ctx, descriptor, tag); err != nil {
		return classifyRegistryError(err, fmt.Sprintf("tagging %s", tag))
	}
	return nil
}

// Close releases idle connections.
func (r *Registry) Close() error {
	if transport, ok := r.client.Client.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// isManifestMediaType decides which distribution endpoint answers for a
// descriptor: manifests and blobs are separate APIs.
func isManifestMediaType(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex:
		return true
	default:
		return false
	}
}

func fromOCIDescriptor(d ocispec.Descriptor) artifact.Descriptor {
	return artifact.Descriptor{
		MediaType: d.MediaType,
		Digest:    d.Digest.String(),
		Size:      d.Size,
	}
}

func toOCIDescriptor(d artifact.Descriptor) (ocispec.Descriptor, error) {
	parsed, err := bundle.ParseDigest(d.Digest)
	if err != nil {
		return ocispec.Descriptor{}, fault.Wrap(fault.CodeInvalidArtifact, registryOp,
			"descriptor digest is invalid", err)
	}
	// The string form is used rather than re-encoding the parsed value so
	// that what goes on the wire is exactly what was validated.
	_ = parsed
	return ocispec.Descriptor{
		MediaType: d.MediaType,
		Digest:    digest.Digest(d.Digest),
		Size:      d.Size,
	}, nil
}

// classifyRegistryError maps a transport failure onto a typed code.
//
// The classification decides whether a retry is even considered, so the
// permanent cases are named explicitly rather than left to a catch-all:
// repeating an authentication failure is how an account gets locked out, and
// repeating a digest mismatch cannot produce different content.
func classifyRegistryError(err error, what string) error {
	switch {
	case err == nil:
		return nil
	case isDigestMismatch(err):
		// Never transport, and therefore never transient. Content that does
		// not hash to the digest it was requested under will not hash to it
		// on a second attempt either, and retrying a registry that is
		// serving the wrong bytes just asks it again.
		return fault.Wrap(fault.CodeDigestMismatch, registryOp,
			what+": the registry served content that does not match the digest requested", err)
	case stderrors.Is(err, errdef.ErrNotFound):
		return fault.Wrap(fault.CodeInvalidArtifact, registryOp, what+": not found", err)
	case isUnauthorized(err):
		return fault.Wrap(fault.CodeAuthentication, registryOp, what+": the registry rejected the credential", err)
	case isForbidden(err):
		return fault.Wrap(fault.CodeAuthorization, registryOp, what+": the credential lacks permission", err)
	case fault.IsNetwork(err):
		return fault.Wrap(fault.CodeTransport, registryOp, what, err).AsTemporary()
	default:
		if existing, ok := fault.AsError(err); ok {
			return existing
		}
		return fault.Wrap(fault.CodeTransport, registryOp, what, err)
	}
}

// isDigestMismatch reports whether a registry answered with content that does
// not match the digest it was asked for.
//
// The typed sentinel is checked first; the message match is a fallback,
// because misclassifying this as transient would turn a broken or hostile
// registry into a retry loop, and that is worth a fragile string.
func isDigestMismatch(err error) bool {
	if stderrors.Is(err, errdef.ErrInvalidDigest) {
		return true
	}
	return strings.Contains(err.Error(), "digest mismatch")
}

// statusCodeOf extracts the HTTP status from a registry error response.
func statusCodeOf(err error) int {
	if response, ok := stderrors.AsType[*errcode.ErrorResponse](err); ok {
		return response.StatusCode
	}
	return 0
}

func isUnauthorized(err error) bool { return statusCodeOf(err) == http.StatusUnauthorized }
func isForbidden(err error) bool    { return statusCodeOf(err) == http.StatusForbidden }

// Referrers lists evidence attached to a subject.
//
// Where the registry has no referrers API, the fallback tag is consulted
// instead and the storage mode says so. A caller that cannot accept the
// fallback's replace-rather-than-accumulate semantics can refuse it by
// policy, but only if it is told which mode answered (DP-028).
func (r *Registry) Referrers(
	ctx context.Context,
	ref artifact.Reference,
	subject artifact.Descriptor,
	artifactType string,
) ([]artifact.Descriptor, artifact.EvidenceStorage, error) {

	repo, err := r.repository(ref)
	if err != nil {
		return nil, "", err
	}
	descriptor, err := toOCIDescriptor(subject)
	if err != nil {
		return nil, "", err
	}

	var found []artifact.Descriptor
	err = repo.Referrers(ctx, descriptor, artifactType, func(page []ocispec.Descriptor) error {
		for _, item := range page {
			found = append(found, fromOCIDescriptor(item))
			if int64(len(found)) > maxReferrers {
				return fault.New(fault.CodeLimitExceeded, registryOp,
					fmt.Sprintf("subject has more than %d referrers", maxReferrers))
			}
		}
		return nil
	})
	if err == nil {
		return found, artifact.StorageReferrers, nil
	}
	if !stderrors.Is(err, errdef.ErrUnsupported) {
		return nil, "", classifyRegistryError(err, "listing referrers")
	}

	// No referrers API. Fall back to the tag scheme.
	subjectDigest, err := subject.ParsedDigest()
	if err != nil {
		return nil, "", err
	}
	fallback := ref
	fallback.Tag = artifact.FallbackTag(subjectDigest)
	fallback.Digest = ""

	resolved, err := r.Resolve(ctx, fallback)
	if err != nil {
		if stderrors.Is(err, fault.CodeInvalidArtifact) {
			// No evidence under the fallback tag is an empty set, not a
			// failure: a subject with no evidence is an ordinary state.
			return nil, artifact.StorageTagFallback, nil
		}
		return nil, "", err
	}
	return []artifact.Descriptor{resolved}, artifact.StorageTagFallback, nil
}

// maxReferrers bounds referrer enumeration. A repository is an open
// attachment surface, so the listing is somebody else's input.
const maxReferrers = 4096

// Attach stores an evidence blob and the referrer manifest naming it.
func (r *Registry) Attach(
	ctx context.Context,
	ref artifact.Reference,
	subject artifact.Descriptor,
	blob artifact.Descriptor,
	content io.Reader,
	artifactType string,
) (artifact.Descriptor, artifact.EvidenceStorage, error) {

	// The blob first, then the empty config, then the manifest that names
	// them: the same ordering rule publication follows, for the same reason.
	if pushErr := r.Push(ctx, ref, blob, content); pushErr != nil {
		return artifact.Descriptor{}, "", pushErr
	}
	if pushErr := r.Push(ctx, ref, artifact.EmptyDescriptor(),
		bytes.NewReader(artifact.EmptyJSONContent)); pushErr != nil {
		return artifact.Descriptor{}, "", pushErr
	}

	manifest := artifact.NewReferrerManifest(subject, blob, artifactType)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return artifact.Descriptor{}, "", fault.Wrap(fault.CodeInternal, registryOp,
			"encoding the referrer manifest", err)
	}
	manifestDescriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, encoded)

	if pushErr := r.Push(ctx, ref, manifestDescriptor, bytes.NewReader(encoded)); pushErr != nil {
		return artifact.Descriptor{}, "", pushErr
	}

	// Whether the registry understood the subject field decides the storage
	// mode. Asking afterwards rather than probing first means one round trip
	// rather than two, and the answer is the one that actually applies.
	_, storage, err := r.Referrers(ctx, ref, subject, artifactType)
	if err != nil {
		return manifestDescriptor, "", err
	}
	if storage == artifact.StorageTagFallback {
		subjectDigest, digestErr := subject.ParsedDigest()
		if digestErr != nil {
			return manifestDescriptor, "", digestErr
		}
		if tagErr := r.Tag(ctx, ref, manifestDescriptor,
			artifact.FallbackTag(subjectDigest)); tagErr != nil {
			return manifestDescriptor, "", tagErr
		}
	}
	return manifestDescriptor, storage, nil
}
