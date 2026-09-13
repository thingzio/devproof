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
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/fault"
)

// fakeRegistry is a minimal OCI Distribution server.
//
// A real registry lives behind a build tag in registry_integration_test.go.
// This one exists to exercise the failure paths that a conformant registry
// will not produce on demand: a 401, a 403, a manifest that comes back
// different from what was pushed, a tag that moves mid-operation.
type fakeRegistry struct {
	server *httptest.Server

	blobs     map[string][]byte
	manifests map[string][]byte
	tags      map[string]string

	// status, when set for a path substring, is returned instead of serving.
	status map[string]int
	// corruptManifest replaces manifest content on read, leaving the
	// reported digest alone.
	corruptManifest atomic.Bool
	// reportWrongDigest makes the registry claim a digest other than the one
	// that was asked for.
	reportWrongDigest atomic.Bool
	// tagMoves swaps what a tag resolves to after the first resolution.
	tagMoves  atomic.Bool
	movedTo   string
	pushCount atomic.Int64
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()

	f := &fakeRegistry{
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
		tags:      map[string]string{},
		status:    map[string]int{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

// host returns the registry host, for building references.
func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.server.URL, "http://") }

func (f *fakeRegistry) reference(t *testing.T, target string) artifact.Reference {
	t.Helper()
	ref, err := artifact.ParseReference("oci://" + f.host() + "/team/config" + target)
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	return ref
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	for fragment, code := range f.status {
		if strings.Contains(r.URL.Path, fragment) {
			w.WriteHeader(code)
			return
		}
	}

	switch {
	case r.URL.Path == "/v2/":
		w.WriteHeader(http.StatusOK)

	case strings.Contains(r.URL.Path, "/blobs/uploads/"):
		f.handleUpload(w, r)

	case strings.Contains(r.URL.Path, "/blobs/"):
		f.handleBlob(w, r)

	case strings.Contains(r.URL.Path, "/manifests/"):
		f.handleManifest(w, r)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeRegistry) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		w.Header().Set("Location", r.URL.Path+"session")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	body, _ := io.ReadAll(r.Body)
	digest := r.URL.Query().Get("digest")
	f.blobs[digest] = body
	f.pushCount.Add(1)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeRegistry) handleBlob(w http.ResponseWriter, r *http.Request) {
	digest := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	body, ok := f.blobs[digest]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", "application/octet-stream")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", itoa(len(body)))
		return
	}
	_, _ = w.Write(body)
}

func (f *fakeRegistry) handleManifest(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]

	if r.Method == http.MethodPut {
		body, _ := io.ReadAll(r.Body)
		digest := digestString(body)
		f.manifests[digest] = body
		if !strings.HasPrefix(target, "sha256:") {
			f.tags[target] = digest
		}
		f.pushCount.Add(1)
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	digest := target
	if resolved, ok := f.tags[target]; ok {
		digest = resolved
		if f.tagMoves.Load() && f.movedTo != "" {
			digest = f.movedTo
		}
	}
	body, ok := f.manifests[digest]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.corruptManifest.Load() {
		body = append(append([]byte{}, body...), ' ')
	}
	reported := digest
	if f.reportWrongDigest.Load() {
		reported = digestString([]byte("something else entirely"))
	}
	w.Header().Set("Docker-Content-Digest", reported)
	w.Header().Set("Content-Type", artifact.MediaTypeImageManifest)
	w.Header().Set("Content-Length", itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func digestString(b []byte) string {
	return artifact.DescriptorFor("x", b).Digest
}

// testRegistry returns a transport pointed at the fake. PlainHTTP because
// httptest serves over HTTP; production callers reach this only through the
// explicitly named WithInsecureRegistry option.
func testRegistry(*fakeRegistry) *Registry {
	return NewRegistry(RegistryOptions{PlainHTTP: true})
}

func TestRegistryPushFetchRoundTrip(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	ref := fake.reference(t, "")
	content := []byte("layer bytes")
	descriptor := artifact.DescriptorFor("application/vnd.oci.image.layer.v1.tar+gzip", content)

	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(content)); err != nil {
		t.Fatalf("Push: %v", err)
	}

	reader, err := registry.Fetch(t.Context(), ref, descriptor)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("round trip returned %q", got)
	}
}

// Storage is content-addressed, so a second push of the same descriptor can
// only be the same bytes. Treating that as fatal would make a retried
// publication fail on its second attempt.
func TestRegistryPushIsIdempotent(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	ref := fake.reference(t, "")
	content := []byte("same bytes")
	descriptor := artifact.DescriptorFor("application/octet-stream", content)

	for i := range 3 {
		if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(content)); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
}

func TestRegistryResolveTagToDigest(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	manifest := []byte(`{"schemaVersion":2}`)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)

	ref := fake.reference(t, "")
	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := registry.Tag(t.Context(), ref, descriptor, "v1"); err != nil {
		t.Fatalf("Tag: %v", err)
	}

	resolved, err := registry.Resolve(t.Context(), fake.reference(t, ":v1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Digest != descriptor.Digest {
		t.Errorf("tag resolved to %s, want %s", resolved.Digest, descriptor.Digest)
	}
}

// A registry that answers a digest request by naming different content is
// broken or hostile, and nothing it says afterwards can be trusted.
func TestRegistryResolveRejectsDigestSubstitution(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	manifest := []byte(`{"schemaVersion":2}`)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)
	ref := fake.reference(t, "")
	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("Push: %v", err)
	}

	fake.reportWrongDigest.Store(true)

	_, err := registry.Resolve(t.Context(), fake.reference(t, "@"+descriptor.Digest))
	if !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q (%v)", fault.CodeOf(err), fault.CodeDigestMismatch, err)
	}
}

// Content that does not hash to its descriptor must not reach the caller,
// whatever the registry claims in its headers.
func TestRegistryFetchRejectsCorruptedContent(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	manifest := []byte(`{"schemaVersion":2}`)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)
	ref := fake.reference(t, "")
	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("Push: %v", err)
	}

	fake.corruptManifest.Store(true)

	reader, err := registry.Fetch(t.Context(), ref, descriptor)
	if err != nil {
		// Some readers reject at open time, which is equally correct.
		return
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()

	if readErr == nil && closeErr == nil && bytes.Equal(body, manifest) {
		t.Error("corrupted content was returned as if it matched its descriptor")
	}
}

func TestRegistryClassifiesAuthFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		code   fault.Code
	}{
		{"unauthorized", http.StatusUnauthorized, fault.CodeAuthentication},
		{"forbidden", http.StatusForbidden, fault.CodeAuthorization},
		{"not found", http.StatusNotFound, fault.CodeInvalidArtifact},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeRegistry(t)
			fake.status["/manifests/"] = tc.status

			registry := testRegistry(fake)
			defer func() { _ = registry.Close() }()

			_, err := registry.Resolve(t.Context(), fake.reference(t, ":v1"))
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q (%v)", fault.CodeOf(err), tc.code, err)
			}
			// An authentication or authorization failure must never be
			// marked transient: retrying is how an account gets locked out.
			if tc.code != fault.CodeTransport && fault.IsTransient(err) {
				t.Errorf("a %s failure was classified transient", tc.name)
			}
		})
	}
}

func TestRegistryRejectsLayoutReference(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(RegistryOptions{})
	defer func() { _ = registry.Close() }()

	ref, err := artifact.ParseReference("oci-layout://./artifact")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if _, err := registry.Resolve(t.Context(), ref); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestRegistryHonorsCancellation(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := registry.Resolve(ctx, fake.reference(t, ":v1")); err == nil {
		t.Error("a canceled resolve succeeded")
	}
}

// Credentials are looked up per host, so a credential issued for one registry
// is never offered to another (DP-013).
func TestRegistryScopesCredentialsToHost(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)

	var asked []string
	registry := NewRegistry(RegistryOptions{
		PlainHTTP: true,
		Credentials: artifact.CredentialFunc(func(_ context.Context, host string) (artifact.Credential, error) {
			asked = append(asked, host)
			return artifact.Credential{}, nil
		}),
	})
	defer func() { _ = registry.Close() }()

	manifest := []byte(`{"schemaVersion":2}`)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)
	ref := fake.reference(t, "")
	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("Push: %v", err)
	}

	for _, host := range asked {
		if host != fake.host() {
			t.Errorf("credentials were requested for %q, but the operation addressed %q",
				host, fake.host())
		}
	}
}

func TestRegistryScheme(t *testing.T) {
	t.Parallel()

	registry := NewRegistry(RegistryOptions{})
	defer func() { _ = registry.Close() }()

	if registry.Scheme() != artifact.SchemeRegistry {
		t.Errorf("Scheme() = %q", registry.Scheme())
	}
}

// A digest mismatch must never be classified transient. Retrying a registry
// that is serving the wrong bytes just asks it again, and a retry loop
// against a hostile registry is worse than a clean failure.
func TestDigestMismatchIsNeverTransient(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	manifest := []byte(`{"schemaVersion":2}`)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)
	ref := fake.reference(t, "")
	if err := registry.Push(t.Context(), ref, descriptor, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("Push: %v", err)
	}

	fake.reportWrongDigest.Store(true)

	_, err := registry.Resolve(t.Context(), fake.reference(t, "@"+descriptor.Digest))
	if err == nil {
		t.Fatal("a digest substitution was accepted")
	}
	if fault.IsTransient(err) {
		t.Error("a digest mismatch was classified transient, so it would be retried")
	}
}

// A tag that moves between operations must not change what an already-pinned
// reference fetches (DP-007).
func TestMovedTagDoesNotAffectAPinnedReference(t *testing.T) {
	t.Parallel()

	fake := newFakeRegistry(t)
	registry := testRegistry(fake)
	defer func() { _ = registry.Close() }()

	ref := fake.reference(t, "")

	original := []byte(`{"schemaVersion":2,"generation":1}`)
	originalDescriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, original)
	if err := registry.Push(t.Context(), ref, originalDescriptor, bytes.NewReader(original)); err != nil {
		t.Fatalf("pushing the original: %v", err)
	}
	if err := registry.Tag(t.Context(), ref, originalDescriptor, "latest"); err != nil {
		t.Fatalf("Tag: %v", err)
	}

	// Resolve the tag once, exactly as an operation does.
	resolved, err := registry.Resolve(t.Context(), fake.reference(t, ":latest"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	pinned := ref.WithDigest(resolved.Digest)

	// The tag now points somewhere else.
	replacement := []byte(`{"schemaVersion":2,"generation":2}`)
	replacementDescriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, replacement)
	if err := registry.Push(t.Context(), ref, replacementDescriptor, bytes.NewReader(replacement)); err != nil {
		t.Fatalf("pushing the replacement: %v", err)
	}
	fake.movedTo = replacementDescriptor.Digest
	fake.tagMoves.Store(true)

	// The pinned reference still fetches what was resolved.
	reader, err := registry.Fetch(t.Context(), pinned, resolved)
	if err != nil {
		t.Fatalf("Fetch after the tag moved: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("a moved tag changed what a pinned reference fetched: got %q", got)
	}
}

// DP-013: a credential issued for one host must not follow a redirect to
// another. Go's HTTP client strips Authorization on a cross-host redirect,
// and this asserts that DevProof actually benefits from it rather than
// assuming so.
func TestCredentialsAreNotForwardedAcrossAHostChangingRedirect(t *testing.T) {
	t.Parallel()

	var sawAuthorization atomic.Bool
	var reached atomic.Bool

	// The second host records whether it was handed a credential.
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		if r.Header.Get("Authorization") != "" {
			sawAuthorization.Store(true)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	registry := NewRegistry(RegistryOptions{
		PlainHTTP: true,
		Credentials: artifact.CredentialFunc(func(context.Context, string) (artifact.Credential, error) {
			return artifact.Credential{Username: "user", Password: "secret"}, nil
		}),
	})
	defer func() { _ = registry.Close() }()

	ref, err := artifact.ParseReference("oci://" + strings.TrimPrefix(origin.URL, "http://") + "/team/config:v1")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	// The call is expected to fail; what matters is what the other host saw.
	_, _ = registry.Resolve(t.Context(), ref)

	if !reached.Load() {
		// Fatal, not skipped. If the redirect is never followed this test
		// asserts nothing and still reports success, which is how a
		// credential-leak check quietly stops being one.
		t.Fatal("the redirect was never followed; this test asserts nothing")
	}
	if sawAuthorization.Load() {
		t.Error("a credential was forwarded across a host-changing redirect")
	}
}
