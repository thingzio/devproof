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

package devproof

import (
	"context"
	"encoding/json"
	"os"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/evidence"
)

const inspectOp = "inspect"

// Confidence records how a reported fact was established.
//
// Marking every fact is what stops an inspect report reading as a
// verification. "The manifest says this URL" and "a signature proves this
// URL" look identical in a flat listing, and only one of them is evidence.
type Confidence string

const (
	// ConfidenceAuthored means a human wrote it in a manifest. It is intent,
	// not fact.
	ConfidenceAuthored Confidence = "authored"
	// ConfidenceResolved means a resolver produced it, recorded in a lock.
	ConfidenceResolved Confidence = "resolved"
	// ConfidenceDigestVerified means content was checked against a digest.
	ConfidenceDigestVerified Confidence = "digest-verified"
	// ConfidenceSignatureVerified means a signature over it verified.
	ConfidenceSignatureVerified Confidence = "signature-verified"
	// ConfidencePolicyAccepted means a policy rule accepted it.
	ConfidencePolicyAccepted Confidence = "policy-accepted"
)

// InspectKind is what was inspected.
type InspectKind string

const (
	InspectKindBundle   InspectKind = "bundle"
	InspectKindManifest InspectKind = "manifest"
	InspectKindLock     InspectKind = "lock"
)

// InspectRequest asks for metadata without expanding anything.
type InspectRequest struct {
	// Reference is an OCI subject to inspect.
	Reference string
	// Path is a local manifest or lock file to inspect. Mutually exclusive
	// with Reference.
	Path string

	// Files includes the file inventory, which can be large.
	Files bool
	// Evidence includes referrer summaries.
	Evidence bool
	// EvidenceContent includes the decoded statements. Only statements whose
	// signatures verified are included; a statement that did not verify is
	// reported as rejected instead, never shown as though it were a fact.
	EvidenceContent bool

	Limits Limits
}

// InspectResult describes what was found.
type InspectResult struct {
	Kind InspectKind `json:"kind"`

	// Bundle facts, when a subject was inspected.
	Subject *SubjectInfo `json:"subject,omitempty"`
	// Manifest facts, when a manifest file was inspected.
	Manifest *ManifestInfo `json:"manifest,omitempty"`
	// Lock facts, when a lock file was inspected.
	Lock *LockInfo `json:"lock,omitempty"`
}

// SubjectInfo describes a bundle.
type SubjectInfo struct {
	Reference  string     `json:"reference"`
	Digest     string     `json:"digest"`
	TreeDigest string     `json:"treeDigest"`
	Format     string     `json:"format"`
	Confidence Confidence `json:"confidence"`

	FileCount  int64 `json:"fileCount"`
	TotalBytes int64 `json:"totalBytes"`
	LayerBytes int64 `json:"layerBytes"`

	ConfigDigest string `json:"configDigest"`
	LayerDigest  string `json:"layerDigest"`

	Files    []FileInfo     `json:"files,omitempty"`
	Evidence []EvidenceInfo `json:"evidence,omitempty"`
	// EvidenceStorage reports how evidence was found. The tag fallback
	// cannot express a set, so a caller needs to know which mode answered.
	EvidenceStorage string `json:"evidenceStorage,omitempty"`
	// RejectedEvidence lists candidates that did not verify.
	RejectedEvidence []string `json:"rejectedEvidence,omitempty"`
}

// FileInfo is one inventory entry.
type FileInfo struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// EvidenceInfo summarizes one verified evidence object.
type EvidenceInfo struct {
	Digest        string     `json:"digest"`
	PredicateType string     `json:"predicateType"`
	Identities    []string   `json:"identities"`
	Confidence    Confidence `json:"confidence"`
	// TransparencyLog reports whether a log inclusion proof verified.
	TransparencyLog bool `json:"transparencyLog"`
	// Statement is the decoded statement, when it was asked for. Present
	// only for evidence whose signatures verified.
	Statement *evidence.Statement `json:"statement,omitempty"`
}

// ManifestInfo describes a manifest file.
//
// Everything here is authored: it is what someone asked for, and none of it
// has been resolved or checked against anything.
type ManifestInfo struct {
	Path       string       `json:"path"`
	APIVersion string       `json:"apiVersion"`
	Name       string       `json:"name"`
	Digest     string       `json:"digest"`
	Confidence Confidence   `json:"confidence"`
	Sources    []SourceInfo `json:"sources"`
}

// SourceInfo is one declared source.
type SourceInfo struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	MountPath string   `json:"mountPath,omitempty"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
}

// LockInfo describes a lock file.
type LockInfo struct {
	Path           string             `json:"path"`
	Digest         string             `json:"digest"`
	ManifestDigest string             `json:"manifestDigest"`
	TreeDigest     string             `json:"treeDigest"`
	Format         string             `json:"format"`
	Confidence     Confidence         `json:"confidence"`
	FileCount      int                `json:"fileCount"`
	Sources        []LockedSourceInfo `json:"sources"`
	Files          []FileInfo         `json:"files,omitempty"`
}

// LockedSourceInfo is one resolved source.
type LockedSourceInfo struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Resolver   string         `json:"resolver"`
	TreeDigest string         `json:"treeDigest"`
	MountPath  string         `json:"mountPath,omitempty"`
	Requested  map[string]any `json:"requested,omitempty"`
	Resolved   map[string]any `json:"resolved,omitempty"`
}

// Inspect reports metadata without expanding payload content.
//
// It performs no remote mutation and writes nothing. Every fact it reports
// carries how it was established, so a reader can tell a claim from a proof.
func (c *Client) Inspect(ctx context.Context, req InspectRequest) (*InspectResult, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	switch {
	case req.Reference != "" && req.Path != "":
		return nil, fault.New(fault.CodeInvalidInput, inspectOp,
			"a reference and a path are mutually exclusive")
	case req.Reference != "":
		return c.inspectSubject(ctx, req)
	case req.Path != "":
		return c.inspectFile(req)
	default:
		return nil, fault.New(fault.CodeInvalidInput, inspectOp,
			"supply a reference or a path to inspect")
	}
}

func (c *Client) inspectSubject(ctx context.Context, req InspectRequest) (*InspectResult, error) {
	subject, pinned, err := c.loadSubject(ctx, VerifyRequest{
		Reference: req.Reference,
		Limits:    req.Limits,
	})
	if err != nil {
		return nil, err
	}

	info := &SubjectInfo{
		Reference:  pinned.String(),
		Digest:     subject.ManifestDigest.String(),
		TreeDigest: subject.TreeDigest.String(),
		Format:     subject.Config.Format.String(),
		// Everything above was checked against a digest on the way in; none
		// of it was merely read.
		Confidence:   ConfidenceDigestVerified,
		FileCount:    subject.Config.FileCount,
		TotalBytes:   subject.Config.TotalSize,
		LayerBytes:   subject.LayerSize,
		ConfigDigest: subject.ConfigDigest.String(),
		LayerDigest:  subject.LayerDigest.String(),
	}

	if req.Files {
		info.Files = make([]FileInfo, 0, len(subject.Config.Files))
		for _, file := range subject.Config.Files {
			info.Files = append(info.Files, FileInfo{
				Path: file.Path, Mode: file.Mode, Size: file.Size, Digest: file.Digest,
			})
		}
	}

	if req.Evidence || req.EvidenceContent {
		if err := c.inspectEvidence(ctx, pinned, subject, req, info); err != nil {
			return nil, err
		}
	}

	return &InspectResult{Kind: InspectKindBundle, Subject: info}, nil
}

func (c *Client) inspectEvidence(
	ctx context.Context,
	pinned artifact.Reference,
	subject *canonical.Subject,
	req InspectRequest,
	info *SubjectInfo,
) error {

	transport, err := c.transportFor(pinned)
	if err != nil {
		return err
	}

	limits := c.effectiveLimits(req.Limits)
	verified, rejected, storage, err := c.discoverEvidence(ctx, transport, pinned, subject, limits.Limits)
	if err != nil {
		return err
	}

	info.EvidenceStorage = storage
	for _, item := range verified {
		summary := EvidenceInfo{
			Digest:        item.digest,
			PredicateType: item.statement.PredicateType,
			// Signature-verified, not policy-accepted: inspect applies no
			// policy, so it cannot report that anybody decided to trust this.
			Confidence:      ConfidenceSignatureVerified,
			TransparencyLog: item.logVerified,
		}
		for _, identity := range item.identities {
			summary.Identities = append(summary.Identities, identity.String())
		}
		if req.EvidenceContent {
			summary.Statement = item.statement
		}
		info.Evidence = append(info.Evidence, summary)
	}
	for _, item := range rejected {
		info.RejectedEvidence = append(info.RejectedEvidence, item.digest+": "+item.reason)
	}
	return nil
}

// inspectFile reads a manifest or a lock.
//
// Which one it is is decided by parsing, not by the file name: a lock called
// devproof.yaml is still a lock, and guessing from an extension would report
// the wrong document kind with complete confidence.
func (c *Client) inspectFile(req InspectRequest) (*InspectResult, error) {
	data, err := os.ReadFile(req.Path) //nolint:gosec // caller-supplied path
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, inspectOp, "reading the file", err)
	}

	var probe struct {
		Kind string `json:"kind" yaml:"kind"`
	}
	// A lock is JSON, so JSON decoding identifies it cheaply. Anything else
	// goes to the manifest parser, which handles YAML and JSON both.
	_ = json.Unmarshal(data, &probe)

	if probe.Kind == bundle.KindBundleLock {
		return inspectLock(req, data)
	}
	return inspectManifest(req, data)
}

func inspectManifest(req InspectRequest, data []byte) (*InspectResult, error) {
	spec, err := bundle.ParseSpec(data)
	if err != nil {
		return nil, err
	}

	digest, _, err := canonical.JSONDigest(spec.Normalized())
	if err != nil {
		return nil, err
	}

	info := &ManifestInfo{
		Path:       req.Path,
		APIVersion: spec.APIVersion,
		Name:       spec.Metadata.Name,
		Digest:     digest.String(),
		// Authored: a manifest is what someone asked for. Nothing in it has
		// been resolved, fetched, or checked.
		Confidence: ConfidenceAuthored,
	}
	for i := range spec.Spec.Sources {
		source := &spec.Spec.Sources[i]
		info.Sources = append(info.Sources, SourceInfo{
			Name:      source.Name,
			Type:      source.Type,
			MountPath: source.MountPath,
			Include:   source.Include,
			Exclude:   source.Exclude,
		})
	}
	return &InspectResult{Kind: InspectKindManifest, Manifest: info}, nil
}

func inspectLock(req InspectRequest, data []byte) (*InspectResult, error) {
	lock, err := bundle.ParseLock(data)
	if err != nil {
		return nil, err
	}

	digest, _, err := canonical.JSONDigest(lock)
	if err != nil {
		return nil, err
	}

	info := &LockInfo{
		Path:           req.Path,
		Digest:         digest.String(),
		ManifestDigest: lock.ManifestDigest,
		TreeDigest:     lock.TreeDigest,
		Format:         lock.Format.String(),
		// Resolved: a lock records what resolvers produced. It is stronger
		// than authored and weaker than verified — nothing here has been
		// checked against the material it describes.
		Confidence: ConfidenceResolved,
		FileCount:  len(lock.Files),
	}
	for i := range lock.Sources {
		source := &lock.Sources[i]
		info.Sources = append(info.Sources, LockedSourceInfo{
			Name:       source.Name,
			Type:       source.Type,
			Resolver:   source.Resolver,
			TreeDigest: source.TreeDigest,
			MountPath:  source.MountPath,
			Requested:  source.Requested,
			Resolved:   source.Resolved,
		})
	}
	if req.Files {
		for i := range lock.Files {
			file := &lock.Files[i]
			info.Files = append(info.Files, FileInfo{
				Path: file.Path, Mode: file.Mode, Size: file.Size, Digest: file.Digest,
			})
		}
	}
	return &InspectResult{Kind: InspectKindLock, Lock: info}, nil
}
