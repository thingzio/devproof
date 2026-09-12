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

// Package evidence describes where a bundle came from, in a form that can be
// verified independently of the bundle itself.
//
// Evidence names a subject by digest and is stored beside it, never inside
// it. That separation is the point of DP-003: adding, renewing, or copying
// evidence cannot change what it describes, so a signature that expires does
// not invalidate an artifact, and an artifact rebuilt from the same content
// keeps its identity while gaining new provenance.
package evidence

import (
	"fmt"
	"time"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

const statementOp = "evidence.statement"

// in-toto Attestation Framework constants.
const (
	// StatementType is the in-toto Statement v1 type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateTypeSLSAProvenance is SLSA Provenance v1, which a DevProof
	// provenance predicate embeds unchanged.
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"
	// PredicateTypeDevProof is the DevProof provenance predicate (DP-024).
	PredicateTypeDevProof = bundle.PredicateTypeProvenanceV1
)

// Statement is an in-toto Statement v1.
//
// The subject is always a bundle's OCI manifest digest. A statement that
// named content by anything else — a tag, a repository, a build number —
// would describe something that can change after the statement was signed.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject names what a statement is about.
type Subject struct {
	// Name is a label. It is not identity and is not matched against
	// anything; the digest is.
	Name string `json:"name,omitempty"`
	// Digest maps an algorithm to a hex value, per the in-toto spec.
	Digest map[string]string `json:"digest"`
}

// Predicate is DevProof provenance.
//
// It embeds SLSA Provenance v1 unchanged and adds the facts SLSA has no field
// for. Neither alone worked: SLSA cannot express "the lock digest" or "this
// source's canonical tree digest", and discarding SLSA would give up every
// consumer that already reads it (DP-024).
type Predicate struct {
	// BuildDefinition and RunDetails are SLSA Provenance v1, verbatim.
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`

	// DevProof carries what SLSA cannot express.
	DevProof DevProofProvenance `json:"devproof"`
}

// BuildDefinition is the SLSA description of what was built.
type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]any       `json:"externalParameters"`
	InternalParameters   map[string]any       `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// RunDetails is the SLSA description of who built it and when.
type RunDetails struct {
	Builder  Builder     `json:"builder"`
	Metadata RunMetadata `json:"metadata,omitzero"`
}

// Builder identifies the build platform.
type Builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

// RunMetadata describes one invocation.
type RunMetadata struct {
	InvocationID string     `json:"invocationId,omitempty"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}

// ResourceDescriptor is the SLSA reference to an input.
type ResourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      map[string]string `json:"digest,omitempty"`
	Annotations map[string]any    `json:"annotations,omitempty"`
}

// DevProofProvenance is the DevProof-specific half of the predicate.
type DevProofProvenance struct {
	// FormatVersion is the bundle format the subject was built as.
	FormatVersion string `json:"formatVersion"`
	// ManifestDigest identifies the manifest that was built from.
	ManifestDigest string `json:"manifestDigest"`
	// LockDigest identifies the lock that was enforced or generated.
	LockDigest string `json:"lockDigest"`
	// TreeDigest is the payload identity, independent of encoding.
	TreeDigest string `json:"treeDigest"`
	// Sources describes each source's resolution.
	Sources []SourceProvenance `json:"sources"`
	// ToolVersion is the DevProof version that built the subject. It is
	// diagnostic: it never affects the subject digest (DP-012).
	ToolVersion string `json:"toolVersion,omitempty"`
}

// SourceProvenance describes one source's contribution.
type SourceProvenance struct {
	// Name is the logical source name from the manifest.
	Name string `json:"name"`
	// Type is the source type, such as "git" or "path".
	Type string `json:"type"`
	// Resolver identifies the implementation and version that resolved it,
	// so a resolver whose behavior changed is visible to policy.
	Resolver string `json:"resolver"`
	// Requested is what the manifest asked for, which may be mutable.
	Requested map[string]any `json:"requested,omitempty"`
	// Resolved is what it resolved to, which is not.
	Resolved map[string]any `json:"resolved,omitempty"`
	// TreeDigest is this source's filtered contribution, before mounting.
	TreeDigest string `json:"treeDigest"`
	// MountPath is where the contribution was placed.
	MountPath string `json:"mountPath,omitempty"`
}

// NewStatement builds a statement about a subject digest.
func NewStatement(subjectDigest bundle.Digest, name string, predicate Predicate) *Statement {
	return &Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name: name,
			// The in-toto digest map is keyed by algorithm with a bare hex
			// value, not the "sha256:" form used elsewhere.
			Digest: map[string]string{"sha256": subjectDigest.Hex()},
		}},
		PredicateType: PredicateTypeDevProof,
		Predicate:     predicate,
	}
}

// Validate checks a statement's structure.
func (s *Statement) Validate() error {
	if s.Type != StatementType {
		return fault.New(fault.CodeEvidenceInvalid, statementOp,
			fmt.Sprintf("statement type is %q, want %q", s.Type, StatementType))
	}
	if len(s.Subject) != 1 {
		// One statement, one subject. A statement covering several subjects
		// could be presented as evidence for any of them, which makes
		// "verified for this artifact" ambiguous.
		return fault.New(fault.CodeEvidenceInvalid, statementOp,
			fmt.Sprintf("statement names %d subjects; DevProof evidence names exactly one",
				len(s.Subject)))
	}
	if _, err := s.SubjectDigest(); err != nil {
		return err
	}
	switch s.PredicateType {
	case PredicateTypeDevProof, PredicateTypeSLSAProvenance:
	default:
		return fault.New(fault.CodeEvidenceInvalid, statementOp,
			fmt.Sprintf("predicate type %q is not recognized", s.PredicateType))
	}
	return nil
}

// SubjectDigest returns the digest this statement is about.
func (s *Statement) SubjectDigest() (bundle.Digest, error) {
	if len(s.Subject) != 1 {
		return bundle.Digest{}, fault.New(fault.CodeEvidenceInvalid, statementOp,
			"statement does not name exactly one subject")
	}
	hex, ok := s.Subject[0].Digest["sha256"]
	if !ok {
		return bundle.Digest{}, fault.New(fault.CodeEvidenceInvalid, statementOp,
			"statement subject has no sha256 digest")
	}
	return bundle.ParseDigest("sha256:" + hex)
}

// BindsTo reports whether the statement is about a particular subject.
//
// This is the check that stops evidence for one artifact being presented as
// evidence for another. A signature proves who wrote a statement; only this
// proves what the statement is about.
func (s *Statement) BindsTo(subject bundle.Digest) bool {
	got, err := s.SubjectDigest()
	return err == nil && got == subject
}
