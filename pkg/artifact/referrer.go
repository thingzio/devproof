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

package artifact

import (
	"context"
	"fmt"
	"io"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

const referrerOp = "artifact.referrer"

// OCI 1.1 empty descriptor, for an artifact manifest with no meaningful
// config. The digest and content are fixed by the spec.
const (
	MediaTypeEmptyJSON = "application/vnd.oci.empty.v1+json"
	emptyJSONDigest    = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	emptyJSONSize      = 2
)

// EmptyJSONContent is the body of the empty descriptor: the two bytes `{}`.
var EmptyJSONContent = []byte("{}")

// EmptyDescriptor returns the OCI 1.1 empty config descriptor.
func EmptyDescriptor() Descriptor {
	return Descriptor{MediaType: MediaTypeEmptyJSON, Digest: emptyJSONDigest, Size: emptyJSONSize}
}

// EvidenceStorage reports how evidence was found or stored.
type EvidenceStorage string

const (
	// StorageReferrers is the OCI referrers API. It expresses a set, so
	// several evidence objects can coexist for one subject.
	StorageReferrers EvidenceStorage = "referrers"
	// StorageTagFallback is the tag scheme used where a registry has no
	// referrers API. It holds one object per subject and replaces rather
	// than accumulates (DP-028).
	StorageTagFallback EvidenceStorage = "tag-fallback"
)

// FallbackTag returns the tag evidence for a subject is stored under when a
// registry has no referrers API.
//
// The scheme is `sha256-<hex>.evidence`: one tag for one subject. A registry
// without the referrers API cannot express a set, and encoding an index into
// the tag would make "which evidence exists" depend on a read-modify-write
// race that has no locking. Replacement is the honest behavior, and it is
// reported rather than hidden.
func FallbackTag(subject bundle.Digest) string {
	return "sha256-" + subject.Hex() + ".evidence"
}

// ReferrerManifest builds the OCI manifest that attaches evidence to a
// subject.
//
// Unlike a bundle's subject manifest, this one carries a `subject` field —
// that field is what makes it a referrer — and its own digest is not a
// bundle identity. Attaching one cannot change what it points at (DP-003).
type ReferrerManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Subject       *Descriptor       `json:"subject"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// NewReferrerManifest assembles a referrer for one evidence blob.
func NewReferrerManifest(subject, blob Descriptor, artifactType string) *ReferrerManifest {
	return &ReferrerManifest{
		SchemaVersion: ManifestSchemaVersion,
		MediaType:     MediaTypeImageManifest,
		ArtifactType:  artifactType,
		Config:        EmptyDescriptor(),
		Layers:        []Descriptor{blob},
		Subject:       &subject,
	}
}

// Validate checks a referrer manifest's shape.
func (m *ReferrerManifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fault.New(fault.CodeInvalidArtifact, referrerOp,
			fmt.Sprintf("referrer schema version is %d, want %d",
				m.SchemaVersion, ManifestSchemaVersion))
	}
	if m.MediaType != MediaTypeImageManifest {
		return fault.New(fault.CodeInvalidArtifact, referrerOp,
			fmt.Sprintf("referrer media type is %q", m.MediaType))
	}
	if m.ArtifactType == "" {
		return fault.New(fault.CodeInvalidArtifact, referrerOp, "referrer has no artifact type")
	}
	if m.Subject == nil {
		// Without a subject it is not a referrer at all; it is a loose
		// manifest that happens to contain evidence, attached to nothing.
		return fault.New(fault.CodeInvalidArtifact, referrerOp,
			"referrer names no subject")
	}
	if err := m.Subject.Validate(); err != nil {
		return err
	}
	if len(m.Layers) != 1 {
		return fault.New(fault.CodeInvalidArtifact, referrerOp,
			fmt.Sprintf("referrer has %d layers; DevProof evidence has exactly one", len(m.Layers)))
	}
	return m.Layers[0].Validate()
}

// EvidenceBlob returns the descriptor of the evidence this referrer carries.
func (m *ReferrerManifest) EvidenceBlob() (Descriptor, error) {
	if len(m.Layers) != 1 {
		return Descriptor{}, fault.New(fault.CodeInvalidArtifact, referrerOp,
			"referrer does not carry exactly one evidence blob")
	}
	return m.Layers[0], nil
}

// ReferrerTransport is a transport that can attach and discover evidence.
//
// It is a separate interface rather than methods on [Transport] because a
// transport that cannot do this is still useful, and widening Transport would
// break every external implementation to add a capability most do not need.
type ReferrerTransport interface {
	Transport

	// Referrers lists evidence attached to a subject, filtered by artifact
	// type. The reported storage mode tells a caller whether the answer is a
	// set or a single replaceable slot.
	Referrers(ctx context.Context, ref Reference, subject Descriptor, artifactType string) ([]Descriptor, EvidenceStorage, error)

	// Attach stores an evidence blob and the referrer manifest naming it.
	//
	// Attach must never modify the subject. That is the guarantee that lets
	// evidence be added, renewed, or copied without changing what it
	// describes (DP-003).
	Attach(ctx context.Context, ref Reference, subject Descriptor, blob Descriptor, content io.Reader, artifactType string) (Descriptor, EvidenceStorage, error)
}
