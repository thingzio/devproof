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

// Package bundle defines the DevProof bundle format: its version identifiers,
// media types, and the manifest, lock, and inventory documents that describe
// what a bundle contains.
//
// The constants here are a compatibility surface. Every one of them
// participates in the OCI subject digest, so changing a value is a new format
// version, never an edit (DP-015).
package bundle

// Format identifies a DevProof canonical bundle format version.
//
// It is carried in the config blob and recognized through the artifact media
// type. Readers dispatch on it and reject what they do not know, rather than
// guessing at a newer layout (DP-015).
type Format string

// FormatV1 is the first canonical bundle format: a portable filesystem
// profile of regular files and implicit directories, encoded as one
// gzip-compressed tar layer.
const FormatV1 Format = "devproof-bundle-v1"

// Media types for format v1.
//
// MediaTypeLayerV1 is the standard OCI gzip layer type, not a DevProof type,
// so that a generic OCI consumer can materialize the payload without
// understanding provenance (DP-006).
const (
	// MediaTypeArtifactV1 is the OCI manifest's artifactType.
	MediaTypeArtifactV1 = "application/vnd.thingz.devproof.bundle.v1"
	// MediaTypeConfigV1 is the DevProof config blob's media type.
	MediaTypeConfigV1 = "application/vnd.thingz.devproof.config.v1+json"
	// MediaTypeLayerV1 is the single filesystem layer's media type.
	MediaTypeLayerV1 = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// PredicateTypeProvenanceV1 is the in-toto predicate type for DevProof
// provenance. It embeds a SLSA Provenance v1 document and adds the DevProof
// facts SLSA has no field for: lock digest and per-source tree digests
// (DP-024).
const PredicateTypeProvenanceV1 = "https://devproof.thingz.io/provenance/v1"

// APIVersionV1Alpha1 is the manifest and policy API group and version.
//
// It is independent of the bundle format version: a later manifest API may
// still build format v1 if its canonical semantics are identical.
const APIVersionV1Alpha1 = "devproof.thingz.io/v1alpha1"

// Document kinds within APIVersionV1Alpha1.
const (
	KindBundle             = "Bundle"
	KindBundleLock         = "BundleLock"
	KindVerificationPolicy = "VerificationPolicy"
)

// TreeDigestDomainV1 is the domain-separation prefix hashed before any file
// record in the v1 tree digest.
//
// Domain separation is what keeps a tree digest from ever colliding with a
// digest computed over the same bytes for a different purpose, and what makes
// a future format's records unmistakable for v1's.
const TreeDigestDomainV1 = "devproof-tree-v1\x00"

// Canonical file modes. The portable profile normalizes every regular file to
// one of two values and every directory to one, so that a bundle built on a
// permissive umask and one built on a restrictive umask are byte-identical
// (DP-005).
const (
	// ModeFile is the canonical mode for a regular file with no execute bit.
	ModeFile = 0o644
	// ModeExecutable is the canonical mode for a regular file with any
	// execute bit set.
	ModeExecutable = 0o755
	// ModeDirectory is the canonical mode for every derived parent directory.
	ModeDirectory = 0o755
)

// supportedFormats lists what this build can read and write. A future build
// that reads v1 and writes v2 simply lists both; format support is additive,
// and removing a reader is a breaking change (DP-015).
var supportedFormats = map[Format]bool{
	FormatV1: true,
}

// SupportedFormats returns the formats this build understands, in a stable
// order suitable for `devproof version` output.
func SupportedFormats() []Format {
	return []Format{FormatV1}
}

// Supported reports whether this build understands f.
func Supported(f Format) bool { return supportedFormats[f] }

// FormatForArtifactType maps an OCI artifactType onto a bundle format.
//
// The artifact type is what a consumer sees before fetching any blob, so it
// is the first place an unsupported version can be rejected — before spending
// a request on a config it cannot parse.
func FormatForArtifactType(artifactType string) (Format, bool) {
	if artifactType == MediaTypeArtifactV1 {
		return FormatV1, true
	}
	return "", false
}

// ConfigMediaType returns the config media type for f.
func (f Format) ConfigMediaType() (string, bool) {
	if f == FormatV1 {
		return MediaTypeConfigV1, true
	}
	return "", false
}

// ArtifactType returns the OCI artifactType for f.
func (f Format) ArtifactType() (string, bool) {
	if f == FormatV1 {
		return MediaTypeArtifactV1, true
	}
	return "", false
}

// LayerMediaType returns the single filesystem layer media type for f.
func (f Format) LayerMediaType() (string, bool) {
	if f == FormatV1 {
		return MediaTypeLayerV1, true
	}
	return "", false
}

func (f Format) String() string { return string(f) }
