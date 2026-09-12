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

package canonical

import (
	"bytes"
	"encoding/json"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const manifestOp = "canonical.manifest"

// EncodeManifest renders a subject manifest as canonical JSON and returns the
// bytes with their digest.
//
// That digest is the bundle's identity, so the manifest is validated before
// it is encoded: minting a digest for a structurally invalid subject would
// give a name to something no consumer can verify.
func EncodeManifest(m *artifact.Manifest) (Digest, []byte, error) {
	if err := m.Validate(); err != nil {
		return Digest{}, nil, err
	}
	return JSONDigest(m)
}

// ParseManifest decodes and validates a subject manifest.
//
// Decoding is strict. An unknown field in a manifest is either a newer format
// this build should refuse, or an attempt to smuggle something past a reader
// that ignores what it does not recognize; neither is a reason to continue.
func ParseManifest(data []byte) (*artifact.Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var m artifact.Manifest
	if err := decoder.Decode(&m); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, manifestOp, "decoding manifest", err)
	}
	if decoder.More() {
		return nil, fault.New(fault.CodeInvalidArtifact, manifestOp,
			"manifest contains trailing data after the JSON object")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Subject is a fully encoded bundle.
//
// The config and manifest are carried as bytes because both are small by
// construction and a caller that recomputed either would invite the bytes and
// the digest to disagree. The layer is not: it is streamed to a writer during
// packaging and identified here by digest and size only.
type Subject struct {
	// Manifest is the OCI subject. ManifestDigest is the bundle's identity.
	Manifest       *artifact.Manifest
	ManifestBytes  []byte
	ManifestDigest Digest

	// Config is the inventory blob.
	Config       *bundle.Config
	ConfigBytes  []byte
	ConfigDigest Digest

	// LayerDigest and LayerSize describe the compressed archive that was
	// written to the packager's output.
	LayerDigest Digest
	LayerSize   int64

	// TreeDigest identifies the payload independently of how it was encoded.
	// Two bundles with the same tree digest hold the same files even if a
	// future format encodes them differently.
	TreeDigest Digest
}

// Descriptor returns the descriptor naming this subject.
func (s *Subject) Descriptor() artifact.Descriptor {
	return artifact.Descriptor{
		MediaType: artifact.MediaTypeImageManifest,
		Digest:    s.ManifestDigest.String(),
		Size:      int64(len(s.ManifestBytes)),
	}
}

// ConfigDescriptor returns the descriptor naming the config blob.
func (s *Subject) ConfigDescriptor() artifact.Descriptor {
	return artifact.Descriptor{
		MediaType: bundle.MediaTypeConfigV1,
		Digest:    s.ConfigDigest.String(),
		Size:      int64(len(s.ConfigBytes)),
	}
}

// LayerDescriptor returns the descriptor naming the compressed layer.
func (s *Subject) LayerDescriptor() artifact.Descriptor {
	return artifact.Descriptor{
		MediaType: bundle.MediaTypeLayerV1,
		Digest:    s.LayerDigest.String(),
		Size:      s.LayerSize,
	}
}
