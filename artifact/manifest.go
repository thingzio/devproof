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
	"fmt"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const manifestOp = "artifact.manifest"

// ManifestSchemaVersion is the OCI image manifest schema version.
const ManifestSchemaVersion = 2

// Manifest is a bundle's OCI subject.
//
// There is no Subject field and no Annotations field, and their absence is the
// point rather than an omission. A subject that could carry annotations could
// carry a build timestamp or a builder name, and those would land in the
// digest — so two builds of identical content would stop having identical
// identity (DP-002). Evidence carries that information instead, attached as a
// referrer that names this manifest's digest.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// NewManifest assembles a format v1 subject from its two blob descriptors.
func NewManifest(config, layer Descriptor) *Manifest {
	return &Manifest{
		SchemaVersion: ManifestSchemaVersion,
		MediaType:     MediaTypeImageManifest,
		ArtifactType:  bundle.MediaTypeArtifactV1,
		Config:        config,
		Layers:        []Descriptor{layer},
	}
}

// Validate checks the manifest against the format v1 shape.
//
// Cardinality is checked as strictly as the media types. A second layer would
// be invisible to the config inventory, which describes one archive, so a
// consumer that materialized both would end up with files that passed
// verification without ever being verified.
func (m *Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("manifest schema version is %d, want %d",
				m.SchemaVersion, ManifestSchemaVersion))
	}
	if m.MediaType != MediaTypeImageManifest {
		return fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("manifest media type is %q, want %q", m.MediaType, MediaTypeImageManifest))
	}

	format, ok := bundle.FormatForArtifactType(m.ArtifactType)
	if !ok {
		return fault.New(fault.CodeUnsupportedVersion, manifestOp,
			fmt.Sprintf("artifact type %q is not a supported DevProof bundle", m.ArtifactType))
	}

	wantConfig, _ := format.ConfigMediaType()
	if m.Config.MediaType != wantConfig {
		return fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("config media type is %q, want %q", m.Config.MediaType, wantConfig))
	}
	if err := m.Config.Validate(); err != nil {
		return err
	}

	if len(m.Layers) != 1 {
		return fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("manifest has %d layers; format v1 has exactly one", len(m.Layers)))
	}
	wantLayer, _ := format.LayerMediaType()
	if m.Layers[0].MediaType != wantLayer {
		return fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("layer media type is %q, want %q", m.Layers[0].MediaType, wantLayer))
	}
	return m.Layers[0].Validate()
}

// Format reports the bundle format this manifest declares.
func (m *Manifest) Format() (bundle.Format, bool) {
	return bundle.FormatForArtifactType(m.ArtifactType)
}

// Layer returns the single filesystem layer descriptor.
func (m *Manifest) Layer() (Descriptor, error) {
	if len(m.Layers) != 1 {
		return Descriptor{}, fault.New(fault.CodeInvalidArtifact, manifestOp,
			fmt.Sprintf("manifest has %d layers; format v1 has exactly one", len(m.Layers)))
	}
	return m.Layers[0], nil
}
