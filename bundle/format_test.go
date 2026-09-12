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

package bundle

import "testing"

// These constants are hashed into the OCI subject. Asserting their literal
// values here is the point: a rename or a "tidy-up" that changes one changes
// every subject digest DevProof has ever produced (DP-015).
func TestFormatConstantsAreFrozen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"format v1", string(FormatV1), "devproof-bundle-v1"},
		{"artifact type", MediaTypeArtifactV1, "application/vnd.thingz.devproof.bundle.v1"},
		{"config type", MediaTypeConfigV1, "application/vnd.thingz.devproof.config.v1+json"},
		{"layer type", MediaTypeLayerV1, "application/vnd.oci.image.layer.v1.tar+gzip"},
		{"tree digest domain", TreeDigestDomainV1, "devproof-tree-v1\x00"},
		{"api version", APIVersionV1Alpha1, "devproof.thingz.io/v1alpha1"},
		{"provenance predicate", PredicateTypeProvenanceV1, "https://devproof.thingz.io/provenance/v1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("= %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// The layer is a standard OCI gzip layer, not a DevProof type, so that a
// generic OCI consumer can materialize the payload without understanding
// DevProof at all (DP-006).
func TestLayerUsesTheStandardOCIMediaType(t *testing.T) {
	t.Parallel()

	const ociGzipLayer = "application/vnd.oci.image.layer.v1.tar+gzip"
	if MediaTypeLayerV1 != ociGzipLayer {
		t.Errorf("layer media type %q is not the standard OCI gzip layer type", MediaTypeLayerV1)
	}
}

func TestCanonicalModes(t *testing.T) {
	t.Parallel()

	if ModeFile != 0o644 {
		t.Errorf("ModeFile = %#o, want 0644", ModeFile)
	}
	if ModeExecutable != 0o755 {
		t.Errorf("ModeExecutable = %#o, want 0755", ModeExecutable)
	}
	if ModeDirectory != 0o755 {
		t.Errorf("ModeDirectory = %#o, want 0755", ModeDirectory)
	}
}

// Readers dispatch by version and reject what they do not know, rather than
// guessing at a newer layout.
func TestSupportedRejectsUnknownFormats(t *testing.T) {
	t.Parallel()

	if !Supported(FormatV1) {
		t.Error("v1 is not reported as supported")
	}
	for _, f := range []Format{"", "devproof-bundle-v2", "devproof-bundle-v1 ", "DEVPROOF-BUNDLE-V1"} {
		if Supported(f) {
			t.Errorf("format %q was accepted", f)
		}
	}
}

func TestSupportedFormatsMatchesTheSupportSet(t *testing.T) {
	t.Parallel()

	listed := SupportedFormats()
	if len(listed) != len(supportedFormats) {
		t.Fatalf("SupportedFormats returned %d formats, the support set has %d",
			len(listed), len(supportedFormats))
	}
	for _, f := range listed {
		if !Supported(f) {
			t.Errorf("SupportedFormats listed %q, which Supported rejects", f)
		}
	}
}

// The artifact type is visible before any blob is fetched, so it is the
// cheapest place to reject a version this build cannot read.
func TestFormatForArtifactType(t *testing.T) {
	t.Parallel()

	got, ok := FormatForArtifactType(MediaTypeArtifactV1)
	if !ok || got != FormatV1 {
		t.Errorf("FormatForArtifactType(v1) = %q, %v; want %q, true", got, ok, FormatV1)
	}

	for _, unknown := range []string{
		"",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.thingz.devproof.bundle.v2",
	} {
		if _, ok := FormatForArtifactType(unknown); ok {
			t.Errorf("artifact type %q was accepted", unknown)
		}
	}
}

func TestFormatMediaTypeAccessors(t *testing.T) {
	t.Parallel()

	config, ok := FormatV1.ConfigMediaType()
	if !ok || config != MediaTypeConfigV1 {
		t.Errorf("ConfigMediaType = %q, %v", config, ok)
	}
	artifact, ok := FormatV1.ArtifactType()
	if !ok || artifact != MediaTypeArtifactV1 {
		t.Errorf("ArtifactType = %q, %v", artifact, ok)
	}
	layer, ok := FormatV1.LayerMediaType()
	if !ok || layer != MediaTypeLayerV1 {
		t.Errorf("LayerMediaType = %q, %v", layer, ok)
	}

	unknown := Format("devproof-bundle-v2")
	if _, ok := unknown.ConfigMediaType(); ok {
		t.Error("ConfigMediaType answered for an unsupported format")
	}
	if _, ok := unknown.ArtifactType(); ok {
		t.Error("ArtifactType answered for an unsupported format")
	}
	if _, ok := unknown.LayerMediaType(); ok {
		t.Error("LayerMediaType answered for an unsupported format")
	}
}
