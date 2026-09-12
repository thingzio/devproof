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
	"encoding/json"
	stderrors "errors"
	"maps"
	"slices"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

// marshalManifest encodes m and returns its top-level keys, so a test can ask
// what fields the type is capable of emitting rather than reading the struct.
func marshalManifest(m *Manifest) ([]string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	return slices.Collect(maps.Keys(fields)), nil
}

func containsKey(keys []string, want string) bool { return slices.Contains(keys, want) }

func descriptor(mediaType, content string) Descriptor {
	return DescriptorFor(mediaType, []byte(content))
}

func validManifest() *Manifest {
	return NewManifest(
		descriptor(bundle.MediaTypeConfigV1, `{"schemaVersion":1}`),
		descriptor(bundle.MediaTypeLayerV1, "layer bytes"),
	)
}

func TestNewManifestIsValid(t *testing.T) {
	t.Parallel()

	if err := validManifest().Validate(); err != nil {
		t.Errorf("a freshly built manifest does not validate: %v", err)
	}
}

// A subject that could carry annotations could carry a build timestamp, and
// that would land in the digest. The type has nowhere to put one, and this
// records that as intentional.
func TestManifestHasNoAnnotationsOrSubjectField(t *testing.T) {
	t.Parallel()

	encoded, err := marshalManifest(validManifest())
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	for _, forbidden := range []string{"annotations", "subject", "created", "author"} {
		if containsKey(encoded, forbidden) {
			t.Errorf("manifest encoding contains a %q field", forbidden)
		}
	}
}

func TestManifestValidateRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Manifest)
		code   fault.Code
	}{
		{
			"wrong schema version",
			func(m *Manifest) { m.SchemaVersion = 1 },
			fault.CodeInvalidArtifact,
		},
		{
			"wrong manifest media type",
			func(m *Manifest) { m.MediaType = "application/vnd.docker.distribution.manifest.v2+json" },
			fault.CodeInvalidArtifact,
		},
		{
			"unknown artifact type",
			func(m *Manifest) { m.ArtifactType = "application/vnd.thingz.devproof.bundle.v2" },
			fault.CodeUnsupportedVersion,
		},
		{
			"missing artifact type",
			func(m *Manifest) { m.ArtifactType = "" },
			fault.CodeUnsupportedVersion,
		},
		{
			"wrong config media type",
			func(m *Manifest) { m.Config.MediaType = "application/json" },
			fault.CodeInvalidArtifact,
		},
		{
			"wrong layer media type",
			func(m *Manifest) { m.Layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar" },
			fault.CodeInvalidArtifact,
		},
		{
			"no layers",
			func(m *Manifest) { m.Layers = nil },
			fault.CodeInvalidArtifact,
		},
		{
			// A second layer is invisible to the config inventory, so a
			// consumer materializing both would write files nothing verified.
			"two layers",
			func(m *Manifest) { m.Layers = append(m.Layers, m.Layers[0]) },
			fault.CodeInvalidArtifact,
		},
		{
			"invalid config digest",
			func(m *Manifest) { m.Config.Digest = "sha256:nothex" },
			fault.CodeInvalidArtifact,
		},
		{
			"negative layer size",
			func(m *Manifest) { m.Layers[0].Size = -1 },
			fault.CodeInvalidArtifact,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := validManifest()
			tc.mutate(m)

			err := m.Validate()
			if err == nil {
				t.Fatal("an invalid manifest validated")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), tc.code)
			}
		})
	}
}

func TestManifestFormatAndLayer(t *testing.T) {
	t.Parallel()

	m := validManifest()

	format, ok := m.Format()
	if !ok || format != bundle.FormatV1 {
		t.Errorf("Format() = %q, %v", format, ok)
	}

	layer, err := m.Layer()
	if err != nil {
		t.Fatalf("Layer: %v", err)
	}
	if layer.MediaType != bundle.MediaTypeLayerV1 {
		t.Errorf("Layer media type = %q", layer.MediaType)
	}

	m.Layers = append(m.Layers, layer)
	if _, err := m.Layer(); err == nil {
		t.Error("Layer() answered for a manifest with two layers")
	}
}

func TestDescriptorVerifyContent(t *testing.T) {
	t.Parallel()

	const content = "exact bytes"
	d := descriptor(bundle.MediaTypeLayerV1, content)

	if err := d.VerifyContent([]byte(content)); err != nil {
		t.Errorf("a descriptor rejected its own content: %v", err)
	}

	// Same length, different bytes: only the digest catches this.
	altered := []byte("exact byteS")
	if err := d.VerifyContent(altered); !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
	}

	if err := d.VerifyContent([]byte("short")); !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
	}
}

func TestDescriptorValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		d    Descriptor
	}{
		{"no media type", Descriptor{Digest: descriptor("x", "y").Digest, Size: 1}},
		{"negative size", Descriptor{MediaType: "x", Digest: descriptor("x", "y").Digest, Size: -1}},
		{"no digest", Descriptor{MediaType: "x", Size: 1}},
		{"malformed digest", Descriptor{MediaType: "x", Digest: "deadbeef", Size: 1}},
		{"wrong algorithm", Descriptor{MediaType: "x", Digest: "md5:abc", Size: 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.d.Validate(); err == nil {
				t.Error("an invalid descriptor validated")
			}
		})
	}

	if err := descriptor(bundle.MediaTypeConfigV1, "ok").Validate(); err != nil {
		t.Errorf("a valid descriptor was rejected: %v", err)
	}
}

func TestDescriptorForEmptyContent(t *testing.T) {
	t.Parallel()

	d := DescriptorFor(bundle.MediaTypeConfigV1, nil)
	if d.Size != 0 {
		t.Errorf("Size = %d, want 0", d.Size)
	}
	if err := d.VerifyContent(nil); err != nil {
		t.Errorf("empty content did not verify against its own descriptor: %v", err)
	}
}
