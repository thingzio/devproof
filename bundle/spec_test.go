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

import (
	stderrors "errors"
	"reflect"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

const validManifest = `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example-config
spec:
  sources:
    - name: application
      type: path
      mountPath: app
      include: ["config/**"]
      exclude: ["**/*.tmp"]
      config:
        path: ./application
`

func TestParseSpec(t *testing.T) {
	t.Parallel()

	spec, err := ParseSpec([]byte(validManifest))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if spec.Metadata.Name != "example-config" {
		t.Errorf("name = %q", spec.Metadata.Name)
	}
	if len(spec.Spec.Sources) != 1 {
		t.Fatalf("parsed %d sources", len(spec.Spec.Sources))
	}
	source := spec.Spec.Sources[0]
	if source.Type != SourceTypePath || source.MountPath != "app" {
		t.Errorf("source = %+v", source)
	}
	if got := source.Config["path"]; got != "./application" {
		t.Errorf("config path = %v", got)
	}
}

// JSON is a subset of YAML, so the same loader accepts both. They must mean
// exactly the same thing, or a manifest's meaning would depend on how it was
// written.
func TestParseSpecAcceptsJSONAndYAMLIdentically(t *testing.T) {
	t.Parallel()

	const asJSON = `{
	  "apiVersion": "devproof.thingz.io/v1alpha1",
	  "kind": "Bundle",
	  "metadata": {"name": "example-config"},
	  "spec": {"sources": [{
	    "name": "application",
	    "type": "path",
	    "mountPath": "app",
	    "include": ["config/**"],
	    "exclude": ["**/*.tmp"],
	    "config": {"path": "./application"}
	  }]}
	}`

	fromYAML, err := ParseSpec([]byte(validManifest))
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	fromJSON, err := ParseSpec([]byte(asJSON))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// The typed model is what the manifest digest is computed over, so
	// comparing the normalized models is comparing what identity depends on.
	// (The canonical encoder itself lives in internal/canonical, which
	// cannot be imported here without a cycle.)
	if !reflect.DeepEqual(fromYAML.Normalized(), fromJSON.Normalized()) {
		t.Error("the same manifest written as YAML and as JSON produced different models")
	}
}

func TestParseSpecRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest string
		code     fault.Code
	}{
		{"empty", "", fault.CodeInvalidInput},
		{
			"unknown apiVersion",
			strings.Replace(validManifest, "v1alpha1", "v2", 1),
			fault.CodeUnsupportedVersion,
		},
		{
			"wrong kind",
			strings.Replace(validManifest, "kind: Bundle", "kind: Policy", 1),
			fault.CodeInvalidInput,
		},
		{
			// A field this build does not recognize may be load-bearing for
			// whoever wrote it; silently ignoring it builds something else.
			"unknown top-level field",
			validManifest + "\nunexpected: true\n",
			fault.CodeInvalidInput,
		},
		{
			"unknown source field",
			strings.Replace(validManifest, "      type: path", "      type: path\n      surprise: yes", 1),
			fault.CodeInvalidInput,
		},
		{
			// A duplicate key means two different readers can disagree about
			// which one wins.
			"duplicate key",
			strings.Replace(validManifest, "  name: example-config", "  name: example-config\n  name: other", 1),
			fault.CodeInvalidInput,
		},
		{
			"two documents",
			validManifest + "\n---\n" + validManifest,
			fault.CodeInvalidInput,
		},
		{
			"no sources",
			"apiVersion: devproof.thingz.io/v1alpha1\nkind: Bundle\nmetadata:\n  name: a\nspec:\n  sources: []\n",
			fault.CodeInvalidInput,
		},
		{
			"duplicate source names",
			strings.Replace(validManifest,
				"    - name: application",
				"    - name: application\n      type: path\n      config: {path: ./a}\n    - name: application", 1),
			fault.CodeInvalidInput,
		},
		{
			"escaping mount path",
			strings.Replace(validManifest, "mountPath: app", "mountPath: ../escape", 1),
			fault.CodeInvalidInput,
		},
		{
			"absolute mount path",
			strings.Replace(validManifest, "mountPath: app", "mountPath: /etc", 1),
			fault.CodeInvalidInput,
		},
		{
			"malformed pattern",
			strings.Replace(validManifest, `include: ["config/**"]`, `include: ["../escape/**"]`, 1),
			fault.CodeInvalidInput,
		},
		{
			"unqualified extension type",
			strings.Replace(validManifest, "type: path", "type: object", 1),
			fault.CodeUnsupportedSource,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseSpec([]byte(tc.manifest))
			if err == nil {
				t.Fatal("an invalid manifest parsed")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q (%v)", fault.CodeOf(err), tc.code, err)
			}
		})
	}
}

// A domain-qualified extension type is accepted even though no resolver is
// registered for it; that failure belongs to the client, not the loader.
func TestParseSpecAcceptsDomainQualifiedExtensionType(t *testing.T) {
	t.Parallel()

	manifest := strings.Replace(validManifest, "type: path", "type: storage.example.com/object", 1)
	if _, err := ParseSpec([]byte(manifest)); err != nil {
		t.Errorf("a domain-qualified extension type was rejected: %v", err)
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()

	valid := []string{"a", "app", "app-config", "a1", "1a", "config-v2"}
	for _, name := range valid {
		if err := ValidateName(name, "test"); err != nil {
			t.Errorf("ValidateName(%q) = %v", name, err)
		}
	}

	invalid := []string{
		"", "-leading", "trailing-", "Upper", "under_score", "has space",
		"dot.separated", "sla/sh", "new\nline", strings.Repeat("a", 64),
	}
	for _, name := range invalid {
		if err := ValidateName(name, "test"); err == nil {
			t.Errorf("ValidateName(%q) was accepted", name)
		}
	}
}

func TestNormalizeMountPath(t *testing.T) {
	t.Parallel()

	// Empty and "." are the same instruction; both mean the bundle root.
	for _, root := range []string{"", "."} {
		got, err := NormalizeMountPath(root)
		if err != nil || got != "" {
			t.Errorf("NormalizeMountPath(%q) = %q, %v", root, got, err)
		}
	}

	if got, err := NormalizeMountPath("app/config"); err != nil || got != "app/config" {
		t.Errorf("= %q, %v", got, err)
	}

	for _, bad := range []string{"/abs", "../up", "a/../b", "a//b", "a/./b", ".."} {
		if _, err := NormalizeMountPath(bad); err == nil {
			t.Errorf("NormalizeMountPath(%q) was accepted", bad)
		}
	}
}

// Normalization is what makes the manifest digest insensitive to spelling.
func TestNormalizedCanonicalizesSetLikeFields(t *testing.T) {
	t.Parallel()

	spec := &Spec{
		APIVersion: APIVersionV1Alpha1,
		Kind:       KindBundle,
		Metadata:   SpecMetadata{Name: "example"},
		Spec: SpecBody{Sources: []SourceSpec{
			{Name: "zebra", Type: SourceTypePath, Include: []string{"b/**", "a/**", "b/**"}},
			{Name: "alpha", Type: SourceTypePath, MountPath: "."},
		}},
	}

	normalized := spec.Normalized()

	if normalized.Spec.Sources[0].Name != "alpha" {
		t.Error("sources were not sorted by name")
	}
	include := normalized.Spec.Sources[1].Include
	if len(include) != 2 || include[0] != "a/**" || include[1] != "b/**" {
		t.Errorf("include = %v, want sorted and de-duplicated", include)
	}
	if normalized.Spec.Sources[0].MountPath != "" {
		t.Error(`an explicit "." mount path did not normalize to the root`)
	}
	// The original must be untouched.
	if spec.Spec.Sources[0].Name != "zebra" {
		t.Error("Normalized mutated its receiver")
	}
}

func TestDecodeConfig(t *testing.T) {
	t.Parallel()

	type resolverConfig struct {
		Path string `json:"path"`
		Ref  string `json:"ref,omitempty"`
	}

	var target resolverConfig
	if err := DecodeConfig(map[string]any{"path": "./a", "ref": "main"}, &target); err != nil {
		t.Fatalf("DecodeConfig: %v", err)
	}
	if target.Path != "./a" || target.Ref != "main" {
		t.Errorf("= %+v", target)
	}

	// An unrecognized key is a mistake the author should hear about.
	var strict resolverConfig
	err := DecodeConfig(map[string]any{"path": "./a", "typo": true}, &strict)
	if !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestSourceByName(t *testing.T) {
	t.Parallel()

	spec, err := ParseSpec([]byte(validManifest))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if _, ok := spec.SourceByName("application"); !ok {
		t.Error("a declared source was not found")
	}
	if _, ok := spec.SourceByName("absent"); ok {
		t.Error("an undeclared source was found")
	}
}
