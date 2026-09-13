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

package schema_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thingzio/devproof/internal/repo"
	"github.com/thingzio/devproof/internal/schema"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/policy"
)

// A digest the schemas accept, used wherever a fixture needs one.
const testDigest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()

	data, err := os.ReadFile(schema.Path(name))
	if err != nil {
		t.Fatalf("reading schema %s: %v", name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("schema %s is not valid JSON: %v", name, err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(name, doc); err != nil {
		t.Fatalf("adding schema %s: %v", name, err)
	}
	compiled, err := compiler.Compile(name)
	if err != nil {
		t.Fatalf("compiling schema %s: %v", name, err)
	}
	return compiled
}

// asJSONValue decodes document bytes into the value model a JSON Schema
// validator expects.
//
// The round trip through encoding/json with UseNumber matters: a YAML integer
// arrives as a Go int, which is not part of that model, and numeric bounds
// would silently not be checked.
func asJSONValue(t *testing.T, data []byte) any {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decoding document: %v", err)
	}
	return value
}

// documentCase pairs a schema with a document and the decoder that reads it.
//
// Both must agree. A schema that accepts what the decoder rejects is a
// specification nobody implements; a schema that rejects what the decoder
// accepts is a specification the implementation violates.
type documentCase struct {
	name   string
	schema string
	doc    string
	decode func([]byte) error
	// nest names a nested object an unknown field is injected into, to prove
	// additionalProperties is closed below the top level too.
	nest func(map[string]any) map[string]any
}

func parseSpec(data []byte) error   { _, err := bundle.ParseSpec(data); return err }
func parseLock(data []byte) error   { _, err := bundle.ParseLock(data); return err }
func parseConfig(data []byte) error { _, err := bundle.ParseConfig(data); return err }
func parsePolicy(data []byte) error { _, err := policy.ParseDocument(data); return err }

const validManifest = `{
  "apiVersion": "devproof.thingz.io/v1alpha1",
  "kind": "Bundle",
  "metadata": { "name": "example-config" },
  "spec": {
    "sources": [
      {
        "name": "application",
        "type": "git",
        "mountPath": "app",
        "include": ["config/**", "scripts/**"],
        "exclude": ["**/*.tmp"],
        "config": {
          "url": "https://github.com/example/application.git",
          "ref": "main",
          "subPath": "deploy"
        }
      },
      {
        "name": "environment",
        "type": "path",
        "mountPath": "environment",
        "config": { "path": "./production" }
      }
    ]
  }
}`

const validLock = `{
  "apiVersion": "devproof.thingz.io/v1alpha1",
  "kind": "BundleLock",
  "manifestDigest": "` + testDigest + `",
  "format": "devproof-bundle-v1",
  "sources": [
    {
      "name": "application",
      "type": "git",
      "resolver": "devproof.thingz.io/git/v1",
      "requested": { "url": "https://github.com/example/application.git", "ref": "main" },
      "resolved": { "objectFormat": "sha1", "commit": "0123456789abcdef0123456789abcdef01234567" },
      "treeDigest": "` + testDigest + `",
      "mountPath": "app"
    }
  ],
  "files": [
    {
      "path": "app/config/service.yaml",
      "source": "application",
      "sourcePath": "config/service.yaml",
      "mode": 420,
      "size": 913,
      "digest": "` + testDigest + `"
    }
  ],
  "treeDigest": "` + testDigest + `"
}`

const validConfig = `{
  "schemaVersion": 1,
  "format": "devproof-bundle-v1",
  "treeDigest": "` + testDigest + `",
  "fileCount": 2,
  "totalSize": 1000,
  "files": [
    { "path": "a/one.yaml", "mode": 420, "size": 913, "digest": "` + testDigest + `" },
    { "path": "b/run.sh", "mode": 493, "size": 87, "digest": "` + testDigest + `" }
  ]
}`

const validPolicy = `{
  "apiVersion": "devproof.thingz.io/v1alpha1",
  "kind": "VerificationPolicy",
  "metadata": { "name": "release-bundles" },
  "spec": {
    "subject": {
      "requireDigestReference": true,
      "allowedFormats": ["devproof-bundle-v1"]
    },
    "signatures": {
      "threshold": 1,
      "identities": [
        {
          "issuer": "https://token.actions.githubusercontent.com",
          "subjectPattern": "^https://github\\.com/example/.*$"
        }
      ],
      "requireTransparencyLog": true
    },
    "provenance": {
      "required": true,
      "predicateTypes": ["https://slsa.dev/provenance/v1"],
      "requireLockDigest": true,
      "sources": {
        "allowedTypes": ["git"],
        "allowedHosts": ["github.com"],
        "requireImmutableResolution": true
      }
    },
    "evidence": { "rejectInvalidMatchingEvidence": true },
    "limits": { "maxFiles": 10000, "maxExpandedBytes": 1073741824 }
  }
}`

func documentCases() []documentCase {
	return []documentCase{
		{
			name: "bundle", schema: schema.Bundle, doc: validManifest, decode: parseSpec,
			nest: func(m map[string]any) map[string]any {
				spec, _ := m["spec"].(map[string]any)
				sources, _ := spec["sources"].([]any)
				nested, _ := sources[0].(map[string]any)
				return nested
			},
		},
		{
			name: "bundle-lock", schema: schema.BundleLock, doc: validLock, decode: parseLock,
			nest: func(m map[string]any) map[string]any {
				files, _ := m["files"].([]any)
				nested, _ := files[0].(map[string]any)
				return nested
			},
		},
		{
			name: "bundle-config", schema: schema.BundleConfig, doc: validConfig, decode: parseConfig,
			nest: func(m map[string]any) map[string]any {
				files, _ := m["files"].([]any)
				nested, _ := files[0].(map[string]any)
				return nested
			},
		},
		{
			name: "verification-policy", schema: schema.VerificationPolicy, doc: validPolicy, decode: parsePolicy,
			nest: func(m map[string]any) map[string]any {
				spec, _ := m["spec"].(map[string]any)
				nested, _ := spec["signatures"].(map[string]any)
				return nested
			},
		},
	}
}

// TestSchemasCompile catches a schema that is malformed as a schema, which a
// validation run against a passing document would not surface.
func TestSchemasCompile(t *testing.T) {
	t.Parallel()

	for _, name := range schema.All() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			compile(t, name)
		})
	}
}

// TestValidDocumentsAreAcceptedByBoth is the agreement in the easy direction.
func TestValidDocumentsAreAcceptedByBoth(t *testing.T) {
	t.Parallel()

	for _, tc := range documentCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := compile(t, tc.schema).Validate(asJSONValue(t, []byte(tc.doc))); err != nil {
				t.Errorf("schema rejects a document the decoder accepts:\n%v", err)
			}
			if err := tc.decode([]byte(tc.doc)); err != nil {
				t.Errorf("decoder rejects a document the schema accepts: %v", err)
			}
		})
	}
}

// TestUnknownFieldRejectedByBoth is the drift check that matters most.
//
// Strict decoding is the reason these documents are safe to trust: a reader
// that ignored an unrecognized field would silently not enforce a rule
// somebody wrote down, turning a strict policy into a permissive one. A
// published schema that allowed the same field would document the opposite
// guarantee.
func TestUnknownFieldRejectedByBoth(t *testing.T) {
	t.Parallel()

	const unknown = "fieldNobodyDefined"

	for _, tc := range documentCases() {
		for _, where := range []string{"top level", "nested object"} {
			t.Run(tc.name+"/"+where, func(t *testing.T) {
				t.Parallel()

				var document map[string]any
				if err := json.Unmarshal([]byte(tc.doc), &document); err != nil {
					t.Fatalf("decoding fixture: %v", err)
				}

				target := document
				if where == "nested object" {
					target = tc.nest(document)
					if target == nil {
						t.Fatal("fixture has no nested object to mutate")
					}
				}
				target[unknown] = "surprise"

				mutated, err := json.Marshal(document)
				if err != nil {
					t.Fatalf("re-encoding: %v", err)
				}

				if err := compile(t, tc.schema).Validate(asJSONValue(t, mutated)); err == nil {
					t.Error("schema accepted an unknown field")
				}
				if err := tc.decode(mutated); err == nil {
					t.Error("decoder accepted an unknown field")
				}
			})
		}
	}
}

// TestRequiredFieldsRejectedByBoth removes each top-level required property
// in turn and asserts neither side accepts the result.
func TestRequiredFieldsRejectedByBoth(t *testing.T) {
	t.Parallel()

	for _, tc := range documentCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(schema.Path(tc.schema))
			if err != nil {
				t.Fatalf("reading schema: %v", err)
			}
			var declared struct {
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(raw, &declared); err != nil {
				t.Fatalf("decoding schema: %v", err)
			}
			if len(declared.Required) == 0 {
				t.Fatal("schema declares no required properties")
			}

			for _, field := range declared.Required {
				t.Run(field, func(t *testing.T) {
					var document map[string]any
					if err := json.Unmarshal([]byte(tc.doc), &document); err != nil {
						t.Fatalf("decoding fixture: %v", err)
					}
					delete(document, field)

					mutated, err := json.Marshal(document)
					if err != nil {
						t.Fatalf("re-encoding: %v", err)
					}

					if err := compile(t, tc.schema).Validate(asJSONValue(t, mutated)); err == nil {
						t.Errorf("schema accepted a document missing required %q", field)
					}
					if err := tc.decode(mutated); err == nil {
						t.Errorf("decoder accepted a document missing required %q", field)
					}
				})
			}
		})
	}
}

// TestPolicyLimitCeilingsMatchCode pins every limit's schema maximum to the
// ceiling the code actually enforces.
//
// These are two spellings of one number in two files, which is exactly the
// arrangement that drifts. A schema advertising a bound the loader refuses --
// or permitting one it does not -- is worse than no schema, because it is
// believed.
func TestPolicyLimitCeilingsMatchCode(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(schema.Path(schema.VerificationPolicy))
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}

	var doc struct {
		Defs struct {
			Limits struct {
				Properties map[string]struct {
					Maximum *int64 `json:"maximum"`
					Minimum *int64 `json:"minimum"`
				} `json:"properties"`
			} `json:"limits"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding schema: %v", err)
	}

	ceilings := bundle.Ceilings()
	value := reflect.ValueOf(ceilings)
	typ := value.Type()

	seen := make(map[string]bool, typ.NumField())
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" {
			t.Fatalf("field %s has no json tag; a limit that cannot be named cannot be "+
				"written in a policy", field.Name)
		}
		seen[name] = true

		declared, ok := doc.Defs.Limits.Properties[name]
		if !ok {
			t.Errorf("limit %q is settable in Go but absent from the schema", name)
			continue
		}
		switch {
		case declared.Maximum == nil:
			t.Errorf("limit %q declares no maximum; its ceiling is %d",
				name, value.Field(i).Int())
		case *declared.Maximum != value.Field(i).Int():
			t.Errorf("limit %q: schema maximum is %d, the enforced ceiling is %d",
				name, *declared.Maximum, value.Field(i).Int())
		}
		if declared.Minimum == nil || *declared.Minimum != 0 {
			t.Errorf("limit %q should declare minimum 0; zero means unset", name)
		}
	}

	for name := range doc.Defs.Limits.Properties {
		if !seen[name] {
			t.Errorf("schema declares limit %q, which the code does not have", name)
		}
	}
}

// TestInitTemplateValidatesAgainstTheSchema closes the loop between the
// scaffold and the specification.
//
// `devproof init` exists so nobody has to read the schema to write a
// well-formed manifest. That promise is only worth making if the file it
// writes is actually well-formed by the schema's own account, rather than
// merely by the decoder's.
func TestInitTemplateValidatesAgainstTheSchema(t *testing.T) {
	t.Parallel()

	for _, sourcePath := range []string{".", "./content", "../sibling"} {
		t.Run(sourcePath, func(t *testing.T) {
			t.Parallel()

			rendered, err := bundle.Template(sourcePath)
			if err != nil {
				t.Fatalf("rendering the template: %v", err)
			}

			// The template is YAML with comments, so it reaches the schema
			// through the typed model. That is the same path a manifest takes
			// on the way to its digest.
			spec, err := bundle.ParseSpec(rendered)
			if err != nil {
				t.Fatalf("the template does not parse: %v", err)
			}
			encoded, err := json.Marshal(spec)
			if err != nil {
				t.Fatalf("encoding the parsed template: %v", err)
			}

			if err := compile(t, schema.Bundle).Validate(asJSONValue(t, encoded)); err != nil {
				t.Errorf("the manifest init writes does not satisfy the published "+
					"schema:\n%v", err)
			}
		})
	}
}

// TestGoldenConfigValidates points the config schema at the normative format
// fixture.
//
// The synthetic fixtures above prove the schema is self-consistent. This one
// proves it describes what the encoder actually emits.
func TestGoldenConfigValidates(t *testing.T) {
	t.Parallel()

	golden := filepath.Join(repo.Root(),
		"internal", "canonical", "testdata", "format", "v1", "config.json")
	data, err := os.ReadFile(golden)
	if err != nil {
		t.Skipf("golden config fixture unavailable: %v", err)
	}

	if err := compile(t, schema.BundleConfig).Validate(asJSONValue(t, data)); err != nil {
		t.Errorf("the schema rejects the normative golden config:\n%v", err)
	}
	if _, err := bundle.ParseConfig(data); err != nil {
		t.Errorf("the decoder rejects the normative golden config: %v", err)
	}
}
