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

package repo_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/repo"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/evidence"
)

// These are documentation-contract tests.
//
// Prose drifts silently. Nothing fails when a document describes a package
// that moved, a media type that was renamed, or a flag that never existed —
// the reader simply follows the instruction and it does not work, and the only
// signal is somebody deciding the documentation is unreliable. Each test here
// picks one machine-checkable claim the documentation makes and fails when the
// repository stops backing it.

// markdownFiles returns every documentation file in the repository.
func markdownFiles(t *testing.T) []string {
	t.Helper()

	root := repo.Root()
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Vendored and generated trees describe somebody else's repository.
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "dist":
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".md") && !strings.Contains(path, "THIRD_PARTY") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no documentation files were found")
	}
	return files
}

// TestDocumentedImportPathsExist catches a document telling somebody to import
// a package that is not there.
//
// An import path is the most literal instruction documentation gives: it is
// copied into a file verbatim. One that names a package which has moved fails
// at the reader's compiler, which is the worst place to find out.
func TestDocumentedImportPathsExist(t *testing.T) {
	t.Parallel()

	const module = "github.com/thingzio/devproof"
	pattern := regexp.MustCompile(regexp.QuoteMeta(module) + `(/[a-z0-9][a-z0-9/]*)?`)

	var checked int
	for _, file := range markdownFiles(t) {
		data, err := os.ReadFile(file) //nolint:gosec // a repository path
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		text := string(data)
		for _, span := range pattern.FindAllStringIndex(text, -1) {
			// The module path and the repository's web URL are the same
			// string. A link to an issue or a workflow is not an import.
			if strings.HasSuffix(text[:span[0]], "://") {
				continue
			}

			match := text[span[0]:span[1]]
			suffix := strings.TrimPrefix(match, module)
			suffix = strings.TrimPrefix(suffix, "/")
			if suffix == "" {
				continue
			}
			checked++

			dir := filepath.Join(repo.Root(), filepath.FromSlash(suffix))
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				t.Errorf("%s names the import path %s, which is not a package in this module",
					mustRel(t, repo.Root(), file), match)
			}
		}
	}
	if checked == 0 {
		t.Error("no import paths were checked; the pattern has stopped matching")
	}
}

// TestDocumentedMediaTypesAreDefined catches a renamed media type.
//
// A media type is a wire contract: a consumer filters referrers by it and
// selects a config parser by it. Documentation naming one this build does not
// emit describes an artifact nobody produces.
func TestDocumentedMediaTypesAreDefined(t *testing.T) {
	t.Parallel()

	defined := map[string]bool{
		bundle.MediaTypeArtifactV1:      true,
		bundle.MediaTypeConfigV1:        true,
		bundle.MediaTypeLayerV1:         true,
		artifact.MediaTypeImageManifest: true,
		artifact.MediaTypeEmptyJSON:     true,
		evidence.MediaTypeEvidenceV1:    true,
		evidence.MediaTypeBundleV1:      true,
	}

	// The vendor tree is named as a prefix in the decision that reserves it,
	// which is a claim about the namespace rather than about one type.
	const vendorTree = "application/vnd.thingz.devproof.*"

	// A sentence-ending period is not part of the type.
	pattern := regexp.MustCompile(`application/vnd\.[A-Za-z0-9][A-Za-z0-9.+*-]*`)

	var checked int
	for _, file := range markdownFiles(t) {
		data, err := os.ReadFile(file) //nolint:gosec // a repository path
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, match := range pattern.FindAllString(string(data), -1) {
			if match == vendorTree {
				continue
			}
			match = strings.TrimRight(match, ".")
			if defined[match] {
				checked++
				continue
			}
			t.Errorf("%s names the media type %q, which no constant defines",
				mustRel(t, repo.Root(), file), match)
		}
	}
	if checked == 0 {
		t.Error("no media types were checked; the pattern has stopped matching")
	}
}

// TestDocumentedSchemasExist catches a reference to a schema that was renamed
// or never published.
func TestDocumentedSchemasExist(t *testing.T) {
	t.Parallel()

	pattern := regexp.MustCompile(`[a-z0-9.-]+\.schema\.json`)

	var checked int
	for _, file := range markdownFiles(t) {
		data, err := os.ReadFile(file) //nolint:gosec // a repository path
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, name := range pattern.FindAllString(string(data), -1) {
			checked++
			if _, err := os.Stat(filepath.Join(repo.Root(), "schemas", name)); err != nil {
				t.Errorf("%s names the schema %s, which is not published",
					mustRel(t, repo.Root(), file), name)
			}
		}
	}
	if checked == 0 {
		t.Error("no schema references were checked; the pattern has stopped matching")
	}
}

// TestDocumentedSDKTypesExist catches a reference naming a type the SDK does
// not have.
//
// The SDK reference is read by somebody writing code against it, so a type it
// names is a type they expect to compile. It named VerifyResult, which never
// existed: verification returns the proof report, and a second type wrapping
// it would be a second thing to keep in step.
func TestDocumentedSDKTypesExist(t *testing.T) {
	t.Parallel()

	root := repo.Root()
	data, err := os.ReadFile(filepath.Join(root, "docs", "sdk.md"))
	if err != nil {
		t.Fatalf("reading the SDK reference: %v", err)
	}

	// Request and result types are the reference's load-bearing names and the
	// ones a reader types verbatim. Narrowing to that suffix keeps the check
	// from guessing at prose that happens to be capitalized.
	pattern := regexp.MustCompile("`([A-Z][A-Za-z0-9]*(Request|Result))`")

	declared, err := declaredTypes(root)
	if err != nil {
		t.Fatalf("scanning declared types: %v", err)
	}

	var checked int
	for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
		checked++
		if !declared[match[1]] {
			t.Errorf("docs/sdk.md names the type %s, which no package declares", match[1])
		}
	}
	if checked == 0 {
		t.Error("no SDK types were checked; the pattern has stopped matching")
	}
}

// declaredTypes collects every type name declared under pkg/.
func declaredTypes(root string) (map[string]bool, error) {
	declaration := regexp.MustCompile(`(?m)^type ([A-Z][A-Za-z0-9]*) `)
	declared := map[string]bool{}

	err := filepath.WalkDir(filepath.Join(root, "pkg"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // a repository path
		if readErr != nil {
			return readErr
		}
		for _, match := range declaration.FindAllStringSubmatch(string(data), -1) {
			declared[match[1]] = true
		}
		return nil
	})
	return declared, err
}

// TestDocumentedPolicyFieldsExist catches the policy reference naming a rule
// that no policy can express.
//
// This is the failure mode with the longest history here: the reference once
// documented sources.allowedSchemes, a field SourceRules has never had, and
// later promised an expected manifest digest, an expected lock digest, and a
// resolver version range against a type carrying none of them. A reader writes
// the rule, the strict decoder rejects it, and the document is what they stop
// trusting.
//
// Backticked identifiers only. Prose that describes a capability without
// naming a field is beyond a mechanical check, which is exactly why the
// reference should name the field.
func TestDocumentedPolicyFieldsExist(t *testing.T) {
	t.Parallel()

	root := repo.Root()
	doc, err := os.ReadFile(filepath.Join(root, "docs", "policy.md"))
	if err != nil {
		t.Fatalf("reading the policy reference: %v", err)
	}
	schemaBytes, err := os.ReadFile(
		filepath.Join(root, "schemas", "verification-policy.v1alpha1.schema.json"))
	if err != nil {
		t.Fatalf("reading the policy schema: %v", err)
	}

	// Every property name the schema defines, at any depth.
	declared := map[string]bool{}
	property := regexp.MustCompile(`"([a-z][a-zA-Z0-9]*)":\s*\{`)
	for _, match := range property.FindAllStringSubmatch(string(schemaBytes), -1) {
		declared[match[1]] = true
	}

	// Words that are commands, statuses, or finding codes rather than fields.
	ignore := map[string]bool{
		"verify": true, "expand": true, "build": true, "diff": true,
		"inspect": true, "lock": true, "init": true, "copy": true,
		"pass": true, "fail": true,
	}

	var checked int
	field := regexp.MustCompile("`([a-z][a-zA-Z0-9]*(?:\\.[a-zA-Z0-9]+)*)`")
	for _, match := range field.FindAllStringSubmatch(string(doc), -1) {
		path := match[1]
		leaf := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			leaf = path[i+1:]
		}
		if ignore[leaf] || strings.Contains(path, "-") {
			continue
		}
		// A bare lowercase word may be prose; a dotted path is a field claim,
		// and so is any word the schema would be expected to define.
		if !strings.Contains(path, ".") && !declared[leaf] {
			continue
		}

		checked++
		if !declared[leaf] {
			t.Errorf("docs/policy.md names the policy field %q, which the schema does not define", path)
		}
	}
	if checked == 0 {
		t.Error("no policy fields were checked; the pattern has stopped matching")
	}
}
