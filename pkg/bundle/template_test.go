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

package bundle_test

import (
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
)

func TestTemplateParsesAndCarriesTheSourcePath(t *testing.T) {
	t.Parallel()

	rendered, err := bundle.Template("./content")
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}

	spec, err := bundle.ParseSpec(rendered)
	if err != nil {
		t.Fatalf("the rendered template does not parse: %v", err)
	}

	if len(spec.Spec.Sources) != 1 {
		t.Fatalf("template declares %d sources, want exactly 1 active one",
			len(spec.Spec.Sources))
	}
	source := spec.Spec.Sources[0]
	if source.Type != bundle.SourceTypePath {
		t.Errorf("source type is %q, want %q", source.Type, bundle.SourceTypePath)
	}
	if got := source.Config["path"]; got != "./content" {
		t.Errorf("source path is %v, want ./content", got)
	}
}

// TestTemplateDefaultsToCurrentDirectory covers `devproof init` with no --src.
func TestTemplateDefaultsToCurrentDirectory(t *testing.T) {
	t.Parallel()

	rendered, err := bundle.Template("")
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	spec, err := bundle.ParseSpec(rendered)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if got := spec.Spec.Sources[0].Config["path"]; got != "." {
		t.Errorf("source path is %v, want .", got)
	}
}

// TestTemplateQuotesAwkwardPaths checks that a path YAML would otherwise read
// as syntax survives as one scalar.
//
// Interpolating raw text into a document that is then parsed is the classic
// injection shape. Here the worst case is a manifest that means something
// other than what was asked for, which is exactly what a scaffold must not
// produce.
func TestTemplateQuotesAwkwardPaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"./has: colon",
		"-leading-dash",
		"./#hash",
		"./trailing space ",
		"./quote'and\"quote",
		"*",
		"./multi\nline",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			rendered, err := bundle.Template(path)
			if err != nil {
				t.Fatalf("rendering %q: %v", path, err)
			}
			spec, err := bundle.ParseSpec(rendered)
			if err != nil {
				t.Fatalf("rendered template for %q does not parse: %v", path, err)
			}
			if got := spec.Spec.Sources[0].Config["path"]; got != path {
				t.Errorf("source path round-tripped to %#v, want %#v", got, path)
			}
		})
	}
}

// TestTemplateTeachesWhatTheSchemaWouldHaveTo checks the comments still name
// the things someone would otherwise open the schema to discover.
//
// The template exists because a user should not have to read a schema to
// write a well-formed manifest. Comments are load-bearing here, so losing one
// in an edit is a regression rather than cosmetic.
func TestTemplateTeachesWhatTheSchemaWouldHaveTo(t *testing.T) {
	t.Parallel()

	rendered, err := bundle.Template(".")
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	text := string(rendered)

	for _, mention := range []string{
		"type: git",       // the other built-in source type
		"include:",        // filtering
		"exclude:",        // filtering
		"mountPath",       // placement
		"subPath",         // partial checkout
		"ref:",            // how a git source is pinned
		"devproof lock",   // the next command to run
		"schemas/bundle.", // where the full grammar lives
	} {
		if !strings.Contains(text, mention) {
			t.Errorf("template no longer mentions %q, which a user would "+
				"otherwise have to find in the schema", mention)
		}
	}
}
