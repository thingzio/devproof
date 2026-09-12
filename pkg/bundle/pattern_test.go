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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devproof/pkg/fault"
)

func TestPatternMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Literals.
		{"config.yaml", "config.yaml", true},
		{"config.yaml", "other.yaml", false},
		{"app/config.yaml", "app/config.yaml", true},
		{"app/config.yaml", "app/other.yaml", false},

		// * stops at a separator.
		{"*.yaml", "config.yaml", true},
		{"*.yaml", "app/config.yaml", false},
		{"app/*.yaml", "app/config.yaml", true},
		{"app/*.yaml", "app/nested/config.yaml", false},
		{"*", "config.yaml", true},
		{"*", "app/config.yaml", false},

		// ? is exactly one non-separator character.
		{"config.?aml", "config.yaml", true},
		{"config.?aml", "config.aml", false},
		{"?", "a", true},
		{"?", "ab", false},

		// Character classes.
		{"config.[yj]aml", "config.yaml", true},
		{"config.[yj]aml", "config.jaml", true},
		{"config.[yj]aml", "config.xaml", false},
		{"v[0-9].txt", "v1.txt", true},
		{"v[0-9].txt", "va.txt", false},

		// ** spans whole segments, including none.
		{"**", "config.yaml", true},
		{"**", "a/b/c/d.yaml", true},
		{"**/*.yaml", "config.yaml", true},
		{"**/*.yaml", "app/config.yaml", true},
		{"**/*.yaml", "a/b/c/config.yaml", true},
		{"**/*.yaml", "config.json", false},
		{"app/**", "app/config.yaml", true},
		{"app/**", "app/nested/deep/config.yaml", true},
		{"app/**", "other/config.yaml", false},
		{"app/**/*.yaml", "app/config.yaml", true},
		{"app/**/*.yaml", "app/a/b/config.yaml", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},

		// Several ** in one pattern.
		{"**/**/*.yaml", "a/b/c.yaml", true},
		{"**/x/**", "a/b/x/c/d", true},
		{"**/x/**", "a/b/y/c/d", false},

		// A pattern longer than the path.
		{"a/b/c", "a/b", false},
		{"a/b", "a/b/c", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			t.Parallel()
			compiled, err := ParsePattern(tc.pattern)
			if err != nil {
				t.Fatalf("ParsePattern(%q): %v", tc.pattern, err)
			}
			if got := compiled.Match(tc.path); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParsePatternRejects(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"/absolute",
		"a//b",
		"./a",
		"a/./b",
		"../escape",
		"a/../b",
		"..",
		"a/**b",       // ** must stand alone in a segment
		"a/b**",       //
		"**x/a",       //
		"a/[unclosed", // malformed class
	} {
		if _, err := ParsePattern(raw); !stderrors.Is(err, fault.CodeInvalidInput) {
			t.Errorf("ParsePattern(%q) = %v, want %q", raw, err, fault.CodeInvalidInput)
		}
	}
}

func TestPatternSetSelects(t *testing.T) {
	t.Parallel()

	set, err := NewPatternSet(
		[]string{"config/**", "scripts/**"},
		[]string{"**/*.tmp", "**/.DS_Store"},
	)
	if err != nil {
		t.Fatalf("NewPatternSet: %v", err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"config/service.yaml", true},
		{"config/nested/deep.yaml", true},
		{"scripts/run.sh", true},
		{"README.md", false},
		{"other/file.yaml", false},
		{"config/scratch.tmp", false},
		{"config/nested/.DS_Store", false},
	}

	for _, tc := range tests {
		if got := set.Selects(tc.path); got != tc.want {
			t.Errorf("Selects(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// An absent include list means everything, spelled explicitly so there is no
// separate unfiltered code path.
func TestPatternSetEmptyIncludeSelectsEverything(t *testing.T) {
	t.Parallel()

	set, err := NewPatternSet(nil, nil)
	if err != nil {
		t.Fatalf("NewPatternSet: %v", err)
	}
	for _, path := range []string{"a", "a/b", "a/b/c.yaml", "deeply/nested/file"} {
		if !set.Selects(path) {
			t.Errorf("Selects(%q) = false, want true", path)
		}
	}
}

// Exclude wins over include regardless of how specific either is. Without
// this the result would depend on which rule was "more specific", which is a
// judgment two implementations could make differently.
func TestPatternSetExcludeAlwaysWins(t *testing.T) {
	t.Parallel()

	set, err := NewPatternSet([]string{"config/service.yaml"}, []string{"**"})
	if err != nil {
		t.Fatalf("NewPatternSet: %v", err)
	}
	if set.Selects("config/service.yaml") {
		t.Error("an excluded path was selected despite an exact include")
	}
}

// Include and exclude are sets. Reordering a manifest must not change what it
// selects (DP-011).
func TestPatternSetIsOrderIndependent(t *testing.T) {
	t.Parallel()

	include := []string{"a/**", "b/**", "c/**"}
	exclude := []string{"**/*.tmp", "**/*.bak"}
	paths := []string{"a/x", "b/y.tmp", "c/z.bak", "d/w", "a/nested/deep"}

	reference, err := NewPatternSet(include, exclude)
	if err != nil {
		t.Fatalf("NewPatternSet: %v", err)
	}

	slices.Reverse(include)
	slices.Reverse(exclude)
	reordered, err := NewPatternSet(include, exclude)
	if err != nil {
		t.Fatalf("NewPatternSet reordered: %v", err)
	}

	for _, p := range paths {
		if reference.Selects(p) != reordered.Selects(p) {
			t.Errorf("reordering changed the result for %q", p)
		}
	}
}

func TestNormalizePatterns(t *testing.T) {
	t.Parallel()

	got := NormalizePatterns([]string{"z/**", "a/**", "z/**", "m/**"})
	want := []string{"a/**", "m/**", "z/**"}

	if !slices.Equal(got, want) {
		t.Errorf("= %v, want %v", got, want)
	}
	if NormalizePatterns(nil) != nil {
		t.Error("an empty list did not normalize to nil")
	}
}

// A pattern a source repository can supply must not be able to cost
// exponential time. The recursive formulation of ** blows up on this input;
// the table-based one does not.
func TestPatternMatchingIsNotExponential(t *testing.T) {
	t.Parallel()

	pattern, err := ParsePattern(strings.Repeat("**/", 24) + "needle")
	if err != nil {
		t.Fatalf("ParsePattern: %v", err)
	}
	candidate := strings.Repeat("a/", 40) + "haystack"

	done := make(chan bool, 1)
	go func() { done <- pattern.Match(candidate) }()

	select {
	case matched := <-done:
		if matched {
			t.Error("the pattern should not have matched")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("matching did not finish; the implementation is superlinear in **")
	}
}
