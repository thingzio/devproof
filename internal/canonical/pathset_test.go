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
	stderrors "errors"
	"slices"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

// addAll adds every path in order and returns the first failure.
func addAll(t *testing.T, paths ...string) error {
	t.Helper()

	var s PathSet
	for _, p := range paths {
		if err := s.Add(Path(p)); err != nil {
			return err
		}
	}
	return nil
}

func TestPathSetAcceptsDisjointTree(t *testing.T) {
	t.Parallel()

	err := addAll(t,
		"app/config/service.yaml",
		"app/config/other.yaml",
		"app/scripts/run.sh",
		"environment/production.yaml",
		"README.md",
	)
	if err != nil {
		t.Errorf("a disjoint tree was rejected: %v", err)
	}
}

func TestPathSetRejectsDuplicate(t *testing.T) {
	t.Parallel()

	err := addAll(t, "app/config.yaml", "app/config.yaml")
	if !stderrors.Is(err, fault.CodePathCollision) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodePathCollision)
	}
}

// Equal bytes do not rescue a collision: ownership would still be ambiguous,
// and DP-011 gives every final path exactly one source owner.
func TestPathSetRejectsDuplicateRegardlessOfContent(t *testing.T) {
	t.Parallel()

	var s PathSet
	if err := s.Add("a.txt"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := s.Add("a.txt"); err == nil {
		t.Error("a duplicate path was accepted")
	}
}

func TestPathSetRejectsCaseCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		paths []string
	}{
		{"file case", []string{"README.md", "readme.md"}},
		{"directory case", []string{"App/config.yaml", "app/other.yaml"}},
		{"deep directory case", []string{"a/B/c/x.txt", "a/b/c/y.txt"}},
		{"kelvin sign against ascii k", []string{"k.txt", "K.txt"}},
		{"sharp s case pair", []string{"ß.txt", "ẞ.txt"}},
		{"file against directory of another case", []string{"config", "CONFIG/a.txt"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := addAll(t, tc.paths...)
			if !stderrors.Is(err, fault.CodePathCollision) {
				t.Errorf("paths %v: code = %q, want %q", tc.paths, fault.CodeOf(err), fault.CodePathCollision)
			}
		})
	}
}

// Simple folding, so these coexist. A false rejection here would refuse
// bundles that expand cleanly on every supported platform.
func TestPathSetAllowsFullFoldingLookalikes(t *testing.T) {
	t.Parallel()

	if err := addAll(t, "ß.txt", "ss.txt"); err != nil {
		t.Errorf("sharp-s and ss were treated as colliding: %v", err)
	}
	if err := addAll(t, "ﬁle.txt", "file.txt"); err != nil {
		t.Errorf("fi-ligature and fi were treated as colliding: %v", err)
	}
}

// A path that is a file in one entry and a directory in another cannot be
// materialized at all. It must fail whichever order it arrives in.
func TestPathSetRejectsFileDirectoryConflictBothOrders(t *testing.T) {
	t.Parallel()

	t.Run("file first", func(t *testing.T) {
		t.Parallel()
		err := addAll(t, "app/config", "app/config/service.yaml")
		if !stderrors.Is(err, fault.CodePathCollision) {
			t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodePathCollision)
		}
	})

	t.Run("directory first", func(t *testing.T) {
		t.Parallel()
		err := addAll(t, "app/config/service.yaml", "app/config")
		if !stderrors.Is(err, fault.CodePathCollision) {
			t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodePathCollision)
		}
	})
}

func TestPathSetRejectsDeepAncestorConflict(t *testing.T) {
	t.Parallel()

	err := addAll(t, "a", "a/b/c/d.txt")
	if !stderrors.Is(err, fault.CodePathCollision) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodePathCollision)
	}
}

// DP-011: source ordering cannot change the outcome. A colliding set must be
// rejected in every permutation, and a clean set accepted in every one.
func TestPathSetOutcomeIsOrderIndependent(t *testing.T) {
	t.Parallel()

	colliding := []string{"app/config", "app/config/service.yaml", "README.md"}
	clean := []string{"app/config/service.yaml", "app/other.yaml", "README.md"}

	for _, perm := range permutations(len(colliding)) {
		ordered := apply(colliding, perm)
		if err := addAll(t, ordered...); err == nil {
			t.Errorf("permutation %v was accepted despite a collision", ordered)
		}
	}

	for _, perm := range permutations(len(clean)) {
		ordered := apply(clean, perm)
		if err := addAll(t, ordered...); err != nil {
			t.Errorf("permutation %v was rejected: %v", ordered, err)
		}
	}
}

func TestPathSetFilesAreSortedByCanonicalBytes(t *testing.T) {
	t.Parallel()

	var s PathSet
	for _, p := range []string{"b.txt", "a/z.txt", "a/a.txt", "A.txt", "é.txt"} {
		if err := s.Add(Path(p)); err != nil {
			t.Fatalf("Add(%q): %v", p, err)
		}
	}

	got := s.Files()
	if !slices.IsSorted(got) {
		t.Errorf("Files() is not sorted: %v", got)
	}
	if s.Len() != 5 {
		t.Errorf("Len() = %d, want 5", s.Len())
	}
}

// The tar stream requires every parent before its first child. Byte-order
// sorting delivers that for free, and this locks it in.
func TestPathSetDirectoriesPlaceParentsBeforeChildren(t *testing.T) {
	t.Parallel()

	var s PathSet
	for _, p := range []string{"a/b/c/deep.txt", "a/other.txt", "z/one.txt"} {
		if err := s.Add(Path(p)); err != nil {
			t.Fatalf("Add(%q): %v", p, err)
		}
	}

	dirs := s.Directories()
	want := []string{"a", "a/b", "a/b/c", "z"}
	if !slices.Equal(dirs, want) {
		t.Fatalf("Directories() = %v, want %v", dirs, want)
	}

	for i, dir := range dirs {
		for _, parent := range Path(dir).Parents() {
			if idx := slices.Index(dirs, parent); idx >= i {
				t.Errorf("parent %q appears at %d, after its child %q at %d", parent, idx, dir, i)
			}
		}
	}
}

func TestPathSetHasFile(t *testing.T) {
	t.Parallel()

	var s PathSet
	if err := s.Add("a/b.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !s.HasFile("a/b.txt") {
		t.Error("HasFile is false for an added file")
	}
	// A derived directory is not a file.
	if s.HasFile("a") {
		t.Error("HasFile is true for a derived directory")
	}
	if s.HasFile("missing.txt") {
		t.Error("HasFile is true for an absent path")
	}
}

func TestPathSetRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	var s PathSet
	if err := s.Add(""); !stderrors.Is(err, fault.CodeUnsafePath) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsafePath)
	}
}

// permutations yields every ordering of n indices.
func permutations(n int) [][]int {
	if n <= 1 {
		return [][]int{make([]int, n)}
	}
	var out [][]int
	var rec func(current []int, remaining []int)
	rec = func(current, remaining []int) {
		if len(remaining) == 0 {
			out = append(out, slices.Clone(current))
			return
		}
		for i, v := range remaining {
			rest := slices.Concat(remaining[:i], remaining[i+1:])
			// Clone rather than append in place: successive iterations would
			// otherwise share current's backing array and overwrite each
			// other's choices.
			next := append(slices.Clone(current), v)
			rec(next, rest)
		}
	}
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	rec(nil, all)
	return out
}

func apply(items []string, perm []int) []string {
	out := make([]string, len(perm))
	for i, idx := range perm {
		out[i] = items[idx]
	}
	return out
}
