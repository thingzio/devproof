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

package devproof_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/thingzio/devproof/pkg/devproof"
)

// buildLayout builds dir into a local layout and returns the reference.
func buildLayout(t *testing.T, client *devproof.Client, dir string) string {
	t.Helper()

	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  dir,
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	_ = built
	return "oci-layout://" + layout + ":v1"
}

// changesByPath indexes a result for assertions.
func changesByPath(result *devproof.DiffResult) map[string]devproof.DiffEntry {
	out := make(map[string]devproof.DiffEntry, len(result.Changes))
	for _, change := range result.Changes {
		out[change.Path] = change
	}
	return out
}

// TestDiffIdenticalDirectories is the base case, and it also pins the
// relationship the result claims: equal tree digests means no changes.
func TestDiffIdenticalDirectories(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	files := map[string]string{"a.yaml": "a: 1\n", "nested/b.txt": "b\n"}
	left := writeSource(t, files)
	right := writeSource(t, files)

	result, err := client.Diff(t.Context(), devproof.DiffRequest{From: left, To: right})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if !result.Identical {
		t.Errorf("two directories with the same content are not identical")
	}
	if len(result.Changes) != 0 {
		t.Errorf("identical trees reported %d changes: %v", len(result.Changes), result.Changes)
	}
	if result.From.TreeDigest != result.To.TreeDigest {
		t.Errorf("tree digests differ: %s vs %s", result.From.TreeDigest, result.To.TreeDigest)
	}
	if result.From.Kind != devproof.OperandDirectory {
		t.Errorf("operand kind = %q, want directory", result.From.Kind)
	}
}

// TestDiffClassifiesEveryChangeKind covers all four classifications at once,
// so a change to one cannot be masked by another being reported instead.
func TestDiffClassifiesEveryChangeKind(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	left := writeSource(t, map[string]string{
		"kept.txt":    "same\n",
		"changed.txt": "before\n",
		"removed.txt": "gone\n",
		"exec.sh":     "#!/bin/sh\n",
	})
	right := writeSource(t, map[string]string{
		"kept.txt":    "same\n",
		"changed.txt": "after\n",
		"added.txt":   "new\n",
		"exec.sh":     "#!/bin/sh\n",
	})
	// Same bytes, different mode: the one case that must not be reported as
	// a content change.
	if err := os.Chmod(filepath.Join(right, "exec.sh"), 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	result, err := client.Diff(t.Context(), devproof.DiffRequest{From: left, To: right})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if result.Identical {
		t.Fatal("trees with different content reported identical")
	}

	changes := changesByPath(result)
	for path, want := range map[string]devproof.Change{
		"added.txt":   devproof.ChangeAdded,
		"removed.txt": devproof.ChangeRemoved,
		"changed.txt": devproof.ChangeModified,
		"exec.sh":     devproof.ChangeModeChanged,
	} {
		got, ok := changes[path]
		if !ok {
			t.Errorf("%s is missing from the diff", path)
			continue
		}
		if got.Change != want {
			t.Errorf("%s classified %q, want %q", path, got.Change, want)
		}
	}
	if _, reported := changes["kept.txt"]; reported {
		t.Error("an unchanged file was reported as a change")
	}

	if result.Added != 1 || result.Removed != 1 || result.Modified != 1 || result.ModeChanged != 1 {
		t.Errorf("counts are added=%d removed=%d modified=%d modeChanged=%d, want 1 each",
			result.Added, result.Removed, result.Modified, result.ModeChanged)
	}
}

// TestDiffModeChangeKeepsDigests checks that a mode-only change still reports
// both digests, and that they are equal.
//
// The classification and the evidence for it must agree: a reader who does
// not trust the label should be able to see for themselves that the bytes
// did not move.
func TestDiffModeChangeKeepsDigests(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	left := writeSource(t, map[string]string{"run.sh": "#!/bin/sh\necho hi\n"})
	right := writeSource(t, map[string]string{"run.sh": "#!/bin/sh\necho hi\n"})
	if err := os.Chmod(filepath.Join(right, "run.sh"), 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	result, err := client.Diff(t.Context(), devproof.DiffRequest{From: left, To: right})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("got %d changes, want 1: %v", len(result.Changes), result.Changes)
	}

	change := result.Changes[0]
	if change.Change != devproof.ChangeModeChanged {
		t.Errorf("classified %q, want mode-changed", change.Change)
	}
	if change.OldDigest != change.NewDigest {
		t.Errorf("a mode change reports different digests: %s vs %s",
			change.OldDigest, change.NewDigest)
	}
	if change.OldMode == change.NewMode {
		t.Errorf("a mode change reports the same mode twice: %#o", change.OldMode)
	}
}

// TestDiffBundleAgainstItsOwnSource is the question the command exists for:
// has anything changed since I built this?
func TestDiffBundleAgainstItsOwnSource(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	dir := writeSource(t, map[string]string{"config.yaml": "key: value\n"})
	reference := buildLayout(t, client, dir)

	result, err := client.Diff(t.Context(), devproof.DiffRequest{From: reference, To: dir})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !result.Identical {
		t.Errorf("a bundle differs from the directory it was built from: %v", result.Changes)
	}
	if result.From.Kind != devproof.OperandBundle {
		t.Errorf("left operand kind = %q, want bundle", result.From.Kind)
	}
	if result.From.Subject == "" {
		t.Error("a bundle operand reports no subject digest")
	}
	if result.To.Subject != "" {
		t.Error("a directory operand reports a subject digest")
	}

	// Now change the directory and confirm it is noticed.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("key: other\n"), 0o644); err != nil {
		t.Fatalf("modifying source: %v", err)
	}
	changed, err := client.Diff(t.Context(), devproof.DiffRequest{From: reference, To: dir})
	if err != nil {
		t.Fatalf("Diff after change: %v", err)
	}
	if changed.Identical {
		t.Error("a modified directory still reports identical")
	}
	if changed.Modified != 1 {
		t.Errorf("modified = %d, want 1", changed.Modified)
	}
}

// TestDiffIsOrderedByPath keeps the output stable for review and for tests.
func TestDiffIsOrderedByPath(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	left := writeSource(t, map[string]string{"m.txt": "m\n"})
	right := writeSource(t, map[string]string{
		"z.txt": "z\n", "a.txt": "a\n", "m/nested.txt": "n\n", "b.txt": "b\n",
	})

	result, err := client.Diff(t.Context(), devproof.DiffRequest{From: left, To: right})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	paths := make([]string, len(result.Changes))
	for i, change := range result.Changes {
		paths[i] = change.Path
	}
	if !sort.StringsAreSorted(paths) {
		t.Errorf("changes are not sorted by path: %v", paths)
	}
}

// TestDiffIsSymmetric checks that swapping the operands swaps added and
// removed, rather than producing an unrelated answer.
func TestDiffIsSymmetric(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	left := writeSource(t, map[string]string{"only-left.txt": "l\n", "both.txt": "1\n"})
	right := writeSource(t, map[string]string{"only-right.txt": "r\n", "both.txt": "2\n"})

	forward, err := client.Diff(t.Context(), devproof.DiffRequest{From: left, To: right})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	backward, err := client.Diff(t.Context(), devproof.DiffRequest{From: right, To: left})
	if err != nil {
		t.Fatalf("Diff reversed: %v", err)
	}

	if forward.Added != backward.Removed || forward.Removed != backward.Added {
		t.Errorf("reversing the operands did not swap added and removed: "+
			"forward(+%d -%d) backward(+%d -%d)",
			forward.Added, forward.Removed, backward.Added, backward.Removed)
	}
	if forward.Modified != backward.Modified {
		t.Errorf("modified count changed with direction: %d vs %d",
			forward.Modified, backward.Modified)
	}
}

// TestDiffRejectsMissingOperands checks the input contract.
func TestDiffRejectsMissingOperands(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	for _, request := range []devproof.DiffRequest{
		{},
		{From: "./somewhere"},
		{To: "./somewhere"},
	} {
		if _, err := client.Diff(t.Context(), request); err == nil {
			t.Errorf("Diff(%+v) accepted an incomplete request", request)
		} else if codeOf(err) != devproof.CodeInvalidInput {
			t.Errorf("Diff(%+v) code = %q, want invalid-input", request, codeOf(err))
		}
	}
}
