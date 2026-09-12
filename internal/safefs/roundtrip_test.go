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

package safefs

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
)

// sourceTree is a directory fixture: relative path to content.
type sourceTree map[string]string

// executables names the entries written with the execute bit set.
var executables = map[string]bool{"app/scripts/run.sh": true}

func fixtureTree() sourceTree {
	return sourceTree{
		"README.md":               "hello world\n",
		"app/config/service.yaml": "a: 1\n",
		"app/scripts/run.sh":      "#!/bin/sh\necho hi\n",
		"binary.dat":              "\x00\x01\xfe\xff",
		"café/naïve.txt":          "utf8 content",
		"empty":                   "",
		"deeply/nested/directory/structure/file.txt": "deep",
	}
}

func writeTree(t *testing.T, dir string, tree sourceTree) {
	t.Helper()

	for rel, content := range tree {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		mode := os.FileMode(0o644)
		if executables[rel] {
			mode = 0o755
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatalf("writing %s: %v", full, err)
		}
	}
}

// buildFrom snapshots dir, packages it, and returns the subject and layer.
func buildFrom(t *testing.T, dir string) (*canonical.Subject, []byte) {
	t.Helper()

	snapshot, err := SnapshotDir(t.Context(), dir, SnapshotOptions{TempRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("SnapshotDir(%s): %v", dir, err)
	}
	t.Cleanup(func() {
		if closeErr := snapshot.Close(); closeErr != nil {
			t.Errorf("closing snapshot: %v", closeErr)
		}
	})

	var layer bytes.Buffer
	subject, err := canonical.Package(t.Context(), snapshot.Records(), snapshot, &layer)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	return subject, layer.Bytes()
}

// The roadmap's first useful milestone: a directory becomes an artifact,
// the artifact is verified and expanded back to a directory, and building
// from that directory reproduces every digest exactly.
//
// This is the claim the whole design rests on. If any of the five digests
// differ, DevProof does not have canonical identity.
func TestRoundTripPreservesEveryDigestLevel(t *testing.T) {
	t.Parallel()

	source := t.TempDir()
	writeTree(t, source, fixtureTree())

	first, firstLayer := buildFrom(t, source)

	destination := filepath.Join(t.TempDir(), "expanded")
	result, err := Extract(t.Context(), bytes.NewReader(firstLayer), ExtractOptions{
		Destination: destination,
		Config:      first.Config,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result.Destination != destination {
		t.Errorf("published %q, want %q", result.Destination, destination)
	}
	if result.FileCount != first.Config.FileCount {
		t.Errorf("expanded %d files, the config declares %d", result.FileCount, first.Config.FileCount)
	}

	second, secondLayer := buildFrom(t, destination)

	// The five compatibility assertions from docs/bundle-format.md.
	if first.TreeDigest != second.TreeDigest {
		t.Errorf("tree digest: %s then %s", first.TreeDigest, second.TreeDigest)
	}
	if first.ConfigDigest != second.ConfigDigest {
		t.Errorf("config digest: %s then %s", first.ConfigDigest, second.ConfigDigest)
	}
	if first.LayerDigest != second.LayerDigest {
		t.Errorf("layer digest: %s then %s", first.LayerDigest, second.LayerDigest)
	}
	if first.ManifestDigest != second.ManifestDigest {
		t.Errorf("subject digest: %s then %s", first.ManifestDigest, second.ManifestDigest)
	}
	if !bytes.Equal(firstLayer, secondLayer) {
		t.Error("layer bytes differ between the original and the rebuilt tree")
	}
}

// The expanded tree must hold the same bytes and the same modes, not merely
// hash the same.
func TestRoundTripPreservesContentAndModes(t *testing.T) {
	t.Parallel()

	tree := fixtureTree()
	source := t.TempDir()
	writeTree(t, source, tree)

	subject, layer := buildFrom(t, source)

	destination := filepath.Join(t.TempDir(), "expanded")
	if _, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Destination: destination,
		Config:      subject.Config,
	}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	for rel, want := range tree {
		full := filepath.Join(destination, filepath.FromSlash(rel))

		got, err := os.ReadFile(full) //nolint:gosec // test-controlled path
		if err != nil {
			t.Errorf("reading %s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s content = %q, want %q", rel, got, want)
		}

		info, err := os.Lstat(full)
		if err != nil {
			t.Errorf("stat %s: %v", rel, err)
			continue
		}
		wantMode := os.FileMode(bundle.ModeFile)
		if executables[rel] {
			wantMode = os.FileMode(bundle.ModeExecutable)
		}
		if info.Mode().Perm() != wantMode {
			t.Errorf("%s mode = %#o, want %#o", rel, info.Mode().Perm(), wantMode)
		}
	}
}

// Filesystem enumeration order is not an input to identity. Creating the same
// files in a different order must not change anything.
func TestBuildIsIndependentOfCreationOrder(t *testing.T) {
	t.Parallel()

	tree := fixtureTree()
	keys := slices.Sorted(maps.Keys(tree))

	forward := t.TempDir()
	for _, k := range keys {
		writeTree(t, forward, sourceTree{k: tree[k]})
	}

	slices.Reverse(keys)
	backward := t.TempDir()
	for _, k := range keys {
		writeTree(t, backward, sourceTree{k: tree[k]})
	}

	first, _ := buildFrom(t, forward)
	second, _ := buildFrom(t, backward)

	if first.ManifestDigest != second.ManifestDigest {
		t.Errorf("creation order changed the subject digest: %s then %s",
			first.ManifestDigest, second.ManifestDigest)
	}
}

// Filtering happens against the canonical path, before any mounting, so a
// pattern in a manifest means the same thing regardless of where the source
// ends up in the bundle.
func TestSnapshotAppliesPatterns(t *testing.T) {
	t.Parallel()

	source := t.TempDir()
	writeTree(t, source, sourceTree{
		"config/service.yaml": "a: 1\n",
		"config/scratch.tmp":  "junk",
		"scripts/run.sh":      "#!/bin/sh\n",
		"README.md":           "docs",
	})

	patterns, err := bundle.NewPatternSet(
		[]string{"config/**", "scripts/**"},
		[]string{"**/*.tmp"},
	)
	if err != nil {
		t.Fatalf("NewPatternSet: %v", err)
	}

	snapshot, err := SnapshotDir(t.Context(), source, SnapshotOptions{
		Patterns: patterns,
		TempRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("SnapshotDir: %v", err)
	}
	defer func() { _ = snapshot.Close() }()

	var got []string
	for _, record := range snapshot.Records() {
		got = append(got, string(record.Path))
	}
	want := []string{"config/service.yaml", "scripts/run.sh"}
	if !slices.Equal(got, want) {
		t.Errorf("selected %v, want %v", got, want)
	}
}
