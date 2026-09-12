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

package compose

import (
	"context"
	stderrors "errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/source"
)

// fakeSnapshot is an in-memory source contribution.
type fakeSnapshot struct {
	files  map[string]string
	closed bool
}

func newFakeSnapshot(files map[string]string) *fakeSnapshot {
	return &fakeSnapshot{files: files}
}

func (f *fakeSnapshot) Material() source.Material { return source.Material{Type: "fake"} }

func (f *fakeSnapshot) Records() []canonical.FileRecord {
	records := make([]canonical.FileRecord, 0, len(f.files))
	for path, content := range f.files {
		records = append(records, canonical.FileRecord{
			Path:   canonical.Path(path),
			Mode:   bundle.ModeFile,
			Size:   int64(len(content)),
			Digest: canonical.DigestOf([]byte(content)),
		})
	}
	slices.SortFunc(records, func(a, b canonical.FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})
	return records
}

func (f *fakeSnapshot) Open(_ context.Context, p canonical.Path) (io.ReadCloser, error) {
	content, ok := f.files[string(p)]
	if !ok {
		return nil, stderrors.New("no such path: " + string(p))
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (f *fakeSnapshot) Close() error {
	f.closed = true
	return nil
}

func TestComposeMountsSources(t *testing.T) {
	t.Parallel()

	result, err := Compose([]Source{
		{Name: "application", MountPath: "app", Snapshot: newFakeSnapshot(map[string]string{
			"config/service.yaml": "a: 1\n",
		})},
		{Name: "environment", MountPath: "environment", Snapshot: newFakeSnapshot(map[string]string{
			"production.yaml": "env: prod\n",
		})},
	}, bundle.Limits{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	var paths []string
	for _, record := range result.Records {
		paths = append(paths, string(record.Path))
	}
	want := []string{"app/config/service.yaml", "environment/production.yaml"}
	if !slices.Equal(paths, want) {
		t.Errorf("composed %v, want %v", paths, want)
	}

	owner := result.Owners["app/config/service.yaml"]
	if owner.Source != "application" || owner.SourcePath != "config/service.yaml" {
		t.Errorf("owner = %+v", owner)
	}
}

// A source mounted at the root contributes its paths unchanged.
func TestComposeRootMount(t *testing.T) {
	t.Parallel()

	for _, mount := range []string{"", "."} {
		result, err := Compose([]Source{
			{Name: "only", MountPath: mount, Snapshot: newFakeSnapshot(map[string]string{"a.yaml": "x"})},
		}, bundle.Limits{})
		if err != nil {
			t.Fatalf("mount %q: %v", mount, err)
		}
		if string(result.Records[0].Path) != "a.yaml" {
			t.Errorf("mount %q produced %q", mount, result.Records[0].Path)
		}
	}
}

// DP-011: the result cannot depend on the order sources were handed over,
// because resolution is concurrent and completion order is arbitrary.
func TestComposeIsOrderIndependent(t *testing.T) {
	t.Parallel()

	build := func() []Source {
		return []Source{
			{Name: "alpha", MountPath: "a", Snapshot: newFakeSnapshot(map[string]string{"one": "1"})},
			{Name: "bravo", MountPath: "b", Snapshot: newFakeSnapshot(map[string]string{"two": "2"})},
			{Name: "charlie", MountPath: "c", Snapshot: newFakeSnapshot(map[string]string{"three": "3"})},
		}
	}

	forward, err := Compose(build(), bundle.Limits{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	reversed := build()
	slices.Reverse(reversed)
	backward, err := Compose(reversed, bundle.Limits{})
	if err != nil {
		t.Fatalf("Compose reversed: %v", err)
	}

	forwardDigest, err := canonical.TreeDigest(forward.Records)
	if err != nil {
		t.Fatalf("TreeDigest: %v", err)
	}
	backwardDigest, err := canonical.TreeDigest(backward.Records)
	if err != nil {
		t.Fatalf("TreeDigest reversed: %v", err)
	}
	if forwardDigest != backwardDigest {
		t.Error("source order changed the composed tree digest")
	}
}

// Equal bytes do not rescue a collision. Ownership would still be ambiguous,
// and every final path has exactly one owner (DP-011).
func TestComposeRejectsCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sources []Source
	}{
		{
			"same path from two sources",
			[]Source{
				{Name: "first", Snapshot: newFakeSnapshot(map[string]string{"shared.yaml": "same"})},
				{Name: "second", Snapshot: newFakeSnapshot(map[string]string{"shared.yaml": "same"})},
			},
		},
		{
			"mount paths collide",
			[]Source{
				{Name: "first", MountPath: "app", Snapshot: newFakeSnapshot(map[string]string{"a.yaml": "1"})},
				{Name: "second", MountPath: "app", Snapshot: newFakeSnapshot(map[string]string{"a.yaml": "2"})},
			},
		},
		{
			"case-only difference",
			[]Source{
				{Name: "first", Snapshot: newFakeSnapshot(map[string]string{"README.md": "1"})},
				{Name: "second", Snapshot: newFakeSnapshot(map[string]string{"readme.md": "2"})},
			},
		},
		{
			"a file where another source needs a directory",
			[]Source{
				{Name: "first", Snapshot: newFakeSnapshot(map[string]string{"app": "1"})},
				{Name: "second", MountPath: "app", Snapshot: newFakeSnapshot(map[string]string{"x.yaml": "2"})},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compose(tc.sources, bundle.Limits{})
			if !stderrors.Is(err, fault.CodePathCollision) {
				t.Fatalf("code = %q, want %q (%v)", fault.CodeOf(err), fault.CodePathCollision, err)
			}
			// The message must name a source; "something collided" cannot be
			// acted on.
			if !strings.Contains(err.Error(), "first") && !strings.Contains(err.Error(), "second") {
				t.Errorf("the error names neither source: %v", err)
			}
		})
	}
}

// A source that contributes nothing is almost always a filter that did not
// match what its author expected, and silently shipping a smaller bundle is
// the worst available outcome.
func TestComposeRejectsEmptySource(t *testing.T) {
	t.Parallel()

	_, err := Compose([]Source{
		{Name: "present", Snapshot: newFakeSnapshot(map[string]string{"a": "1"})},
		{Name: "empty", Snapshot: newFakeSnapshot(nil)},
	}, bundle.Limits{})

	if !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("the error does not name the empty source: %v", err)
	}
}

func TestComposeRejectsNoSources(t *testing.T) {
	t.Parallel()

	if _, err := Compose(nil, bundle.Limits{}); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestComposeRejectsEscapingMountPath(t *testing.T) {
	t.Parallel()

	_, err := Compose([]Source{
		{Name: "escaping", MountPath: "../outside", Snapshot: newFakeSnapshot(map[string]string{"a": "1"})},
	}, bundle.Limits{})

	if !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

// A mount can push a path past a limit that neither part crossed on its own,
// so the joined result is re-validated rather than concatenated.
func TestComposeRevalidatesMountedPaths(t *testing.T) {
	t.Parallel()

	_, err := Compose([]Source{
		{
			Name:      "deep",
			MountPath: strings.TrimSuffix(strings.Repeat("d/", 40), "/"),
			Snapshot:  newFakeSnapshot(map[string]string{strings.Repeat("s/", 40) + "f": "1"}),
		},
	}, bundle.Limits{MaxPathDepth: 64})

	if !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
	}
}

func TestComposeEnforcesLimits(t *testing.T) {
	t.Parallel()

	sources := []Source{
		{Name: "big", Snapshot: newFakeSnapshot(map[string]string{
			"a": "aaaa", "b": "bbbb", "c": "cccc",
		})},
	}

	if _, err := Compose(sources, bundle.Limits{MaxFiles: 2}); !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("file count: code = %q", fault.CodeOf(err))
	}
	if _, err := Compose(sources, bundle.Limits{MaxExpandedBytes: 6}); !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("total size: code = %q", fault.CodeOf(err))
	}
}

// Composition routes content through the owning snapshot rather than copying
// it, and refuses a path it did not produce.
func TestResultOpenRoutesToTheOwningSource(t *testing.T) {
	t.Parallel()

	result, err := Compose([]Source{
		{Name: "application", MountPath: "app", Snapshot: newFakeSnapshot(map[string]string{
			"config/service.yaml": "a: 1\n",
		})},
	}, bundle.Limits{})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	reader, err := result.Open(t.Context(), "app/config/service.yaml")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if string(content) != "a: 1\n" {
		t.Errorf("read %q", content)
	}

	// The source-relative path is not a composed path and must not open.
	if _, err := result.Open(t.Context(), "config/service.yaml"); err == nil {
		t.Error("an uncomposed path was opened")
	}
	if _, err := result.Open(t.Context(), "absent"); err == nil {
		t.Error("an unknown path was opened")
	}
}
