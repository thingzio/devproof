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
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

func snapshot(t *testing.T, dir string, opts SnapshotOptions) (*Snapshot, error) {
	t.Helper()

	if opts.TempRoot == "" {
		opts.TempRoot = t.TempDir()
	}
	s, err := SnapshotDir(t.Context(), dir, opts)
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

// Following a symlink would let a source tree pull in anything the build
// account can read. DP-005 excludes links so no consumer has to guess what
// one meant.
func TestSnapshotRejectsSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"real.txt": "content"})
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := snapshot(t, dir, SnapshotOptions{})
	if !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

// A symlink that points inside the tree is refused too. It resolves to real
// content, so following it would silently duplicate a file under two paths.
func TestSnapshotRejectsInternalSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"real.txt": "content"})
	if err := os.Symlink("real.txt", filepath.Join(dir, "alias.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := snapshot(t, dir, SnapshotOptions{}); !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

func TestSnapshotRejectsFIFO(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := mkfifo(filepath.Join(dir, "pipe")); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}

	if _, err := snapshot(t, dir, SnapshotOptions{}); !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

// The source root itself being a symlink is refused rather than followed, so
// what the manifest names is what was actually read.
func TestSnapshotRejectsSymlinkedSourceRoot(t *testing.T) {
	t.Parallel()

	target := t.TempDir()
	writeTree(t, target, sourceTree{"a.txt": "x"})

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := snapshot(t, link, SnapshotOptions{}); !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

func TestSnapshotRejectsNonDirectorySource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"a.txt": "x"})

	_, err := snapshot(t, filepath.Join(dir, "a.txt"), SnapshotOptions{})
	if !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestSnapshotRejectsMissingSource(t *testing.T) {
	t.Parallel()

	_, err := snapshot(t, filepath.Join(t.TempDir(), "absent"), SnapshotOptions{})
	if !stderrors.Is(err, fault.CodeSourceResolution) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeSourceResolution)
	}
}

// A path a source can produce but the portable profile cannot represent must
// fail at snapshot time, not at expansion time on someone else's machine.
func TestSnapshotRejectsUnportablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Legal on Linux and macOS, impossible on Windows.
	if err := os.WriteFile(filepath.Join(dir, "aux"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	if _, err := snapshot(t, dir, SnapshotOptions{}); !stderrors.Is(err, fault.CodeUnsafePath) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsafePath)
	}
}

func TestSnapshotLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tree   sourceTree
		limits bundle.Limits
	}{
		{
			"too many files",
			sourceTree{"a": "1", "b": "2", "c": "3"},
			bundle.Limits{MaxFiles: 2},
		},
		{
			"file too large",
			sourceTree{"big": "0123456789"},
			bundle.Limits{MaxFileBytes: 5},
		},
		{
			"total too large",
			sourceTree{"a": "01234", "b": "56789"},
			bundle.Limits{MaxExpandedBytes: 6},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeTree(t, dir, tc.tree)

			_, err := snapshot(t, dir, SnapshotOptions{Limits: tc.limits})
			if !stderrors.Is(err, fault.CodeLimitExceeded) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
			}
		})
	}
}

// Records must be sorted by canonical path regardless of how the filesystem
// enumerated them.
func TestSnapshotRecordsAreSorted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"z.txt": "1", "a.txt": "2", "m/n.txt": "3", "b/c.txt": "4"})

	s, err := snapshot(t, dir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("SnapshotDir: %v", err)
	}

	records := s.Records()
	for i := 1; i < len(records); i++ {
		if records[i-1].Path >= records[i].Path {
			t.Errorf("records are not sorted: %q then %q", records[i-1].Path, records[i].Path)
		}
	}
}

// Open must refuse anything outside the inventory, so there is no path
// through which packaging could reach a file the snapshot did not record.
func TestSnapshotOpenRefusesUnknownPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"a.txt": "content"})

	s, err := snapshot(t, dir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("SnapshotDir: %v", err)
	}

	if _, err := s.Open(t.Context(), "a.txt"); err != nil {
		t.Errorf("opening a recorded path failed: %v", err)
	}
	for _, p := range []string{"missing.txt", "../escape", "/etc/passwd"} {
		if _, err := s.Open(t.Context(), canonicalPath(p)); err == nil {
			t.Errorf("Open(%q) was allowed", p)
		}
	}
}

// Closing the snapshot must remove its private storage; leaving copies of
// source content in a temporary directory is a disclosure in itself.
func TestSnapshotCloseRemovesStorage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, sourceTree{"a.txt": "secret"})

	temp := t.TempDir()
	s, err := SnapshotDir(t.Context(), dir, SnapshotOptions{TempRoot: temp})
	if err != nil {
		t.Fatalf("SnapshotDir: %v", err)
	}
	path := s.ws.Path()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("workspace missing while open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("workspace survived Close: %v", err)
	}
	// Idempotent: a second Close after cleanup must not error.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// Workspaces are created owner-only so that a partially built tree is never
// readable by anyone else.
func TestWorkspaceIsPrivate(t *testing.T) {
	t.Parallel()

	ws, err := NewWorkspace(t.TempDir(), "devproof-test-")
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	defer func() { _ = ws.Close() }()

	info, err := os.Lstat(ws.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != privateDirMode {
		t.Errorf("mode = %#o, want %#o", info.Mode().Perm(), privateDirMode)
	}
}

// Names come from crypto/rand, not a counter: a predictable name in a shared
// temporary directory lets someone else create it first.
func TestWorkspaceNamesAreUnpredictable(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	seen := make(map[string]bool)

	for range 32 {
		ws, err := NewWorkspace(parent, "devproof-test-")
		if err != nil {
			t.Fatalf("NewWorkspace: %v", err)
		}
		if seen[ws.Path()] {
			t.Fatalf("workspace name %q was reused", ws.Path())
		}
		seen[ws.Path()] = true
		t.Cleanup(func() { _ = ws.Close() })
	}
}
