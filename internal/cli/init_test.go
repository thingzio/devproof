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

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

// TestInitProducesAManifestLockAccepts is the whole point of the command: the
// file it writes must be usable without being edited first.
func TestInitProducesAManifestLockAccepts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := filepath.Join(dir, "content")
	if err := os.MkdirAll(content, 0o755); err != nil {
		t.Fatalf("creating source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(content, "a.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	manifest := filepath.Join(dir, bundle.DefaultSpecName)
	got := run(t, "init", "--src", content, "--to", manifest)
	if got.code != fault.ExitSuccess {
		t.Fatalf("init: exit %d: %s", got.code, got.stderr)
	}

	locked := run(t, "lock", "-f", manifest)
	if locked.code != fault.ExitSuccess {
		t.Fatalf("the manifest init wrote is not one lock accepts: %s", locked.stderr)
	}
}

// TestInitRecordsSourceRelativeToTheManifest covers the case where the two
// paths are given from different directories.
//
// A manifest resolves its source paths against itself, so recording the
// string the user typed would silently mean a different directory.
func TestInitRecordsSourceRelativeToTheManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	content := filepath.Join(dir, "content")
	for _, d := range []string{nested, content} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("creating %s: %v", d, err)
		}
	}

	manifest := filepath.Join(nested, bundle.DefaultSpecName)
	if got := run(t, "init", "--src", content, "--to", manifest); got.code != fault.ExitSuccess {
		t.Fatalf("init: %s", got.stderr)
	}

	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	spec, err := bundle.ParseSpec(data)
	if err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if got := spec.Spec.Sources[0].Config["path"]; got != "../content" {
		t.Errorf("recorded source path is %v, want ../content", got)
	}
}

// TestInitDefaultsToCurrentDirectory covers `devproof init` with no flags.
func TestInitDefaultsToCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if got := run(t, "init"); got.code != fault.ExitSuccess {
		t.Fatalf("init: %s", got.stderr)
	}

	data, err := os.ReadFile(bundle.DefaultSpecName)
	if err != nil {
		t.Fatalf("init wrote no %s: %v", bundle.DefaultSpecName, err)
	}
	spec, err := bundle.ParseSpec(data)
	if err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if got := spec.Spec.Sources[0].Config["path"]; got != "." {
		t.Errorf("recorded source path is %v, want .", got)
	}
}

// TestInitRefusesToOverwrite guards the one destructive thing this command
// could otherwise do.
func TestInitRefusesToOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifest := filepath.Join(dir, bundle.DefaultSpecName)
	const precious = "# hand-edited, do not lose\n"
	if err := os.WriteFile(manifest, []byte(precious), 0o644); err != nil {
		t.Fatalf("seeding manifest: %v", err)
	}

	got := run(t, "init", "--to", manifest)
	if got.code != fault.ExitArtifact {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitArtifact)
	}

	after, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	if string(after) != precious {
		t.Error("init overwrote an existing manifest")
	}
}

// TestInitWarnsAboutAMissingSource checks the scaffold is still written.
//
// Writing a manifest before creating the directory it points at is an
// ordinary order of operations, so this warns rather than failing.
func TestInitWarnsAboutAMissingSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifest := filepath.Join(dir, bundle.DefaultSpecName)

	got := run(t, "init", "--src", filepath.Join(dir, "not-created-yet"), "--to", manifest)
	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d, want success: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "does not exist") {
		t.Errorf("no warning about the missing source: %q", got.stderr)
	}
	if _, err := os.Stat(manifest); err != nil {
		t.Errorf("the manifest was not written: %v", err)
	}
}

// TestInitQuietPrintsOnlyThePath keeps the command pipeable.
func TestInitQuietPrintsOnlyThePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifest := filepath.Join(dir, bundle.DefaultSpecName)

	got := run(t, "--quiet", "init", "--src", dir, "--to", manifest)
	if got.code != fault.ExitSuccess {
		t.Fatalf("init: %s", got.stderr)
	}
	if strings.TrimSpace(got.stdout) != manifest {
		t.Errorf("quiet stdout = %q, want %q", got.stdout, manifest)
	}
}
