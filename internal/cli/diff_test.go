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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/fault"
)

// diffTree writes a directory with the given files and returns its path.
func diffTree(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", full, err)
		}
	}
	return dir
}

// TestDiffExitsZeroWhenIdentical and its sibling below are the contract a
// shell script depends on.
func TestDiffExitsZeroWhenIdentical(t *testing.T) {
	t.Parallel()

	files := map[string]string{"a.yaml": "a: 1\n"}
	got := run(t, "diff", diffTree(t, files), diffTree(t, files))

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d, want 0: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "identical") {
		t.Errorf("stdout does not report identical: %q", got.stdout)
	}
}

// TestDiffExitsOneWhenDifferent pins the one place DevProof uses exit 1.
//
// It is not a failure: the command answered the question, and the answer was
// no. Nothing is printed to stderr, because there is no error.
func TestDiffExitsOneWhenDifferent(t *testing.T) {
	t.Parallel()

	left := diffTree(t, map[string]string{"a.yaml": "a: 1\n"})
	right := diffTree(t, map[string]string{"a.yaml": "a: 2\n", "b.yaml": "b\n"})

	got := run(t, "diff", left, right)
	if got.code != fault.ExitDifferences {
		t.Fatalf("exit = %d, want %d: %s", got.code, fault.ExitDifferences, got.stderr)
	}
	if strings.Contains(got.stderr, "error") {
		t.Errorf("a difference was reported as an error: %q", got.stderr)
	}
	for _, want := range []string{"~ a.yaml", "+ b.yaml"} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout does not contain %q: %q", want, got.stdout)
		}
	}
}

// TestDiffQuietPrintsTheAnswer keeps the command usable in a pipeline that
// reads text rather than branching on status.
func TestDiffQuietPrintsTheAnswer(t *testing.T) {
	t.Parallel()

	files := map[string]string{"a.yaml": "a: 1\n"}
	same := run(t, "--quiet", "diff", diffTree(t, files), diffTree(t, files))
	if strings.TrimSpace(same.stdout) != "identical" {
		t.Errorf("quiet stdout = %q, want identical", same.stdout)
	}

	differ := run(t, "--quiet", "diff",
		diffTree(t, files), diffTree(t, map[string]string{"a.yaml": "a: 2\n"}))
	if strings.TrimSpace(differ.stdout) != "differ" {
		t.Errorf("quiet stdout = %q, want differ", differ.stdout)
	}
	if differ.code != fault.ExitDifferences {
		t.Errorf("exit = %d, want %d", differ.code, fault.ExitDifferences)
	}
}

// TestDiffQuietIfSamePrintsNothing covers the flag meant for CI, where a
// passing check should be silent.
func TestDiffQuietIfSamePrintsNothing(t *testing.T) {
	t.Parallel()

	files := map[string]string{"a.yaml": "a: 1\n"}
	got := run(t, "diff", "--quiet-if-same", diffTree(t, files), diffTree(t, files))

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d, want 0: %s", got.code, got.stderr)
	}
	if strings.TrimSpace(got.stdout) != "" {
		t.Errorf("stdout is not empty: %q", got.stdout)
	}
}

// TestDiffJSONReportsEveryChange checks the machine-readable shape.
func TestDiffJSONReportsEveryChange(t *testing.T) {
	t.Parallel()

	left := diffTree(t, map[string]string{"gone.txt": "x\n", "same.txt": "s\n"})
	right := diffTree(t, map[string]string{"new.txt": "y\n", "same.txt": "s\n"})

	got := run(t, "--format", "json", "diff", left, right)
	if got.code != fault.ExitDifferences {
		t.Fatalf("exit = %d, want %d: %s", got.code, fault.ExitDifferences, got.stderr)
	}

	var envelope struct {
		Result struct {
			Identical bool `json:"identical"`
			Added     int  `json:"added"`
			Removed   int  `json:"removed"`
			Changes   []struct {
				Path   string `json:"path"`
				Change string `json:"change"`
			} `json:"changes"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &envelope); err != nil {
		t.Fatalf("decoding JSON result: %v\n%s", err, got.stdout)
	}

	if envelope.Result.Identical {
		t.Error("JSON reports identical for differing trees")
	}
	if envelope.Result.Added != 1 || envelope.Result.Removed != 1 {
		t.Errorf("added=%d removed=%d, want 1 each",
			envelope.Result.Added, envelope.Result.Removed)
	}
	if len(envelope.Result.Changes) != 2 {
		t.Fatalf("got %d changes, want 2", len(envelope.Result.Changes))
	}
	// Sorted by path: gone.txt before new.txt.
	if envelope.Result.Changes[0].Path != "gone.txt" {
		t.Errorf("changes are not sorted by path: %v", envelope.Result.Changes)
	}
}

// TestDiffRequiresTwoOperands covers the usage contract.
func TestDiffRequiresTwoOperands(t *testing.T) {
	t.Parallel()

	dir := diffTree(t, map[string]string{"a.yaml": "a: 1\n"})
	for _, args := range [][]string{
		{"diff"},
		{"diff", dir},
		{"diff", dir, dir, dir},
	} {
		got := run(t, args...)
		if got.code != fault.ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, got.code, fault.ExitUsage)
		}
	}
}

// TestDiffReportsAnUnreadableOperand checks that a mistyped directory fails
// as a directory rather than being reinterpreted as a registry reference.
func TestDiffReportsAnUnreadableOperand(t *testing.T) {
	t.Parallel()

	dir := diffTree(t, map[string]string{"a.yaml": "a: 1\n"})
	got := run(t, "diff", dir, filepath.Join(t.TempDir(), "does-not-exist"))

	if got.code == fault.ExitSuccess || got.code == fault.ExitDifferences {
		t.Fatalf("a missing directory was not an error: exit %d", got.code)
	}
	if strings.Contains(got.stderr, "authenticat") || strings.Contains(got.stderr, "registry") {
		t.Errorf("a missing directory was reported as a registry problem: %q", got.stderr)
	}
}

// TestOfflineRefusesARemoteReference covers the flag end to end.
//
// --offline used to reach only a check that a trust root had been supplied;
// it was never passed to the SDK, so a remote reference fetched exactly as it
// would have without it. The failure here must be the refusal, not a network
// error that happens to look like one.
func TestOfflineRefusesARemoteReference(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(root, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("writing a trust root: %v", err)
	}

	got := run(t, "verify", "oci://registry.invalid/team/config:v1",
		"--offline", "--trust-root", root)

	if got.code == fault.ExitSuccess {
		t.Fatal("an offline verify of a remote reference succeeded")
	}
	if !strings.Contains(got.stderr, "offline") {
		t.Errorf("the failure does not mention offline, so it may be a network "+
			"error rather than a refusal: %q", got.stderr)
	}
}

// TestOfflineStillNeedsTrustMaterial keeps the older check working.
func TestOfflineStillNeedsTrustMaterial(t *testing.T) {
	t.Parallel()

	got := run(t, "verify", "oci-layout://"+t.TempDir()+":v1", "--offline")
	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitUsage)
	}
	if !strings.Contains(got.stderr, "--trust-root") {
		t.Errorf("the error does not say what is missing: %q", got.stderr)
	}
}
