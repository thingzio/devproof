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

// Package tamperandtrust_test runs the walkthrough in README.md.
//
// The demo makes claims about tamper detection and gating that were not true
// of this code a week ago, and a reader has no way to tell a demonstration
// from a description. Extracting the commands out of the document and running
// them is what keeps the two the same thing.
package tamperandtrust_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bashBlock matches a fenced bash block, which is what the document uses for
// commands a reader is meant to run. console blocks hold expected output and
// are deliberately not executed.
var bashBlock = regexp.MustCompile("(?s)```bash\n(.*?)```")

// buildCLI compiles devproof into a directory and returns that directory.
func buildCLI(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "devproof"),
		"github.com/thingzio/devproof/cmd/devproof")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}
	return dir
}

// TestDemoRuns executes every command in README.md and checks the outcomes it
// claims.
//
// Outcomes rather than output: text rendering is explicitly not a contract
// (docs/compatibility.md), so asserting on wording would break for reasons the
// reader would not care about. What must stay true is that the tampered bundle
// fails, the untouched one passes, the round trip preserves the digest, and
// the refused expansion left nothing behind.
func TestDemoRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI and shells out")
	}
	for _, tool := range []string{"bash", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available: %v", tool, err)
		}
	}

	doc, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading the demo: %v", err)
	}
	blocks := bashBlock.FindAllStringSubmatch(string(doc), -1)
	if len(blocks) < 8 {
		t.Fatalf("found %d command blocks; the demo should have at least 8. "+
			"Has the document been restructured?", len(blocks))
	}

	// One shell for every block, so `cd` and the layer_of helper carry across
	// exactly as they do for a reader pasting them in order.
	//
	// No `set -e`: two of the commands are supposed to fail, and that is the
	// point of the steps they belong to.
	var script strings.Builder
	for _, block := range blocks {
		script.WriteString(block[1])
		script.WriteString("\n")
	}

	binDir := buildCLI(t)
	workdir := t.TempDir()
	cmd := exec.Command("bash", "-c", script.String())
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the demo script failed: %v\n%s", err, out)
	}
	t.Logf("demo output:\n%s", out)

	demo := filepath.Join(workdir, "devproof-demo")
	devproof := filepath.Join(binDir, "devproof")

	verify := func(reference string) error {
		check := exec.Command(devproof, "verify", reference)
		check.Dir = demo
		return check.Run()
	}

	// Step 5: the altered copy must fail and the untouched one must pass.
	// Both carry the same subject digest and the same tag, so this is the
	// assertion that the name alone was never the guarantee.
	if err := verify("oci-layout://./bundle:v1"); err == nil {
		t.Error("the tampered bundle verified; step 5 of the demo is not true")
	}
	if err := verify("oci-layout://./bundle-again:v1"); err != nil {
		t.Errorf("the untouched bundle failed to verify: %v", err)
	}

	// Step 4: a refused expansion publishes no destination at all.
	if _, err := os.Stat(filepath.Join(demo, "gated")); !os.IsNotExist(err) {
		t.Error("the refused expansion left a destination behind; " +
			"step 4 of the demo is not true")
	}

	// Steps 1 and 3: three independent builds of the same content, one of them
	// from an expanded copy, must all carry one digest.
	first := subjectDigest(t, devproof, demo, "oci-layout://./bundle-again:v1")
	rebuilt := subjectDigest(t, devproof, demo, "oci-layout://./rebuilt:v1")
	if first != rebuilt {
		t.Errorf("a round trip changed the digest: %s then %s", first, rebuilt)
	}
	if first == "" {
		t.Error("no subject digest was reported")
	}
}

// subjectDigest reads one subject's digest through the CLI.
func subjectDigest(t *testing.T, devproof, dir, reference string) string {
	t.Helper()

	cmd := exec.Command(devproof, "inspect", reference, "--format", "json")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("inspecting %s: %v", reference, err)
	}

	// Parsed with a regexp rather than the SDK's own types: this test stands
	// where a reader stands, reading the documented JSON surface, so it fails
	// if that surface changes shape.
	match := regexp.MustCompile(`"digest":"(sha256:[0-9a-f]{64})"`).FindSubmatch(out)
	if match == nil {
		t.Fatalf("no subject digest in inspect output: %s", out)
	}
	return string(match[1])
}
