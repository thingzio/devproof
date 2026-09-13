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

// Package firmwarecatalog_test runs the walkthrough in README.md.
//
// The catalog is committed, and the extraction script is deliberately not run
// here: a test that reached docs.nvidia.com would fail for reasons that have
// nothing to do with this repository, and would make every CI run depend on a
// third party's uptime.
package firmwarecatalog_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var bashBlock = regexp.MustCompile("(?s)```bash\n(.*?)```")

// TestWalkthroughRuns executes the document and checks what it claims.
func TestWalkthroughRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI and shells out")
	}
	for _, tool := range []string{"bash", "python3", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available: %v", tool, err)
		}
	}

	doc, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading the walkthrough: %v", err)
	}

	var script strings.Builder
	var blocks int
	for _, block := range bashBlock.FindAllStringSubmatch(string(doc), -1) {
		body := block[1]
		switch {
		case strings.HasPrefix(strings.TrimSpace(body), "cd examples"):
			// The reader changes directory; the test already runs in a copy.
			continue
		case strings.Contains(body, "regenerate.py"):
			// Network, and a third party's page. Covered by --check, run by
			// hand when the snapshot is refreshed.
			continue
		}
		script.WriteString(body)
		script.WriteString("\n")
		blocks++
	}
	if blocks < 6 {
		t.Fatalf("found %d runnable blocks; the walkthrough should have at least 6", blocks)
	}

	binDir := buildCLI(t)
	work := t.TempDir()
	copyTree(t, "catalog", filepath.Join(work, "catalog"))

	cmd := exec.Command("bash", "-c", script.String())
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// The script's own exit status is not the verdict. Three of its commands
	// are supposed to fail -- the policy gate, the differing diff, and the
	// offline refusal -- and the last one is among them, so bash reports the
	// failure it was asked to demonstrate. The assertions below are what
	// decide, and a command that broke in the middle will surface there.
	out, _ := cmd.CombinedOutput()
	t.Logf("walkthrough output:\n%s", out)

	devproof := filepath.Join(binDir, "devproof")
	run := func(args ...string) (string, error) {
		cmd := exec.Command(devproof, args...)
		cmd.Dir = work
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	// Step 1 and 4: one component changed renames the whole stack. This is
	// the claim the example is built around, and it is the reason a catalog
	// is worth publishing as an artifact rather than as a page.
	original := subjectOf(t, run, "oci-layout://./stack:gb200-1.3.10")
	altered := subjectOf(t, run, "oci-layout://./altered:gb200-1.3.10")
	if original == altered {
		t.Error("altering a firmware version did not change the catalog's digest")
	}

	// Rebuilding the untouched catalog must reproduce the original digest,
	// or the difference above proves nothing about the edit.
	if _, err := run("build", "./catalog/gb200-nvl72-1.3.10",
		"--to", "oci-layout://./rebuilt", "--tag", "check", "--quiet"); err != nil {
		t.Fatalf("rebuilding: %v", err)
	}
	if rebuilt := subjectOf(t, run, "oci-layout://./rebuilt:check"); rebuilt != original {
		t.Errorf("rebuilding the catalog changed its digest: %s then %s", original, rebuilt)
	}

	// Step 2: the two rack generations differ, so diff reports it.
	if _, err := run("diff", "./catalog/gb200-nvl72-1.3.10",
		"./catalog/gb300-nvl72-1.0.10"); err == nil {
		t.Error("two different rack catalogs compared as identical")
	}

	// Step 3: the signed catalog satisfies the policy, by digest.
	signed := subjectOf(t, run, "oci-layout://./signed:gb200-1.3.10")
	output, err := run("verify", "oci-layout://./signed@"+signed,
		"--policy", "trust.yaml", "--key", "signer.pub.pem")
	if err != nil {
		t.Fatalf("verifying the signed catalog: %v\n%s", err, output)
	}
	if !strings.Contains(output, "trust:           pass") {
		t.Errorf("the signed catalog did not establish trust:\n%s", output)
	}
	// And the report says plainly that nothing judged the contents, which is
	// the claim the document is careful about.
	if !strings.Contains(output, "semantics:       not-evaluated") {
		t.Errorf("a passing result did not report semantics as not-evaluated:\n%s", output)
	}

	// The same policy must refuse the same artifact reached by tag. A tag can
	// be repointed after somebody decides to trust it, which is the whole
	// reason requireDigestReference exists.
	output, err = run("verify", "oci-layout://./signed:gb200-1.3.10",
		"--policy", "trust.yaml", "--key", "signer.pub.pem")
	if err == nil {
		t.Error("a policy requiring a digest reference accepted a tag")
	}
	if !strings.Contains(output, "digest reference") {
		t.Errorf("the refusal does not mention the digest requirement: %s", output)
	}

	// Step 5: offline refuses a network reference rather than attempting it.
	output, err = run("verify", "oci://registry.example.com/stacks/gb200:1.3.10",
		"--offline", "--trust-root", "signer.pub.pem")
	if err == nil {
		t.Error("an offline client accepted a registry reference")
	}
	if !strings.Contains(output, "offline") {
		t.Errorf("the refusal does not mention offline: %s", output)
	}
}

// subjectOf reads one subject digest through the CLI.
func subjectOf(t *testing.T, run func(...string) (string, error), reference string) string {
	t.Helper()

	out, err := run("inspect", reference, "--format", "json")
	if err != nil {
		t.Fatalf("inspecting %s: %v\n%s", reference, err, out)
	}
	match := regexp.MustCompile(`"digest":"(sha256:[0-9a-f]{64})"`).FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("no digest in inspect output: %s", out)
	}
	return match[1]
}

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

func copyTree(t *testing.T, from, to string) {
	t.Helper()

	if out, err := exec.Command("cp", "-R", from, to).CombinedOutput(); err != nil {
		t.Fatalf("copying %s: %v\n%s", from, err, out)
	}
}
