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

// Package publishonce_test runs the walkthrough in README.md.
//
// The document claims that an artifact published from CI can be regenerated,
// bit for bit, by a stranger on a different operating system. That claim is
// worth exactly as much as the last time somebody ran it, which is why it is
// run rather than described.
package publishonce_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// publishedDigest is the artifact the document names.
//
// Duplicated here on purpose. The README is the thing a reader copies from, so
// a digest that drifted out of it would be wrong in the only place that
// matters; TestDocumentNamesThePublishedDigest asserts the two agree.
const publishedDigest = "sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6"

// reference is the published artifact, by digest.
const reference = "oci://ghcr.io/thingzio/devproof/example-baseline@" + publishedDigest

// networkEnv gates the walkthrough on an explicit opt-in.
//
// Every other example here runs offline. This one cannot: it reaches
// github.com to resolve the locked commit and ghcr.io to read the artifact and
// its evidence. A test that silently skipped would be indistinguishable from a
// test that passed, so the opt-in is named and the CI job that sets it is the
// thing that keeps the claim honest.
const networkEnv = "DEVPROOF_EXAMPLE_GHCR"

// bashBlock matches a fenced bash block, which is what the document uses for
// commands a reader runs here and now. console blocks hold expected output and
// are not executed. sh blocks are real commands that cannot run in this
// context -- the pipeline-gate fragment refers to a variable a reader supplies
// -- and the fence is what keeps them out of the script.
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

// TestDocumentNamesThePublishedDigest keeps the document and this test on one
// artifact.
//
// It needs no network, so it runs everywhere and fails fast: a README that
// names a digest nothing else in the repository knows about is the specific
// way this example would rot.
func TestDocumentNamesThePublishedDigest(t *testing.T) {
	doc, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading the walkthrough: %v", err)
	}
	if !strings.Contains(string(doc), publishedDigest) {
		t.Errorf("README.md does not name %s; the document and the test "+
			"disagree about which artifact this example is about", publishedDigest)
	}
}

// TestCommittedLockBuildsThePublishedDigest guards against drift in the lock.
//
// The walkthrough fetches the manifest and lock from main, which is what a
// reader does, but it means an edit to the committed lock would not be
// exercised by the walkthrough at all until it merged -- the fetch would keep
// returning the old one and the demo would keep passing. Building the lock in
// this directory is what catches that, in the pull request that changes it.
func TestCommittedLockBuildsThePublishedDigest(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI and resolves a git source")
	}
	if os.Getenv(networkEnv) == "" {
		t.Skipf("set %s=1 to run; this resolves a git source over the network", networkEnv)
	}

	binDir := buildCLI(t)
	out := filepath.Join(t.TempDir(), "layout")

	cmd := exec.Command(filepath.Join(binDir, "devproof"), "build",
		"-f", "devproof.yaml", "--lock", "devproof.lock.json",
		"--to", "oci-layout://"+out, "--tag", "v1", "--quiet")
	built, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building from the committed lock: %v\n%s", err, built)
	}
	if !strings.Contains(string(built), publishedDigest) {
		t.Errorf("the committed lock builds %s, but this example is about %s.\n"+
			"If the lock changed on purpose, republish and update the digest "+
			"in README.md and in this file.", strings.TrimSpace(string(built)), publishedDigest)
	}
}

// TestWalkthroughRuns executes every command in README.md and checks what it
// claims.
//
// Outcomes rather than output: text rendering is explicitly not a contract
// (docs/compatibility.md). What must stay true is that a rebuild reproduces
// the published digest, that the comparison against the published artifact
// reports no difference, that the policy naming the publisher is satisfied,
// and that a policy naming anyone else is not.
func TestWalkthroughRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI and shells out")
	}
	if os.Getenv(networkEnv) == "" {
		t.Skipf("set %s=1 to run; this reads github.com and ghcr.io", networkEnv)
	}
	for _, tool := range []string{"bash", "curl", "cosign"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available: %v", tool, err)
		}
	}

	doc, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading the walkthrough: %v", err)
	}
	blocks := bashBlock.FindAllStringSubmatch(string(doc), -1)
	if len(blocks) < 8 {
		t.Fatalf("found %d command blocks; the walkthrough should have at least 8. "+
			"Has the document been restructured?", len(blocks))
	}

	// One shell for every block, so `cd` and $base carry across exactly as they
	// do for a reader pasting them in order.
	//
	// No `set -e`: the wrong-identity verification in section 1 is supposed to
	// fail, and that is the point of the step it belongs to.
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
		t.Fatalf("the walkthrough script failed: %v\n%s", err, out)
	}
	t.Logf("walkthrough output:\n%s", out)

	demo := filepath.Join(workdir, "devproof-consumer")
	devproof := filepath.Join(binDir, "devproof")

	run := func(dir string, args ...string) error {
		c := exec.Command(devproof, args...)
		c.Dir = dir
		return c.Run()
	}

	// Section 2: the rebuild a reader performed must carry the published
	// digest. This is the claim the example exists for.
	if got := subjectDigest(t, devproof, demo, "oci-layout://./rebuilt:v1"); got != publishedDigest {
		t.Errorf("the rebuild produced %s, not the published %s; "+
			"section 2 of the walkthrough is not true", got, publishedDigest)
	}

	// Section 3: the published artifact and the local rebuild must be
	// identical. diff exits 0 for identical and 1 for different, so this is
	// the assertion and not merely a report.
	if err := run(demo, "diff", reference, "oci-layout://./rebuilt:v1"); err != nil {
		t.Errorf("the published artifact differs from the rebuild: %v", err)
	}

	// Section 1, three policies over one artifact, and each verdict is a
	// separate claim the document makes.
	//
	// The strict one must refuse: GHCR answers the referrers request with 404,
	// so this evidence was found under the fallback tag scheme, and a policy
	// that has not opted into that is required to say so. If this ever starts
	// passing, GHCR has begun serving referrers and the walkthrough's section 1
	// is describing a registry that no longer exists -- which is a documentation
	// bug, not a windfall, so it fails here rather than silently improving.
	if err := run(demo, "verify", reference, "--policy", "policy.yaml"); err == nil {
		t.Error("the strict policy accepted tag-fallback evidence; " +
			"either DP-028 regressed or GHCR now serves referrers and " +
			"section 1 of the walkthrough needs rewriting")
	}
	// The same policy with the fallback accepted must pass. This is the one
	// that proves the signature and the identity are actually good.
	if err := run(demo, "verify", reference, "--policy", "accept.yaml"); err != nil {
		t.Errorf("verification against the publisher's identity failed: %v", err)
	}
	// And naming anyone else must not. Without this the check above proves
	// only that some signature existed.
	if err := run(demo, "verify", reference, "--policy", "wrong.yaml"); err == nil {
		t.Error("a policy naming the wrong workflow was accepted; " +
			"section 1 of the walkthrough is not true")
	}

	// Section 5: the air-gapped copy verifies with the network refused, using
	// only the trust material that traveled with it. By digest, because
	// accept.yaml requires one.
	if err := run(demo, "verify", "oci-layout://./transfer@"+publishedDigest, "--offline",
		"--trust-root", "trusted_root.json", "--policy", "accept.yaml"); err != nil {
		t.Errorf("the air-gapped copy failed to verify offline: %v", err)
	}
}

// subjectDigest reads one subject's digest through the CLI.
func subjectDigest(t *testing.T, devproof, dir, ref string) string {
	t.Helper()

	cmd := exec.Command(devproof, "inspect", ref, "--format", "json")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("inspecting %s: %v", ref, err)
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
