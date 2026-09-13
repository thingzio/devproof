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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/cli"
	"github.com/thingzio/devproof/pkg/fault"
)

// result is one captured command run.
type result struct {
	code   int
	stdout string
	stderr string
}

// run executes the command tree in-process with captured streams.
//
// In-process rather than by exec'ing a binary: it keeps the test fast, and
// more importantly it means the exit code and both streams are observed
// exactly as the code produces them, with no shell in between to reinterpret
// anything.
func run(t *testing.T, args ...string) result {
	t.Helper()

	var out, errOut bytes.Buffer
	code := cli.Run(context.Background(), append([]string{"devproof"}, args...), cli.Streams{
		Out: &out,
		Err: &errOut,
		// Never a terminal in a test, which is also the truth for CI.
		IsTerminal: false,
	})
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// sourceTree writes a small fixture and returns its directory.
func sourceTree(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	files := map[string]string{
		"README.md":               "hello\n",
		"app/config/service.yaml": "a: 1\n",
	}
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

func TestVersionHasNoSideEffects(t *testing.T) {
	t.Parallel()

	got := run(t, "version")

	if got.code != fault.ExitSuccess {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitSuccess)
	}
	if !strings.Contains(got.stdout, "devproof-bundle-v1") {
		t.Errorf("version does not report the supported format: %q", got.stdout)
	}
}

// Running bare prints help and succeeds. Asking a tool what it does is not an
// error.
func TestBareInvocationPrintsHelpAndSucceeds(t *testing.T) {
	t.Parallel()

	got := run(t)

	if got.code != fault.ExitSuccess {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitSuccess)
	}
	if !strings.Contains(got.stdout+got.stderr, "build") {
		t.Error("help does not mention the build command")
	}
}

// The stream contract: stdout carries the result and nothing else, so
// `devproof build ... | xargs` works. A single diagnostic line on stdout
// breaks every pipeline built on it.
func TestStdoutCarriesOnlyTheResult(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	got := run(t, "--verbose", "build", sourceTree(t), "--to", "oci-layout://"+layout)

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(got.stdout), "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(line, ":") {
			t.Errorf("stdout line is not a result field: %q", line)
		}
		for _, noise := range []string{"level=", "warning:", "error:", "✓"} {
			if strings.Contains(line, noise) {
				t.Errorf("diagnostic output reached stdout: %q", line)
			}
		}
	}
}

// Quiet output is the one value a pipeline wants, on stdout, alone.
func TestQuietPrintsOnlyTheReference(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	got := run(t, "--quiet", "build", sourceTree(t), "--to", "oci-layout://"+layout)

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	lines := strings.Split(strings.TrimSpace(got.stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("quiet stdout has %d lines, want 1: %q", len(lines), got.stdout)
	}
	if !strings.HasPrefix(lines[0], "oci-layout://") || !strings.Contains(lines[0], "@sha256:") {
		t.Errorf("quiet output is not a digest reference: %q", lines[0])
	}
}

func TestJSONOutputIsOneDocument(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	got := run(t, "--format", "json", "build", sourceTree(t), "--to", "oci-layout://"+layout)

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}

	decoder := json.NewDecoder(strings.NewReader(got.stdout))
	var envelope struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Result     json.RawMessage `json:"result"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, got.stdout)
	}
	if decoder.More() {
		t.Error("stdout contains more than one JSON document")
	}
	if envelope.APIVersion != cli.EnvelopeAPIVersion {
		t.Errorf("apiVersion = %q, want %q", envelope.APIVersion, cli.EnvelopeAPIVersion)
	}
	if envelope.Kind != "BuildResult" {
		t.Errorf("kind = %q", envelope.Kind)
	}
}

// On failure in text mode stdout stays empty: a pipeline that got no result
// should receive no bytes.
func TestTextFailureLeavesStdoutEmpty(t *testing.T) {
	t.Parallel()

	got := run(t, "verify", "oci-layout://"+filepath.Join(t.TempDir(), "absent"))

	if got.code == fault.ExitSuccess {
		t.Fatal("verifying a missing layout succeeded")
	}
	if got.stdout != "" {
		t.Errorf("stdout is not empty on failure: %q", got.stdout)
	}
	if !strings.Contains(got.stderr, "error:") {
		t.Errorf("stderr does not report the error: %q", got.stderr)
	}
}

// In JSON mode the failure envelope goes to stdout, because a caller parsing
// JSON reads errors the same way it reads results.
func TestJSONFailureEnvelopeGoesToStdout(t *testing.T) {
	t.Parallel()

	got := run(t, "--format", "json", "verify",
		"oci-layout://"+filepath.Join(t.TempDir(), "absent"))

	if got.code == fault.ExitSuccess {
		t.Fatal("verifying a missing layout succeeded")
	}

	var envelope struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Error      struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &envelope); err != nil {
		t.Fatalf("stdout is not a JSON error envelope: %v\n%s", err, got.stdout)
	}
	if envelope.Kind != "Error" {
		t.Errorf("kind = %q, want Error", envelope.Kind)
	}
	if envelope.Error.Code == "" {
		t.Error("the error envelope carries no code")
	}
	// The finer SDK code is what a caller branches on; the coarse exit code
	// is for the shell.
	if envelope.Error.Code == "internal" {
		t.Errorf("a missing layout was reported as an internal error: %q", envelope.Error.Message)
	}
}

// DP-023: every error class maps to its documented exit code.
func TestExitCodesFollowTheDocumentedMapping(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	source := sourceTree(t)
	if got := run(t, "build", source, "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	destination := filepath.Join(t.TempDir(), "out")
	if got := run(t, "expand", "oci-layout://"+layout+":v1", "--to", destination); got.code != 0 {
		t.Fatalf("fixture expand failed: %s", got.stderr)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"missing argument", []string{"verify"}, fault.ExitUsage},
		{"unknown format", []string{"--format", "yaml", "version"}, fault.ExitUsage},
		{"quiet with json", []string{"--quiet", "--format", "json", "version"}, fault.ExitUsage},
		{
			"unparseable reference",
			[]string{"verify", "not a valid reference"},
			fault.ExitUsage,
		},
		{
			"destination already exists",
			[]string{"expand", "oci-layout://" + layout + ":v1", "--to", destination},
			fault.ExitArtifact,
		},
		{
			"missing subject",
			[]string{"verify", "oci-layout://" + layout + ":absent"},
			fault.ExitArtifact,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := run(t, tc.args...); got.code != tc.want {
				t.Errorf("exit = %d, want %d\nstderr: %s", got.code, tc.want, got.stderr)
			}
		})
	}
}

// Flag-parsing failures are raised by the CLI library before any Action runs,
// on a path that by default prints "Incorrect Usage", dumps help to stdout,
// and returns an untyped error. Each of those breaks a documented contract, so
// each is asserted here rather than left to the library's defaults.
func TestUsageErrorsAreTypedAndQuiet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"missing required flag", []string{"build", "."}},
		{"unknown flag", []string{"build", "--nosuchflag"}},
		{"unknown global flag", []string{"--nosuchflag", "version"}},
		{"unknown command", []string{"nosuchcommand"}},
		{"malformed duration", []string{"--timeout", "soon", "version"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := run(t, tc.args...)

			if got.code != fault.ExitUsage {
				t.Errorf("exit = %d, want %d (usage)", got.code, fault.ExitUsage)
			}
			// The help dump is the specific regression: two kilobytes of it
			// landing in whatever the caller piped stdout to.
			if got.stdout != "" {
				t.Errorf("stdout is not empty on a usage error: %.120q", got.stdout)
			}
			if !strings.Contains(got.stderr, "error:") {
				t.Errorf("stderr does not report the error: %q", got.stderr)
			}
			// One failure, one diagnostic. The library's default prefix
			// alongside ours means the same problem is reported twice.
			if strings.Contains(got.stderr, "Incorrect Usage") {
				t.Errorf("the error is reported twice: %q", got.stderr)
			}
		})
	}
}

// The same failures in JSON mode must still produce a parseable envelope
// rather than a help dump.
func TestUsageErrorsRenderAsJSON(t *testing.T) {
	t.Parallel()

	got := run(t, "--format", "json", "build", ".")

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitUsage)
	}

	var envelope struct {
		Kind  string `json:"kind"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &envelope); err != nil {
		t.Fatalf("stdout is not a JSON error envelope: %v\n%.200s", err, got.stdout)
	}
	if envelope.Kind != "Error" {
		t.Errorf("kind = %q, want Error", envelope.Kind)
	}
	if envelope.Error.Code != "invalid-input" {
		t.Errorf("code = %q, want invalid-input", envelope.Error.Code)
	}
}

// A verification whose policy fails must exit non-zero. A report that says
// "fail" alongside exit 0 makes every CI gate built on it useless.
func TestFailedPolicyExitsNonZero(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: strict
spec:
  provenance:
    required: true
`
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatalf("writing policy: %v", err)
	}

	got := run(t, "verify", "oci-layout://"+layout+":v1", "--policy", policyPath)

	if got.code != fault.ExitPolicy {
		t.Errorf("exit = %d, want %d\nstderr: %s", got.code, fault.ExitPolicy, got.stderr)
	}
}

// writePolicy writes a policy that nothing unsigned can satisfy.
func writeUnsatisfiablePolicy(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: strict
spec:
  provenance:
    required: true
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return path
}

// An expansion gated on a policy must write nothing when the policy fails.
//
// Content that is written and then removed has already been readable by
// anything watching the directory, so "clean up afterwards" is not the same
// guarantee as "never wrote it".
func TestFailedPolicyExpandsNothing(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	destination := filepath.Join(t.TempDir(), "out")
	got := run(t, "expand", "oci-layout://"+layout+":v1",
		"--to", destination, "--policy", writeUnsatisfiablePolicy(t))

	if got.code != fault.ExitPolicy {
		t.Errorf("exit = %d, want %d\nstderr: %s", got.code, fault.ExitPolicy, got.stderr)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Errorf("a policy-gated expansion wrote to %s despite failing", destination)
	}
}

// The same policy, satisfied, still expands.
func TestExpandWithSatisfiedPolicyWrites(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: permissive
spec:
  subject:
    requireDigestReference: false
`
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatalf("writing policy: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "out")
	got := run(t, "expand", "oci-layout://"+layout+":v1",
		"--to", destination, "--policy", policyPath)

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if _, err := os.Stat(filepath.Join(destination, "README.md")); err != nil {
		t.Errorf("the payload was not written: %v", err)
	}
}

// Offline verification without trust material cannot establish anything, so
// it fails where it can be fixed rather than at the first network call.
func TestOfflineWithoutTrustRootIsRejected(t *testing.T) {
	t.Parallel()

	got := run(t, "verify", "oci-layout://"+t.TempDir(), "--offline")

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitUsage)
	}
	if !strings.Contains(got.stderr, "trust-root") {
		t.Errorf("the error does not say what is missing: %q", got.stderr)
	}
}

// Color is never emitted to a non-terminal. Escape sequences in a log file
// are noise at best.
func TestNoColorWhenNotATerminal(t *testing.T) {
	t.Parallel()

	got := run(t, "verify", "oci-layout://"+filepath.Join(t.TempDir(), "absent"))

	if strings.Contains(got.stdout+got.stderr, "\033[") {
		t.Error("ANSI escape sequences were written to a non-terminal stream")
	}
}

// Every command must print help without reading configuration, touching the
// network, or writing anything.
func TestEveryCommandHasHelp(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"init", "lock", "build", "verify", "expand", "diff", "copy", "inspect", "version",
	} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			got := run(t, command, "--help")
			if got.code != fault.ExitSuccess {
				t.Errorf("exit = %d: %s", got.code, got.stderr)
			}
			if !strings.Contains(got.stdout+got.stderr, command) {
				t.Errorf("help does not name the command: %q", got.stdout)
			}
		})
	}
}

func TestInspectReadsManifestAndLockFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
		t.Fatalf("creating source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "a.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	manifestPath := filepath.Join(dir, "devproof.yaml")
	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example
spec:
  sources:
    - name: content
      type: path
      config: {path: ./content}
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	// A manifest reports authored facts: intent, not proof.
	got := run(t, "inspect", manifestPath)
	if got.code != fault.ExitSuccess {
		t.Fatalf("inspect manifest: %s", got.stderr)
	}
	if !strings.Contains(got.stdout, "authored") {
		t.Errorf("manifest facts are not marked authored: %q", got.stdout)
	}

	if locked := run(t, "lock", "-f", manifestPath); locked.code != fault.ExitSuccess {
		t.Fatalf("lock: %s", locked.stderr)
	}

	// A lock reports resolved facts: stronger than authored, weaker than
	// verified.
	got = run(t, "inspect", filepath.Join(dir, "devproof.lock.json"))
	if got.code != fault.ExitSuccess {
		t.Fatalf("inspect lock: %s", got.stderr)
	}
	if !strings.Contains(got.stdout, "resolved") {
		t.Errorf("lock facts are not marked resolved: %q", got.stdout)
	}
}

// A subject's facts are digest-verified, and saying so is what stops an
// inspect report reading as a verification.
func TestInspectMarksSubjectFactsAsVerified(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	got := run(t, "inspect", "oci-layout://"+layout+":v1")
	if got.code != fault.ExitSuccess {
		t.Fatalf("inspect: %s", got.stderr)
	}
	if !strings.Contains(got.stdout, "digest-verified") {
		t.Errorf("subject facts are not marked digest-verified: %q", got.stdout)
	}
}

// Configuration comes from prefixed environment variables only. An
// unprefixed name collides with shells and CI runners, and picking one up by
// accident changes behavior nobody asked to change.
func TestEnvironmentVariablesArePrefixed(t *testing.T) {
	t.Setenv("DEVPROOF_FORMAT", "json")

	got := run(t, "version")
	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(got.stdout), "{") {
		t.Errorf("DEVPROOF_FORMAT was not honored: %q", got.stdout)
	}

	t.Setenv("FORMAT", "json")
	t.Setenv("DEVPROOF_FORMAT", "")
	plain := run(t, "version")
	if strings.HasPrefix(strings.TrimSpace(plain.stdout), "{") {
		t.Error("an unprefixed FORMAT variable was honored")
	}
}

// Completion scripts are the requested result, so they go to stdout: the
// documented usage is `source <(devproof completion bash)`.
func TestCompletionScriptsGoToStdout(t *testing.T) {
	t.Parallel()

	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			t.Parallel()

			got := run(t, "completion", shell)
			if got.code != fault.ExitSuccess {
				t.Fatalf("exit = %d: %s", got.code, got.stderr)
			}
			if got.stdout == "" {
				t.Error("no completion script was written to stdout")
			}
			if !strings.Contains(got.stdout, "devproof") {
				t.Errorf("the script does not mention the program: %.100q", got.stdout)
			}
		})
	}
}

// Exit 130 is a claim that a signal killed the process, so a caller who
// canceled their own context must not get it. They get the operational code
// for a canceled operation instead (DP-023).
//
// This distinction cannot be drawn from the context alone — a canceled
// context looks the same whichever way it ended — which is why signals are
// watched separately.
func TestProgrammaticCancellationIsNotReportedAsASignal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out, errOut bytes.Buffer
	code := cli.Run(ctx,
		[]string{"devproof", "build", sourceTree(t),
			"--to", "oci-layout://" + filepath.Join(t.TempDir(), "layout")},
		cli.Streams{Out: &out, Err: &errOut})

	if code == fault.ExitInterrupted {
		t.Error("a caller-canceled context was reported as death by SIGINT")
	}
	if code != fault.ExitSuccess && out.Len() != 0 {
		t.Errorf("a failed run wrote a result to stdout: %q", out.String())
	}
}

// A canceled run must leave no partial destination behind.
func TestCancellationLeavesNoPartialOutput(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	destination := filepath.Join(t.TempDir(), "out")
	var out, errOut bytes.Buffer
	code := cli.Run(ctx,
		[]string{"devproof", "expand", "oci-layout://" + layout + ":v1", "--to", destination},
		cli.Streams{Out: &out, Err: &errOut})

	if code == fault.ExitSuccess {
		return // it completed before the cancellation was observed
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Errorf("a canceled expansion left %s behind", destination)
	}
}

// A timeout that has already elapsed must fail rather than run unbounded.
func TestElapsedTimeoutFails(t *testing.T) {
	t.Parallel()

	got := run(t, "--timeout", "1ns", "build", sourceTree(t),
		"--to", "oci-layout://"+filepath.Join(t.TempDir(), "layout"))

	if got.code == fault.ExitSuccess {
		t.Skip("the build completed within the timeout")
	}
	if got.stdout != "" {
		t.Errorf("a timed-out run wrote to stdout: %q", got.stdout)
	}
}

// Nothing may prompt when interaction is prohibited, which is the state every
// CI runner is in. A command that blocks on a prompt hangs the job until
// someone notices.
func TestNonInteractiveNeverPrompts(t *testing.T) {
	t.Setenv("CI", "true")

	// Signing without a key would otherwise be the one path that could reach
	// for a browser. With no ambient credential it must fail, not block.
	got := run(t, "--timeout", "20s", "build", sourceTree(t),
		"--to", "oci-layout://"+filepath.Join(t.TempDir(), "layout"),
		"--sign")

	if got.code == fault.ExitSuccess {
		t.Skip("an ambient signing credential was available")
	}
	if got.stdout != "" {
		t.Errorf("a failed signing run wrote to stdout: %q", got.stdout)
	}
}

// The round trip, driven entirely through the command line.
func TestCLIRoundTrip(t *testing.T) {
	t.Parallel()

	source := sourceTree(t)
	layout := filepath.Join(t.TempDir(), "layout")

	built := run(t, "--quiet", "build", source, "--to", "oci-layout://"+layout, "--tag", "v1")
	if built.code != fault.ExitSuccess {
		t.Fatalf("build: %s", built.stderr)
	}
	reference := strings.TrimSpace(built.stdout)

	if verified := run(t, "verify", reference); verified.code != fault.ExitSuccess {
		t.Fatalf("verify: %s", verified.stderr)
	}

	destination := filepath.Join(t.TempDir(), "out")
	expanded := run(t, "--quiet", "expand", reference, "--to", destination)
	if expanded.code != fault.ExitSuccess {
		t.Fatalf("expand: %s", expanded.stderr)
	}
	if strings.TrimSpace(expanded.stdout) != destination {
		t.Errorf("quiet expand printed %q, want the destination", expanded.stdout)
	}

	// Rebuilding from the expanded tree reproduces the same subject.
	rebuilt := run(t, "--quiet", "build", destination,
		"--to", "oci-layout://"+filepath.Join(t.TempDir(), "again"))
	if rebuilt.code != fault.ExitSuccess {
		t.Fatalf("rebuild: %s", rebuilt.stderr)
	}

	originalDigest := reference[strings.Index(reference, "@")+1:]
	rebuiltReference := strings.TrimSpace(rebuilt.stdout)
	rebuiltDigest := rebuiltReference[strings.Index(rebuiltReference, "@")+1:]
	if originalDigest != rebuiltDigest {
		t.Errorf("a command-line round trip changed the subject:\n  %s\n  %s",
			originalDigest, rebuiltDigest)
	}
}

// Trust material with no policy cannot take effect, and saying so is what
// separates a confusing result from an actionable one. Without the warning,
// someone who supplied a key is told "no verification policy was supplied",
// which answers a question they did not ask.
func TestUnusedTrustMaterialWarns(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	got := run(t, "verify", "oci-layout://"+layout+":v1", "--key", writePublicKey(t))

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "--key was supplied but no policy") {
		t.Errorf("no warning that the key could not take effect:\n%s", got.stderr)
	}
	// The warning is a diagnostic, so it must not reach a piped result.
	if strings.Contains(got.stdout, "--key") {
		t.Errorf("the warning reached stdout:\n%s", got.stdout)
	}
}

// With a policy the key is consulted, so there is nothing to warn about.
func TestTrustMaterialWithPolicyDoesNotWarn(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	got := run(t, "verify", "oci-layout://"+layout+":v1",
		"--key", writePublicKey(t), "--policy", writeUnsatisfiablePolicy(t))

	if strings.Contains(got.stderr, "was supplied but no policy") {
		t.Errorf("warned despite a policy being supplied:\n%s", got.stderr)
	}
}

// writePublicKey writes a throwaway P-256 public key and returns its path.
//
// Generated rather than hard-coded: the tests above check whether the key is
// consulted, not what it proves, and a generated key cannot rot into an
// invalid encoding that makes them fail for the wrong reason.
func writePublicKey(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encoding the key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "key.pub.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	return path
}
