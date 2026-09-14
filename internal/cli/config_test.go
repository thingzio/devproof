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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/cli"
	"github.com/thingzio/devproof/pkg/fault"
)

// writeConfig writes a configuration file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "devproof.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestConfigFileSuppliesDefaults(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "format: json\n")
	got := run(t, "--config", config, "version")

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(got.stdout), "{") {
		t.Errorf("the configured format was not applied: %q", got.stdout)
	}
}

// Precedence: a flag beats the file. The reverse would make a one-off
// override impossible.
func TestFlagBeatsConfigFile(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "format: json\n")
	got := run(t, "--config", config, "--format", "text", "version")

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if strings.HasPrefix(strings.TrimSpace(got.stdout), "{") {
		t.Error("the configuration file overrode an explicit --format flag")
	}
}

// Precedence: an environment variable also beats the file, and is itself
// beaten by a flag.
func TestEnvironmentBeatsConfigFile(t *testing.T) {
	config := writeConfig(t, "format: text\n")
	t.Setenv("DEVPROOF_FORMAT", "json")

	got := run(t, "--config", config, "version")
	if !strings.HasPrefix(strings.TrimSpace(got.stdout), "{") {
		t.Errorf("the environment did not override the file: %q", got.stdout)
	}

	override := run(t, "--config", config, "--format", "text", "version")
	if strings.HasPrefix(strings.TrimSpace(override.stdout), "{") {
		t.Error("the environment overrode an explicit flag")
	}
}

// An explicitly named file that is absent is an error: the operator said to
// use it, and silently proceeding without it applies settings they believe
// are in force.
func TestMissingExplicitConfigIsAnError(t *testing.T) {
	t.Parallel()

	got := run(t, "--config", filepath.Join(t.TempDir(), "absent.yaml"), "version")

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitUsage)
	}
}

// A misspelled key is a setting that silently would not apply, so it is
// rejected where it can be fixed.
func TestUnknownConfigKeyIsRejected(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "frmat: json\n")
	got := run(t, "--config", config, "version")

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d\nstderr: %s", got.code, fault.ExitUsage, got.stderr)
	}
}

func TestInvalidConfigFormatIsRejected(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "format: yaml\n")
	got := run(t, "--config", config, "version")

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d", got.code, fault.ExitUsage)
	}
}

// A configured policy applies when --policy is not given, which is how an
// operator makes verification strict by default.
func TestConfiguredPolicyApplies(t *testing.T) {
	t.Parallel()

	layout := filepath.Join(t.TempDir(), "layout")
	if got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout, "--tag", "v1"); got.code != 0 {
		t.Fatalf("fixture build failed: %s", got.stderr)
	}

	config := writeConfig(t, "policy: "+writeUnsatisfiablePolicy(t)+"\n")
	got := run(t, "--config", config, "verify", "oci-layout://"+layout+":v1")

	if got.code != fault.ExitPolicy {
		t.Errorf("exit = %d, want %d; the configured policy was not applied\nstderr: %s",
			got.code, fault.ExitPolicy, got.stderr)
	}
}

// The configuration file cannot name an artifact. A file that could change
// which artifact a command acted on would make the same command line mean
// different things on different machines.
func TestConfigCannotNameAnArtifact(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"reference", "destination", "tag", "to", "source"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			config := writeConfig(t, key+": something\n")
			if got := run(t, "--config", config, "version"); got.code != fault.ExitUsage {
				t.Errorf("configuration accepted %q, which names an artifact", key)
			}
		})
	}
}

// A configured timeout that is not a duration fails where it can be fixed.
func TestInvalidConfiguredTimeoutIsRejected(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "timeout: soon\n")
	got := run(t, "--config", config, "verify", "oci-layout://"+t.TempDir())

	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d\nstderr: %s", got.code, fault.ExitUsage, got.stderr)
	}
}

// Reading the configuration must not write to stdout, whatever it contains.
func TestConfigLoadingKeepsStdoutClean(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "verbose: true\n")
	layout := filepath.Join(t.TempDir(), "layout")

	var out, errOut bytes.Buffer
	code := cli.Run(context.Background(),
		[]string{"devproof", "--config", config, "--quiet", "build", sourceTree(t),
			"--to", "oci-layout://" + layout},
		cli.Streams{Out: &out, Err: &errOut})

	if code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	if lines := strings.Count(strings.TrimSpace(out.String()), "\n"); lines != 0 {
		t.Errorf("verbose configuration leaked into stdout:\n%s", out.String())
	}
}

// --debug prints the effective settings and their source, on stderr. A
// precedence question is the most common "why did it do that", and answering
// it by reasoning about three layers is what nobody gets right under pressure.
func TestDebugReportsSettingSources(t *testing.T) {
	config := writeConfig(t, "timeout: 5m\nformat: json\n")
	t.Setenv("DEVPROOF_FORMAT", "text")

	got := run(t, "--config", config, "--debug", "version")

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	for _, want := range []string{
		"config file: " + config,
		// The file supplied the timeout and the environment overrode the
		// format, so the report must attribute each to a different layer.
		"timeout: 5m0s (config)",
		"format: text (flag or DEVPROOF_FORMAT)",
	} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("the debug report is missing %q:\n%s", want, got.stderr)
		}
	}
}

// The settings report is a diagnostic, so it goes to stderr like every other
// diagnostic. On stdout it would corrupt a piped result.
func TestDebugReportNeverReachesStdout(t *testing.T) {
	t.Parallel()

	config := writeConfig(t, "timeout: 5m\n")
	layout := filepath.Join(t.TempDir(), "layout")

	got := run(t, "--config", config, "--debug", "--quiet", "build",
		sourceTree(t), "--to", "oci-layout://"+layout)

	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s", got.code, got.stderr)
	}
	if strings.Contains(got.stdout, "config file:") || strings.Contains(got.stdout, "timeout:") {
		t.Errorf("the debug report reached stdout:\n%s", got.stdout)
	}
	if lines := strings.Count(strings.TrimSpace(got.stdout), "\n"); lines != 0 {
		t.Errorf("quiet stdout has more than one line:\n%s", got.stdout)
	}
}

// A path to trust material is a setting; the material itself is not. Nothing
// in the report may be a secret.
func TestDebugReportOmitsSecrets(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "key.pem")
	secret := "-----BEGIN PRIVATE KEY-----\nNOTAREALKEY\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(secret), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	got := run(t, "--debug", "build", sourceTree(t),
		"--to", "oci-layout://"+filepath.Join(t.TempDir(), "layout"),
		"--sign", "--key", keyPath)

	for _, stream := range []string{got.stdout, got.stderr} {
		if strings.Contains(stream, "NOTAREALKEY") || strings.Contains(stream, "BEGIN PRIVATE KEY") {
			t.Errorf("key material was printed:\n%s", stream)
		}
	}
}

// TestBooleanFlagOverridesConfigFile covers a precedence rule the documented
// table promised and the code inverted.
//
// String settings resolved flag-first, but the booleans were OR'd with the
// configured value: `verbose: true` in a file could not be turned off by
// --verbose=false or by DEVPROOF_VERBOSE=false. A setting that cannot be
// overridden for one invocation is not a default, and the documented
// precedence said otherwise.
func TestBooleanFlagOverridesConfigFile(t *testing.T) {
	config := writeConfig(t, "debug: true\n")

	// The debug settings report is the observable effect of debug being on.
	const report = "config file:"

	if got := run(t, "--config", config, "version"); !strings.Contains(got.stderr, report) {
		t.Fatalf("the configured default did not apply: %q", got.stderr)
	}
	if got := run(t, "--config", config, "--debug=false", "version"); strings.Contains(got.stderr, report) {
		t.Errorf("--debug=false did not override the configuration file: %q", got.stderr)
	}

	t.Setenv("DEVPROOF_DEBUG", "false")
	if got := run(t, "--config", config, "version"); strings.Contains(got.stderr, report) {
		t.Errorf("DEVPROOF_DEBUG=false did not override the configuration file: %q", got.stderr)
	}
}

// TestNonPositiveTimeoutIsRejected covers the other half of the same promise.
//
// The documentation says a value of zero does not silently mean unbounded, and
// the code that applied it said so in a comment while returning a context with
// no deadline -- so --timeout 0 produced exactly the run that can hang a CI job
// forever. There is no spelling for unbounded, so the value is refused where
// somebody can fix it.
func TestNonPositiveTimeoutIsRejected(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"0s", "-5s"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			if got := run(t, "--timeout", value, "version"); got.code != fault.ExitUsage {
				t.Errorf("--timeout %s: exit = %d, want %d", value, got.code, fault.ExitUsage)
			}

			config := writeConfig(t, "timeout: "+value+"\n")
			if got := run(t, "--config", config, "version"); got.code != fault.ExitUsage {
				t.Errorf("configured timeout %s: exit = %d, want %d", value, got.code, fault.ExitUsage)
			}
		})
	}
}

// TestKeyAndTrustRootAreMutuallyExclusive covers trust configuration that was
// accepted and then discarded.
//
// --key and --trust-root select two different trust models: bare public keys,
// and a Sigstore trusted root for certificate-based identities. The key branch
// returned before the trust root was ever read, so supplying both silently
// verified against the keys alone. An operator who believed they had pinned a
// trust root had pinned nothing, and nothing said so.
//
// The two do not compose underneath either -- both install one verifier on the
// client, so applying both would replace rather than combine. Refusing the
// combination says that out loud instead of picking a winner.
func TestKeyAndTrustRootAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := filepath.Join(dir, "signer.pub.pem")
	if err := os.WriteFile(key, []byte("-----BEGIN PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}

	got := run(t, "verify", "oci-layout://"+dir, "--key", key, "--trust-root", key)
	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d: %s", got.code, fault.ExitUsage, got.stderr)
	}
	if !strings.Contains(got.stderr, "trust-root") {
		t.Errorf("the error does not name the ignored setting: %q", got.stderr)
	}
}
