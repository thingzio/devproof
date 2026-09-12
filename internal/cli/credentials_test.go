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

package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// withDockerConfig points DOCKER_CONFIG at a directory holding the given
// config.json body.
func withDockerConfig(t *testing.T, body string) {
	t.Helper()

	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
			t.Fatalf("writing docker config: %v", err)
		}
	}
	t.Setenv("DOCKER_CONFIG", dir)
}

// newTestProvider returns a provider writing diagnostics to a buffer.
func newTestProvider(t *testing.T) (*dockerCredentials, *bytes.Buffer) {
	t.Helper()

	var stderr bytes.Buffer
	printer := &Printer{Streams: Streams{Out: &bytes.Buffer{}, Err: &stderr}, Format: FormatText}
	return newDockerCredentials(printer), &stderr
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func TestCredentialFromAuthField(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"registry.example.com":{"auth":%q}}}`, basicAuth("alice", "s3cret")))

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "alice" || cred.Password != "s3cret" {
		t.Errorf("got %+v, want alice/s3cret", cred)
	}
}

// A password containing a colon must survive: the auth field splits on the
// first colon only, and splitting on the last would corrupt the secret.
func TestCredentialPasswordMayContainColon(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"registry.example.com":{"auth":%q}}}`, basicAuth("bob", "a:b:c")))

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "bob" || cred.Password != "a:b:c" {
		t.Errorf("got %+v, want bob and the full password", cred)
	}
}

// An identity token supersedes a stored password, which may be a stale
// single-use secret.
func TestIdentityTokenSupersedesPassword(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"registry.example.com":{"auth":%q,"identitytoken":"tok"}}}`,
		basicAuth("alice", "s3cret")))

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Token != "tok" || cred.Password != "" {
		t.Errorf("got %+v, want the identity token and no password", cred)
	}
}

// `docker login` writes keys with a scheme and sometimes a path. A credential
// that cannot be found is a credential that is not sent.
func TestCredentialKeyIsMatchedByHost(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"https://registry.example.com/v2/":{"auth":%q}}}`, basicAuth("alice", "s3cret")))

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "alice" {
		t.Errorf("a credential written with a scheme and path was not found: %+v", cred)
	}
}

func TestDockerHubLegacyKey(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"https://index.docker.io/v1/":{"auth":%q}}}`, basicAuth("alice", "s3cret")))

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry-1.docker.io")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "alice" {
		t.Errorf("the Docker Hub credential was not found: %+v", cred)
	}
}

// DP-013: a credential issued for one registry is never sent to another.
func TestCredentialsAreScopedToTheirHost(t *testing.T) {
	withDockerConfig(t, fmt.Sprintf(
		`{"auths":{"registry.example.com":{"auth":%q}}}`, basicAuth("alice", "s3cret")))

	provider, _ := newTestProvider(t)
	for _, host := range []string{
		"attacker.example.com",
		"registry.example.com.attacker.net",
		"notregistry.example.com",
		"registry.example.co",
	} {
		cred, err := provider.Credential(context.Background(), host)
		if err != nil {
			t.Fatalf("Credential(%s): %v", host, err)
		}
		if !cred.IsZero() {
			t.Errorf("a credential for registry.example.com was offered to %s: %+v", host, cred)
		}
	}
}

// No configuration means anonymous access, not an error: a public pull must
// work on a machine that has never run `docker login`.
func TestMissingDockerConfigIsAnonymous(t *testing.T) {
	withDockerConfig(t, "")

	provider, stderr := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !cred.IsZero() {
		t.Errorf("got %+v, want anonymous", cred)
	}
	if stderr.Len() != 0 {
		t.Errorf("an absent config produced a diagnostic: %q", stderr.String())
	}
}

// A malformed configuration warns and falls back to anonymous rather than
// failing: the alternative is that one broken file blocks every public pull.
func TestMalformedDockerConfigWarns(t *testing.T) {
	withDockerConfig(t, "{not json")

	provider, stderr := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !cred.IsZero() {
		t.Errorf("got %+v, want anonymous", cred)
	}
	if stderr.Len() == 0 {
		t.Error("a malformed config produced no warning")
	}
}

// fakeHelper installs a docker-credential-<name> script on PATH and returns a
// path that records how many times it ran.
func fakeHelper(t *testing.T, name, script string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the helper protocol test uses a shell script")
	}

	dir := t.TempDir()
	counter := filepath.Join(dir, "calls")
	path := filepath.Join(dir, "docker-credential-"+name)
	body := "#!/bin/sh\nprintf x >> " + counter + "\n" + script + "\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatalf("writing helper: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return counter
}

func helperCalls(t *testing.T, counter string) int {
	t.Helper()

	data, err := os.ReadFile(counter)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("reading the call counter: %v", err)
	}
	return len(data)
}

func TestCredentialFromHelper(t *testing.T) {
	fakeHelper(t, "test", `echo '{"Username":"bob","Secret":"hunter2"}'`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "bob" || cred.Password != "hunter2" {
		t.Errorf("got %+v, want bob/hunter2", cred)
	}
}

// The protocol signals a token credential with this sentinel username, which
// must not be sent as a literal username.
func TestHelperTokenSentinel(t *testing.T) {
	fakeHelper(t, "test", `echo '{"Username":"<token>","Secret":"tok"}'`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Token != "tok" || cred.Username != "" {
		t.Errorf("got %+v, want a bare token", cred)
	}
}

// A per-registry helper wins over the global store.
func TestCredHelperBeatsCredsStore(t *testing.T) {
	fakeHelper(t, "specific", `echo '{"Username":"specific","Secret":"s"}'`)
	fakeHelper(t, "global", `echo '{"Username":"global","Secret":"g"}'`)
	withDockerConfig(t,
		`{"credsStore":"global","credHelpers":{"registry.example.com":"specific"}}`)

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if cred.Username != "specific" {
		t.Errorf("got %+v, want the per-registry helper", cred)
	}
}

// "credentials not found" is the protocol's way of saying nothing is stored,
// which is an answer rather than a failure.
func TestHelperNotFoundIsAnonymous(t *testing.T) {
	fakeHelper(t, "test", `echo "credentials not found in native keychain" >&2; exit 1`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("a missing credential was reported as an error: %v", err)
	}
	if !cred.IsZero() {
		t.Errorf("got %+v, want anonymous", cred)
	}
}

// Any other helper failure is real: silently proceeding anonymously would
// turn an authentication problem into a confusing 404.
func TestHelperFailureIsAnError(t *testing.T) {
	fakeHelper(t, "test", `echo "the keychain is locked" >&2; exit 1`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	if _, err := provider.Credential(context.Background(), "registry.example.com"); err == nil {
		t.Fatal("a failing credential helper was ignored")
	}
}

// A helper that is configured but absent warns rather than failing, because
// the request can still legitimately succeed anonymously.
func TestMissingHelperWarns(t *testing.T) {
	withDockerConfig(t, `{"credsStore":"definitely-not-installed"}`)

	provider, stderr := newTestProvider(t)
	cred, err := provider.Credential(context.Background(), "registry.example.com")
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !cred.IsZero() {
		t.Errorf("got %+v, want anonymous", cred)
	}
	if stderr.Len() == 0 {
		t.Error("a missing helper produced no warning")
	}
}

// Helpers shell out, so a push touching one registry many times must not run
// the helper many times.
func TestHelperResultIsCached(t *testing.T) {
	counter := fakeHelper(t, "test", `echo '{"Username":"bob","Secret":"hunter2"}'`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	for range 5 {
		if _, err := provider.Credential(context.Background(), "registry.example.com"); err != nil {
			t.Fatalf("Credential: %v", err)
		}
	}
	if calls := helperCalls(t, counter); calls != 1 {
		t.Errorf("the helper ran %d times, want 1", calls)
	}
}

// Distinct hosts are distinct lookups: caching must not collapse them, which
// would send one registry's credential to another.
func TestCacheIsPerHost(t *testing.T) {
	counter := fakeHelper(t, "test", `read host; echo "{\"Username\":\"$host\",\"Secret\":\"s\"}"`)
	withDockerConfig(t, `{"credsStore":"test"}`)

	provider, _ := newTestProvider(t)
	for _, host := range []string{"a.example.com", "b.example.com"} {
		cred, err := provider.Credential(context.Background(), host)
		if err != nil {
			t.Fatalf("Credential(%s): %v", host, err)
		}
		if cred.Username != host {
			t.Errorf("host %s got the credential for %s", host, cred.Username)
		}
	}
	if calls := helperCalls(t, counter); calls != 2 {
		t.Errorf("the helper ran %d times, want 2", calls)
	}
}
