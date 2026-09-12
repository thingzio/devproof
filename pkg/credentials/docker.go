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

// Package credentials resolves registry credentials from the environment a
// developer or a CI runner already has.
//
// It is public because the CLI must not be the only way to reach it. A program
// embedding the SDK that pushes to a registry the operator has already logged
// in to should not have to reimplement Docker configuration parsing,
// credential helpers, and host scoping to do what `devproof build` does with
// no configuration at all (DP-001).
package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/fault"
)

// dockerConfig is the subset of ~/.docker/config.json that matters here.
//
// Reading the Docker configuration rather than inventing a credential store
// means `docker login` already works, which is what every operator and CI
// runner has done. Decoding is lenient: this file is shared with other tools
// and gains fields that are none of our business, so an unknown one must not
// be an error.
type dockerConfig struct {
	Auths       map[string]dockerAuth `json:"auths"`
	CredsStore  string                `json:"credsStore"`
	CredHelpers map[string]string     `json:"credHelpers"`
}

type dockerAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Auth is base64("username:password"), which is where `docker login`
	// actually writes the credential.
	Auth string `json:"auth"`
	// IdentityToken is used by registries that exchange a login for a
	// refresh token; when set it supersedes the password.
	IdentityToken string `json:"identitytoken"`
}

// dockerCredentials resolves registry credentials from the Docker config.
//
// Lookups are cached for the process lifetime. Credential helpers shell out,
// and a push that touches one registry a few hundred times should not run a
// few hundred subprocesses.
type Docker struct {
	logger *slog.Logger
	// configPath overrides discovery. Empty uses DOCKER_CONFIG, then the
	// per-user default.
	configPath string

	once   sync.Once
	config dockerConfig
	// loadErr is recorded rather than returned at construction: a missing or
	// malformed Docker config must not stop an anonymous pull from a public
	// registry, which is the common case.
	loadErr error

	mu     sync.Mutex
	cached map[string]artifact.Credential
}

// DockerOptions configures a [Docker] provider.
type DockerOptions struct {
	// ConfigPath overrides the configuration location. Empty uses
	// DOCKER_CONFIG when set, then ~/.docker/config.json.
	ConfigPath string
	// Logger receives diagnostics: an unreadable configuration, a credential
	// helper named but not installed. Nil discards them, because a library
	// that printed to stderr on its own would be unusable inside a server.
	Logger *slog.Logger
}

// NewDocker returns a provider backed by the Docker configuration.
//
// Nothing is read until the first lookup, so constructing one is free and
// cannot fail.
func NewDocker(opts DockerOptions) *Docker {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Docker{
		logger:     logger,
		configPath: opts.ConfigPath,
		cached:     make(map[string]artifact.Credential),
	}
}

// configPath returns the Docker config location.
func (d *Docker) resolveConfigPath() (string, error) {
	if d.configPath != "" {
		return d.configPath, nil
	}
	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".docker", "config.json"), nil
}

func (d *Docker) load() {
	path, err := d.resolveConfigPath()
	if err != nil {
		d.loadErr = err
		return
	}

	data, err := os.ReadFile(path) //nolint:gosec // a well-known per-user path
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			d.loadErr = err
		}
		return
	}
	if err := json.Unmarshal(data, &d.config); err != nil {
		d.loadErr = fmt.Errorf("parsing %s: %w", path, err)
	}
}

// Credential implements [artifact.CredentialProvider].
//
// A registry with no entry gets anonymous access rather than an error: public
// registries exist, and failing here would make an unauthenticated pull
// impossible on a machine that has never run `docker login`.
func (d *Docker) Credential(ctx context.Context, registry string) (artifact.Credential, error) {
	d.once.Do(d.load)
	if d.loadErr != nil {
		// Reported once, as a warning: an unreadable config means the pull
		// proceeds anonymously, and silently getting a 401 later would send
		// the operator looking in the wrong place.
		d.logger.Warn("ignoring the Docker configuration", "error", d.loadErr)
		d.loadErr = nil
	}

	d.mu.Lock()
	if cred, ok := d.cached[registry]; ok {
		d.mu.Unlock()
		return cred, nil
	}
	d.mu.Unlock()

	cred, err := d.resolve(ctx, registry)
	if err != nil {
		return artifact.Credential{}, err
	}

	d.mu.Lock()
	d.cached[registry] = cred
	d.mu.Unlock()
	return cred, nil
}

func (d *Docker) resolve(ctx context.Context, registry string) (artifact.Credential, error) {
	// A per-registry helper wins over the global store, which is how a
	// machine with one cloud registry and one private registry is configured.
	if helper, ok := d.config.CredHelpers[registry]; ok {
		return d.fromHelper(ctx, helper, registry)
	}
	if entry, ok := lookupAuth(d.config.Auths, registry); ok {
		cred, err := entry.credential()
		if err != nil {
			return artifact.Credential{}, fault.Wrap(fault.CodeAuthentication, "cli",
				fmt.Sprintf("reading the stored credential for %s", registry), err)
		}
		// An entry with no usable secret means the credential lives in the
		// store; `docker login` writes both.
		if !cred.IsZero() {
			return cred, nil
		}
	}
	if d.config.CredsStore != "" {
		return d.fromHelper(ctx, d.config.CredsStore, registry)
	}
	return artifact.Credential{}, nil
}

// lookupAuth finds the entry for a registry.
//
// Docker keys Docker Hub credentials under a legacy URL, and other entries
// may carry a scheme or a trailing path. Comparing the host alone is what
// makes a credential written by `docker login` findable.
func lookupAuth(auths map[string]dockerAuth, registry string) (dockerAuth, bool) {
	if entry, ok := auths[registry]; ok {
		return entry, true
	}
	for key, entry := range auths {
		if authHost(key) == registry {
			return entry, true
		}
	}
	if registry == dockerHubRegistry {
		if entry, ok := auths[dockerHubLegacyKey]; ok {
			return entry, true
		}
	}
	return dockerAuth{}, false
}

const (
	dockerHubRegistry  = "registry-1.docker.io"
	dockerHubLegacyKey = "https://index.docker.io/v1/"
)

// authHost reduces a config key to its host.
func authHost(key string) string {
	if scheme := strings.Index(key, "://"); scheme >= 0 {
		key = key[scheme+3:]
	}
	if slash := strings.Index(key, "/"); slash >= 0 {
		key = key[:slash]
	}
	return key
}

// credential decodes one auths entry.
func (a dockerAuth) credential() (artifact.Credential, error) {
	username, password := a.Username, a.Password

	if a.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(a.Auth)
		if err != nil {
			return artifact.Credential{}, fmt.Errorf("decoding the auth field: %w", err)
		}
		user, pass, found := strings.Cut(string(decoded), ":")
		if !found {
			return artifact.Credential{}, errors.New("the auth field is not username:password")
		}
		username, password = user, pass
	}

	// An identity token supersedes the password: registries that issue one
	// expect it, and the stored password may be a stale single-use secret.
	if a.IdentityToken != "" {
		return artifact.Credential{Username: username, Token: a.IdentityToken}, nil
	}
	return artifact.Credential{Username: username, Password: password}, nil
}

// helperTimeout bounds a credential helper.
//
// Helpers reach the network — a cloud helper mints a short-lived token — and
// one that hangs would hang the whole command with no indication why.
const helperTimeout = 30 * time.Second

// helperOutput is the docker-credential-helper protocol response.
type helperOutput struct {
	Username string `json:"Username"`
	Secret   string `json:"Secret"`
}

// fromHelper runs a docker-credential-<name> binary.
func (d *Docker) fromHelper(ctx context.Context, helper, registry string) (artifact.Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	name := "docker-credential-" + helper
	path, err := exec.LookPath(name)
	if err != nil {
		// Configured but absent is worth saying out loud: the operator
		// believes they are authenticated, and the request is about to fail
		// as anonymous for a reason that is not otherwise visible.
		d.logger.Warn("credential helper is configured but not installed",
			"helper", name, "registry", registry)
		return artifact.Credential{}, nil
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "get")
	cmd.Stdin = strings.NewReader(registry)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		// The protocol's way of saying "nothing stored for this host", which
		// is an answer, not a failure.
		if strings.Contains(message, "credentials not found") {
			return artifact.Credential{}, nil
		}
		return artifact.Credential{}, fault.Wrap(fault.CodeAuthentication, "cli",
			fmt.Sprintf("credential helper %s failed for %s: %s", name, registry, message), err)
	}

	var out helperOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return artifact.Credential{}, fault.Wrap(fault.CodeAuthentication, "cli",
			fmt.Sprintf("credential helper %s returned unreadable output", name), err)
	}
	if out.Secret == "" {
		return artifact.Credential{}, nil
	}

	// The helper protocol signals a token-style credential with this
	// sentinel username, in which case the secret is an identity token.
	if out.Username == "<token>" {
		return artifact.Credential{Token: out.Secret}, nil
	}
	return artifact.Credential{Username: out.Username, Password: out.Secret}, nil
}
