package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/internal/fault"
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
type dockerCredentials struct {
	printer *Printer

	once   sync.Once
	config dockerConfig
	// loadErr is recorded rather than returned at construction: a missing or
	// malformed Docker config must not stop an anonymous pull from a public
	// registry, which is the common case.
	loadErr error

	mu     sync.Mutex
	cached map[string]artifact.Credential
}

// newDockerCredentials returns a provider backed by the Docker config.
func newDockerCredentials(printer *Printer) *dockerCredentials {
	return &dockerCredentials{printer: printer, cached: make(map[string]artifact.Credential)}
}

// configPath returns the Docker config location.
func dockerConfigPath() (string, error) {
	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".docker", "config.json"), nil
}

func (d *dockerCredentials) load() {
	path, err := dockerConfigPath()
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
func (d *dockerCredentials) Credential(ctx context.Context, registry string) (artifact.Credential, error) {
	d.once.Do(d.load)
	if d.loadErr != nil {
		// Reported once, as a warning: an unreadable config means the pull
		// proceeds anonymously, and silently getting a 401 later would send
		// the operator looking in the wrong place.
		d.printer.Warn("ignoring the Docker configuration: %v", d.loadErr)
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

func (d *dockerCredentials) resolve(ctx context.Context, registry string) (artifact.Credential, error) {
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
func (d *dockerCredentials) fromHelper(ctx context.Context, helper, registry string) (artifact.Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()

	name := "docker-credential-" + helper
	path, err := exec.LookPath(name)
	if err != nil {
		// Configured but absent is worth saying out loud: the operator
		// believes they are authenticated, and the request is about to fail
		// as anonymous for a reason that is not otherwise visible.
		d.printer.Warn("credential helper %q is configured for %s but was not found in PATH", name, registry)
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
