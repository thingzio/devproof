# CLI design

## Command model

The executable is `devproof`. The CLI is human-readable by default and stable
for automation when `--format json` or `--quiet` is selected.

```text
devproof
  lock       resolve a manifest and write its immutable lock
  build      build and optionally publish a bundle
  verify     verify integrity, evidence, and policy
  expand     verify and materialize a bundle
  inspect    show subject, inventory, and evidence metadata
  version    show version and supported format versions
```

`diff` is a planned post-v1 command and is not part of the first implementation
contract.

Running `devproof` without arguments prints root help and exits successfully.
Every command supports `--help` without reading configuration, touching disk
beyond executable loading, or making a network request.

## Global flags

```text
--config PATH         CLI settings file
--format text|json    result rendering; default text
--quiet               print only the primary resulting digest or path
--verbose             include informational diagnostics on stderr
--debug               include sanitized debug diagnostics on stderr
--timeout DURATION    overall operation timeout
--no-color            disable color; NO_COLOR is also honored
--non-interactive     prohibit prompts or browser/device-flow interaction
```

`--quiet` and `--format json` are mutually exclusive unless a command defines
the JSON value as its quiet output. `--debug` never changes the data written to
stdout.

The default timeout is command-specific and printed by help. A value of zero
does not silently mean unbounded; unbounded behavior, if supported, requires an
explicit spelling.

## Configuration precedence

Highest priority wins:

```text
explicit flag > DEVPROOF_* environment variable > config file > built-in default
```

Manifest, lock, and verification-policy data are not CLI settings and are not
silently loaded from a user-global configuration file.

The settings file may contain registry aliases, credential-provider names,
timeouts, concurrency, limits, and output preferences. It may not contain raw
tokens or private keys. `--debug` prints effective non-secret settings and
their source.

## Streams

- stdout contains the requested result only;
- stderr contains progress, diagnostics, warnings, prompts, and errors;
- JSON mode writes exactly one JSON document followed by `\n` to stdout;
- progress UI is enabled only when stderr is a terminal;
- color is enabled only for a compatible terminal and is disabled by
  `NO_COLOR`, `TERM=dumb`, `--no-color`, JSON, or quiet mode.

Logging never corrupts a digest, path, or JSON result intended for a pipeline.

## `devproof lock`

```text
devproof lock [-f devproof.yaml] [--to devproof.lock.json]
devproof lock -f devproof.yaml --check [--lock devproof.lock.json]
```

Behavior:

- `-f/--file` defaults to `./devproof.yaml`.
- `--to` defaults beside the manifest as `devproof.lock.json`.
- Relative source paths are based on the manifest directory.
- The lock is written atomically with private creation permissions followed by
  its normal read permissions.
- Re-locking may replace the generated lock atomically without prompting.
- `--check` performs no write and fails when the lock is absent or stale.
- Source failures produce no partial lock.

Text output reports the lock path, lock digest, final tree digest, source count,
and file count. Quiet output is the lock digest.

## `devproof build`

Manifest mode:

```text
devproof build -f devproof.yaml \
  --lock devproof.lock.json \
  --to oci://registry.example.com/team/config:v1
```

Direct source mode:

```text
devproof build ./content --to oci-layout://./artifact

devproof build https://github.com/example/config.git \
  --git-ref 0123456789abcdef0123456789abcdef01234567 \
  --git-sub-path deploy \
  --to oci://registry.example.com/team/config:v1
```

Rules:

- `--file` and a positional direct source are mutually exclusive.
- Manifest mode requires a matching lock by default.
- `--update-lock` explicitly resolves and atomically replaces the lock before
  building; it is never implied by `build`.
- Direct Git mode requires `--git-ref`. It resolves and reports an immutable
  commit even when the input is already commit-shaped.
- `--write-lock PATH` records the synthesized direct-mode lock.
- `--to` is required until a documented local-layout default is selected.
- Supported destinations initially use `oci://` and `oci-layout://` schemes.
- A registry tag is optional; publication results always print the digest
  reference.
- `--sign` selects the configured signing provider. `--attest` emits provenance;
  policy or configuration may require both.
- A requested tag is assigned only after digest publication succeeds.

Text output reports the canonical digest reference, tree digest, file and byte
counts, and evidence descriptors. Quiet output is the canonical digest
reference.

## `devproof verify`

```text
devproof verify registry.example.com/team/config@sha256:... \
  --policy policy.yaml

devproof verify oci-layout://./artifact
```

Rules:

- The subject is the single required positional argument.
- Bare registry references and `oci://` references normalize to the same typed
  reference.
- A tag is resolved once and the resolved digest is prominent in output.
- `--require-digest` rejects tag input before fetching content.
- Without `--policy`, integrity is evaluated and trust is `not-evaluated`.
- With a policy, failure of any required trust rule returns the policy-failure
  exit code.
- `--offline` prohibits network access and requires a local OCI layout plus
  local trust material.
- `--trust-root PATH` may be repeated and reads protected local trust material.

Text output separates integrity, trust, and semantic results. JSON output uses
stable field names and finding codes. Quiet output is the resolved subject
digest only on success.

## `devproof expand`

```text
devproof expand registry.example.com/team/config@sha256:... \
  --to ./expanded \
  --policy policy.yaml
```

Rules:

- The subject and `--to` are required.
- Integrity verification is mandatory and cannot be disabled.
- Trust policy is optional unless required by configuration.
- The destination must not exist.
- There is no `--force`, merge, strip-components, ownership, or permission
  preservation flag in v1.
- No destination is published after failure or cancellation.
- `--offline` has the same semantics as verify.

Text output reports the destination, subject digest, tree digest, file count,
and verification summary. Quiet output is the absolute destination path.

## `devproof inspect`

```text
devproof inspect registry.example.com/team/config@sha256:...
devproof inspect devproof.lock.json
devproof inspect devproof.yaml
```

Inspect identifies the input kind, renders its typed metadata, and marks each
fact as authored, resolved, digest-verified, signature-verified, or
policy-accepted. It performs no expansion and no remote mutation.

`--files` includes the potentially large file inventory. `--evidence` includes
referrer summaries. Full evidence payloads require `--evidence-content`.

## Authentication and interaction

The CLI may use standard Git and registry credential helpers, environment
variables, protected credential files, workload identity, or an explicitly
configured OIDC provider.

Tokens, passwords, and private keys are not accepted as ordinary flag values.
Flags may name a credential provider or key reference.

Browser opening or device authorization occurs only when explicitly enabled,
stderr is an interactive terminal, and `--non-interactive` is absent. Otherwise
the command fails with instructions for supplying non-interactive credentials.

## Cancellation

The root command derives a context from SIGINT and SIGTERM. Ctrl-C cancels
source resolution, hashing, registry operations, evidence creation, and
expansion. Temporary state is cleaned up before exit when the operating system
allows it.

A canceled operation exits `130` for SIGINT. Programmatic context cancellation
that was not caused by SIGINT uses the operational failure code and reports
`canceled` in JSON.

## Exit codes

```text
0    requested operation completed successfully
2    command usage, manifest, lock, or unsupported-version error
3    source resolution, stale lock, unsafe path, or composition error
4    artifact construction, integrity, digest, or expansion error
5    evidence or verification-policy failure
6    authentication, authorization, registry, or network transport error
10   unexpected internal error
130  interrupted by SIGINT
```

The JSON error object also contains the finer SDK error code. Exit codes remain
coarse enough for stable shell behavior.

## JSON result envelope

Every command uses the same top-level shape:

```json
{
  "apiVersion": "devproof.thingz.io/cli/v1alpha1",
  "kind": "BuildResult",
  "result": {},
  "warnings": []
}
```

On failure, stdout remains empty unless `--format json` is selected. JSON mode
writes a failure envelope to stdout and diagnostics to stderr, then exits
non-zero:

```json
{
  "apiVersion": "devproof.thingz.io/cli/v1alpha1",
  "kind": "Error",
  "error": {
    "code": "stale-lock",
    "message": "source application no longer matches the lock",
    "source": "application"
  }
}
```

Stack traces are debug diagnostics and never part of the stable JSON schema.
