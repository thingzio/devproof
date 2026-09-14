# CLI design

## Command model

The executable is `devproof`. The CLI is human-readable by default and stable
for automation when `--format json` or `--quiet` is selected.

```text
devproof
  init       write a starter bundle manifest
  lock       resolve a manifest and write its immutable lock
  build      build and optionally publish a bundle
  verify     verify integrity, evidence, and policy
  expand     verify and materialize a bundle
  diff       compare two canonical trees
  copy       copy a subject and its evidence between locations
  inspect    show subject, inventory, and evidence metadata
  version    show version and supported format versions
```

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
--insecure-registry   use plain HTTP for registries
```

`--quiet` and `--format json` are mutually exclusive unless a command defines
the JSON value as its quiet output. `--debug` never changes the data written to
stdout.

The default timeout is 30 minutes for every command and is printed by help.
There is no spelling for unbounded: a zero or negative `--timeout`, or a
configured one, is a usage error rather than an operation that can occupy a CI
runner until somebody notices.

`--insecure-registry` sends credentials and content in the clear and warns on
stderr every time it is used.

## Configuration precedence

Highest priority wins:

```text
explicit flag > DEVPROOF_* environment variable > config file > built-in default
```

The table applies to every setting, including the boolean ones: a file that
sets `verbose` or `debug` supplies a default, and `--verbose=false` or
`DEVPROOF_VERBOSE=false` turns it off for one invocation.

Manifest, lock, and verification-policy data are not CLI settings and are not
silently loaded from a user-global configuration file.

The settings file is read from the per-user configuration directory, or from
`--config`. It is never discovered by searching the working directory or its
ancestors: a file picked up from a cloned repository could otherwise change
what a command does.

It may contain `format`, `verbose`, `debug`, `noColor`, `timeout`, `policy`,
`trustRoot`, `fulcioUrl`, and `rekorUrl`. It may not contain raw tokens or
private keys, and it may not name a reference, destination, or tag — a file
that could change *which* artifact a command acted on would make the same
command line mean different things on different machines (DP-030).

A configured `policy` can only make verification stricter. There is no setting
that relaxes it.

Decoding is strict: an unknown key is an error rather than a silently ignored
setting.

`--debug` prints effective non-secret settings and their source. Global
settings are reported by the root command; a setting a subcommand owns is
reported where it is resolved, because the root has not parsed it yet.

An explicitly named `--config` that does not exist is an error. The default
path not existing is not.

## Streams

- stdout contains the requested result only;
- stderr contains progress, diagnostics, warnings, prompts, and errors;
- JSON mode writes exactly one JSON document followed by `\n` to stdout;
- progress UI is enabled only when stderr is a terminal;
- color is enabled only for a compatible terminal and is disabled by
  `NO_COLOR`, `TERM=dumb`, `--no-color`, JSON, or quiet mode.

Logging never corrupts a digest, path, or JSON result intended for a pipeline.

## `devproof init`

```text
devproof init [--src DIR] [--to devproof.yaml]
```

Writes a commented manifest describing one local source, so that a first
manifest does not require reading the schema first. The comments cover the
`git` source type, `include` and `exclude`, `mountPath`, `subPath`, and `ref` —
the things someone would otherwise go looking for.

Behavior:

- `--src` defaults to the working directory and sets only the source's `path`.
  The rest of the document never varies.
- The recorded path is rewritten relative to the manifest's directory, because
  a manifest resolves its sources against itself.
- A `--src` that does not exist yet warns on stderr and still writes the
  manifest, since creating the manifest first is an ordinary order of work.
- It never overwrites. An existing file at `--to` is a `destination-exists`
  error, exit 4.

The file it writes is validated against the published
[bundle schema](../schemas/bundle.v1alpha1.schema.json) by the test suite, so
the scaffold cannot drift out of conformance with the document it teaches.

Text output reports the manifest path, the recorded source, and the next
command. Quiet output is the manifest path.

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

Direct source mode, which takes one local directory:

```text
devproof build ./content --to oci-layout://./artifact

devproof build ./content \
  --mount app \
  --include "config/**" \
  --exclude "**/*.tmp" \
  --to oci://registry.example.com/team/config:v1 --tag v1
```

A Git source is written in a manifest rather than given on the command line.
It needs a URL, a ref, and optionally a subpath, and a flag set large enough
to express that is a manifest with worse ergonomics and no way to review it.

Rules:

- `--file` and a positional direct source are mutually exclusive.
- Manifest mode requires a matching lock by default. `--no-lock` builds without
  one, which is for a throwaway artifact rather than a release.
- `--update-lock` explicitly resolves and atomically replaces the lock before
  building; it is never implied by `build`.
- `--mount PREFIX` places a direct source below a prefix. `--include` and
  `--exclude` are repeatable selection patterns with the same syntax the
  manifest uses.
- `--to` is required until a documented local-layout default is selected.
- Supported destinations initially use `oci://` and `oci-layout://` schemes.
- `--tag` is optional; publication results always print the digest reference,
  and a requested tag is assigned only after digest publication succeeds.
- `--sign` signs provenance and attaches it to the subject. It is keyless by
  default; `--key PATH` uses a PEM private key instead, and `--fulcio-url` and
  `--rekor-url` select a private Sigstore deployment.

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
  local trust material. A `--key` is local trust material, so it satisfies this
  on its own.
- `--trust-root PATH` reads a Sigstore trusted root, for certificate-based
  identities. It takes one path; use `--key` (repeatable) for bare public keys.
- `--key` and `--trust-root` select different trust models and **cannot be
  combined**. They do not compose underneath — each installs one verifier — so
  supplying both used to accept the trust root and then discard it, leaving an
  operator who believed they had pinned one having pinned nothing.

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
- Trust policy is optional unless required by configuration. When a policy is
  supplied it is evaluated *before* anything is written, and an unsatisfied
  policy publishes no destination at all (DP-032).
- The destination must not exist.
- There is no force, merge, strip-components, ownership, or permission
  preservation flag in v1.
- No destination is published after failure or cancellation.
- `--offline` has the same semantics as verify.

Text output reports the destination, subject digest, tree digest, file count,
and verification summary. Quiet output is the absolute destination path.

## `devproof diff`

```text
devproof diff [--quiet-if-same] FROM TO
```

Compares two canonical trees. Each operand is either an OCI reference —
anything carrying a `://` scheme — or a path to a local directory. A directory
is canonicalized through the same path a build uses, so "no differences" means
a build of that directory would produce the subject it was compared against.

```console
$ devproof diff oci://registry.example.com/team/config:v1 ./content
from:            sha256:168de0126f4a8c...
to:              sha256:08f7a027d5c509...
added:           1
removed:         0
modified:        1

~ app/config/service.yaml
+ app/config/new.yaml
```

Markers are `+` added, `-` removed, `~` content changed, and `m` mode changed.
A mode change is separate from a modification on purpose: reporting an
executable bit flip as a modification would claim the bytes changed when they
did not. Every entry carries both digests, so the classification can be
checked rather than trusted.

Changes are sorted by canonical path.

**Exit codes are the contract here.** `0` means the two sides are identical;
`1` means they differ. A difference is an answer rather than a failure, so it
carries no error and writes nothing to stderr. Everything above `1` is a real
failure, as everywhere else.

```bash
if devproof diff "$REFERENCE" ./content --quiet-if-same; then
  echo "nothing to publish"
fi
```

An operand that cannot be read fails normally. A mistyped directory reports
that it could not be read rather than being reinterpreted as a registry
reference, because the scheme decides how an operand is parsed, not whether
the path happens to exist.

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

## `devproof copy`

```text
devproof copy oci://registry.example.com/team/config@sha256:... \
  --to oci-layout://./mirror --tag v1
```

Copies a subject between registries, layouts, or repositories. Integrity is
verified at the source and the copy is published under the same rules as a
build, so a copy cannot launder a broken artifact into a destination that looks
authoritative.

The subject digest is unchanged by definition: identity is a function of
content and format version, and a repository name is neither (DP-002).
`--require-digest` rejects a source tag before anything is fetched.

Evidence moves with the subject. Every referrer is carried, not only DevProof's
own, because a mirror that silently dropped what it did not recognize would
leave a gap nobody could see. The evidence blob is transferred byte for byte,
which is what preserves the signature; the referrer manifest is rebuilt at the
destination, since a layout and a registry record it differently.

A destination that cannot hold referrers is an error rather than a silent
partial copy. An export for an air gap has one chance to carry the signature
across, and finding out afterwards is finding out too late.

`CopyResult.EvidenceCount` reports how many objects travelled.

## `devproof version`

```text
devproof version
```

Reports the version, the commit it was built from, and the bundle format
versions this build supports. With `--format json` it is the machine-readable
form a CI job records alongside a result, which is what makes a later "which
build produced this" answerable.

## `devproof conformance`

```text
devproof conformance ./layout --reference v1
devproof conformance ./layout --level structure
devproof conformance ./vectors/format/v1 --level bytes
```

Reads the artifact with an independent implementation built from
[the format specification](bundle-format.md), sharing no code with the writer
(DP-034). It is the check to run against another implementation's output, and
it needs no policy, no evidence, and no network.

| `--level` | Question |
| --- | --- |
| `structure` | is it intact, self-consistent, and safe to expand? |
| `canonical` | are these the only bytes a conforming writer produces for this tree? |
| `bytes` | is this identical to the published vectors in [vectors/](../vectors)? |

The default is `canonical`. A deviation found above the requested level is
printed as a warning and counted in the result rather than discarded, so a
structural pass still says what it tolerated.

`bytes` takes a directory of vector files rather than a layout: byte
conformance is a claim about what an encoder produced.

A non-conforming artifact exits with the invalid-artifact code.

## Authentication and interaction

Registry credentials come from the Docker configuration — `DOCKER_CONFIG` or
`~/.docker/config.json` — including `auths` entries, `credHelpers`, and
`credsStore`. `docker login` is therefore all the setup there is, and
helper-based cloud registries work without extra configuration (DP-031).

A credential is looked up by host and is never offered to any other host. A
registry with no entry gets anonymous access rather than an error, because
public registries exist. A configured helper that is missing from `PATH`
warns rather than failing, since the request may still succeed anonymously.

Helper results are cached per host for the process lifetime.

Tokens, passwords, and private keys are not accepted as ordinary flag values.
Flags may name a credential provider or key reference.

Nothing prompts, opens a browser, or reads a terminal. Keyless signing uses an
ambient OIDC token — the one a CI runner already has — and fails with an
explanation when none is available rather than starting a device flow.

`--non-interactive` is therefore satisfied unconditionally today. It exists so
a script can assert the guarantee rather than discover later that some path
began prompting; any interactive flow added in future must read it before
prompting.

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
1    devproof diff only: the comparison succeeded and the sides differ
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

No failure exits `1`. It is reserved for a command that completed and whose
answer is "no", so a script branching on "they differ" cannot mistake a
registry timeout for a difference (DP-023).

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
