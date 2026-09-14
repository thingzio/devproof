# DevProof

[![ci](https://github.com/thingzio/devproof/actions/workflows/ci.yaml/badge.svg)](https://github.com/thingzio/devproof/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/thingzio/devproof.svg)](https://pkg.go.dev/github.com/thingzio/devproof)
[![Go Report Card](https://goreportcard.com/badge/github.com/thingzio/devproof)](https://goreportcard.com/report/github.com/thingzio/devproof)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Package files into OCI artifacts that have the same digest on every machine,
carry signed proof of where they came from, and unpack safely.**

Configuration, policies, scripts, and catalogs get assembled from several
places that all move independently. Put them in a tarball and you have bytes
nobody can say much about: not what was selected, not where it came from, not
whether it changed, not who stands behind it.

DevProof gives that pile a **name derived from its content** — a digest that is
the same on every machine, forever — then lets you attach signed evidence to
that name and check it against your own rules before anything touches disk.

## Install

```bash
brew install thingzio/tap/devproof
```

Or with Go:

```bash
go install github.com/thingzio/devproof/cmd/devproof@latest
```

Prebuilt binaries for Linux and macOS (amd64 and arm64) ship with each release,
each covered by a signed checksum file and an SBOM. Windows is not supported —
use WSL ([DP-035](docs/decisions.md)).

## Quickstart

```console
$ devproof init --src ./content
manifest:        devproof.yaml
source:          ./content
next:            edit metadata.name, then run devproof lock

$ devproof build ./content --to oci-layout://./artifact --tag v1
reference:       oci-layout://./artifact@sha256:e3d8f68bd8c485...
subject:         sha256:e3d8f68bd8c485...
tree digest:     sha256:168de0126f4a8c...
format:          devproof-bundle-v1
files:           2

$ devproof verify oci-layout://./artifact:v1
subject:         sha256:e3d8f68bd8c485...
integrity:       pass
trust:           not-evaluated
semantics:       not-evaluated

$ devproof expand oci-layout://./artifact:v1 --to ./expanded

$ devproof diff oci-layout://./artifact:v1 ./content
from:            sha256:168de0126f4a8c...
to:              sha256:168de0126f4a8c...
result:          identical
```

Run the build again — different directory, different machine, next year — and
the subject digest is the same. Everything else here rests on that.

`devproof init` writes a commented manifest so a first one does not require
reading a schema, and `devproof diff` answers "has anything changed since I
built this?" — exit `0` when the two sides are identical, exit `1` when they
differ.

For a five-minute walkthrough that alters a stored artifact and watches
verification catch it, see the [demo](examples/). It runs entirely on your
machine, and it runs in CI, so what it claims stays true.

Swap `oci-layout://` for `oci://registry.example.com/team/config` to work
against a registry. Credentials come from your Docker configuration, so
`docker login`, `gh auth login`, or `gcloud auth configure-docker` is the whole
setup.

## Use it from Go

The SDK is the primary API and the CLI is a thin adapter over it, so anything
you can do at the command line you can do in-process, without shelling out.

```go
import "github.com/thingzio/devproof/pkg/devproof"

client, err := devproof.New()
if err != nil {
	return err
}
defer func() { _ = client.Close() }()

built, err := client.Build(ctx, devproof.BuildRequest{
	SourcePath:  "./content",
	Destination: "oci://registry.example.com/team/config",
	Tag:         "v1",
})
if err != nil {
	return err
}

// Expansion is gated: if the policy is not satisfied, nothing is written.
_, err = client.Expand(ctx, devproof.ExpandRequest{
	Reference:   built.Reference,
	Destination: "./expanded",
	PolicyPath:  "policy.yaml",
})
```

Full reference on [pkg.go.dev](https://pkg.go.dev/github.com/thingzio/devproof).

## Verification answers three separate questions

Most tools collapse these into one boolean. Keeping them apart is the point.

| Dimension | Question | Needs |
| --- | --- | --- |
| **integrity** | Are these the bytes the artifact claims? | nothing — always checked |
| **trust** | Who produced them, and do I accept that? | a policy |
| **semantics** | Is the content valid for my use? | a validator, supplied by the embedding application |

A dimension you did not ask about reports `not-evaluated`, **never `pass`**. If
your trust configuration silently failed to load, you will see
`trust: not-evaluated` rather than a green check — which is the difference
between knowing and assuming.

Semantics is answered by a validator you supply. DevProof has no domain, so it
has no opinion about what your payload means — it provides the seam, not the
check. The CLI ships no validator, so it reports `not-evaluated`, which is the
honest answer rather than a placeholder.

The interface is deliberately unexported in v1
([DP-026](docs/decisions.md)): a public interface is a permanent obligation,
and two real validators are needed before its shape can be trusted. See
[semantic validation](docs/policy.md#semantic-validation).

```yaml
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release-gate
spec:
  subject:
    requireDigestReference: true
  signatures:
    threshold: 1
    identities:
      - issuer: https://token.actions.githubusercontent.com
        subjectPattern: ^https://github\.com/example/config/\.github/workflows/release\.yaml@refs/tags/v.*$
  provenance:
    required: true
    requireLockDigest: true
```

```bash
devproof verify oci://registry.example.com/team/config@sha256:... --policy policy.yaml
```

Exit code `0` means the policy was satisfied. A failed policy exits non-zero,
so a CI gate built on this cannot pass by accident.

## How it works

```text
sources ──▶ manifest ──▶ lock ──▶ canonical tree ──▶ OCI subject @ sha256:…
                                                            │
                                        signed provenance, attached as
                                        referrers — identity unchanged
                                                            │
                                        verify ──▶ safely expand to disk
```

A **manifest** says what you want, and may name moving things — a branch, a
local directory. A **lock** records what those resolved to, so "what did you
ask for" and "what did you get" stay independently reviewable. The files are
normalized into a **canonical tree**, encoded deterministically, and named by
digest.

**Evidence is attached to that name, not baked into it.** Signing, re-signing,
or copying an artifact never changes its digest — so a signature can be added
later without invalidating every reference to the content.

Multi-source builds compose through explicit mount paths, with one owner per
path. Collisions fail loudly, even when the colliding bytes are identical.

```yaml
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example-config
spec:
  sources:
    - name: application
      type: git
      mountPath: app
      config:
        url: https://github.com/example/application.git
        # A branch, a tag, or a full commit SHA. A branch is fine here
        # precisely because the lock pins whatever it resolved to, and a
        # locked build fails rather than quietly following it somewhere new.
        ref: main
        subPath: deploy
    - name: environment
      type: path
      mountPath: environment
      config:
        path: ./production
```

## Safe by construction

- **Expansion is staged and atomic.** Files land in a private directory and are
  published with an exclusive rename. A failed, canceled, or hostile
  extraction leaves no destination — not a partial one that looks finished.
- **A gated expansion writes nothing when the policy fails.** Content that is
  written and then deleted was already readable.
- **Nothing from a bundle is executed.** No hooks, no validators, no plugins.
- **The portable profile** rejects symlinks, device files, path aliases,
  Windows reserved names, and case-fold collisions, so a bundle that builds is
  a bundle that expands everywhere.
- **Bounded by default** — file counts, sizes, compression ratios, and path
  depth all have documented limits, and memory does not scale with payload
  size.

## Works with what you already have

A DevProof artifact is an ordinary OCI artifact. `skopeo`, `crane`, and `oras`
copy it with the digest intact; GHCR, Google Artifact Registry, and
`distribution` all store and serve it, referrers API included. The layer is
plain `tar+gzip` — GNU, BSD, and busybox `tar` all unpack it directly.

Verified results and commands to reproduce them:
[interoperability](docs/interoperability.md).

## What it is not

Not a deployment engine, dependency solver, registry server, container runtime,
secrets manager, or package manager.

DevProof proves identity, integrity, provenance, and policy compliance. It
makes **no claim** that the content inside is correct, safe, or free of
vulnerabilities — a perfectly valid signature on malware is still a valid
signature.

## Don't take our word for it

The [`conformance`](pkg/conformance) package is a second, independent reader of the
bundle format, built only from the Go standard library and the written
specification. It imports nothing else from this project, so it is free to
disagree with the main implementation — and when it did, it was the
specification that turned out to be wrong.

```go
import "github.com/thingzio/devproof/pkg/conformance"

report, err := conformance.VerifyLayout("./artifact", "v1", conformance.LevelCanonical)
```

## Documentation

| | |
| --- | --- |
| [Demo](examples/) | a five-minute walkthrough, executed in CI |
| [Architecture](docs/architecture.md) | components, data flow, failure behavior |
| [Bundle format](docs/bundle-format.md) | canonical model, tree digest, OCI encoding |
| [Manifest and lock](docs/manifest.md) | sources, resolution, filtering, composition |
| [Go SDK](docs/sdk.md) · [CLI](docs/cli.md) | operations, errors, exit codes, streams |
| [Verification policy](docs/policy.md) | trust rules and result semantics |
| [Security](docs/security.md) | threat model, trust boundaries, safe extraction |
| [JSON Schemas](schemas/) | normative schemas for every document, and what they cannot express |
| [Decisions](docs/decisions.md) | every accepted design decision, and why |
| [Compatibility](docs/compatibility.md) | what each version number promises |
| [Interoperability](docs/interoperability.md) | verified results against other tooling |
| [Testing](docs/testing.md) | golden vectors, determinism matrix, fuzzing |

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING](CONTRIBUTING.md) for
the development workflow, and [SECURITY](SECURITY.md) to report a vulnerability
privately.

## License

[Apache License 2.0](LICENSE). Dependency licenses and notices are reproduced
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
