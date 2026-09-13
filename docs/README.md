# DevProof design

Status: implemented and released. These documents describe what ships.

DevProof is a Go SDK and CLI that resolves content from one or more sources,
composes it into a canonical filesystem tree, packages that tree as an OCI
artifact, records provenance as independently verifiable evidence, evaluates
the result against policy, and safely expands the artifact back to a
filesystem.

The shortest description is:

> A Go-embeddable, extensible, multi-source artifact bundler with canonical
> identity across platforms, provenance evidence, policy-based verification,
> and safe deterministic expansion.

## Design goals

DevProof must:

- produce the same subject digest for the same canonical filesystem content on
  every supported platform;
- preserve exact file bytes while normalizing only the filesystem metadata
  defined by the format;
- resolve mutable source references into immutable lock data before building;
- keep content identity independent from signatures, timestamps, source
  locations, and other provenance;
- expose all core behavior through a Go SDK, with the CLI as an adapter;
- support additional source, transport, attestation, and policy implementations
  without allowing extensions to redefine the canonical format;
- verify structure and content before publishing or expanding;
- expand into a private staging directory and publish the result atomically;
- make network access, authentication, mutation, and trust decisions explicit;
- provide stable machine-readable results and typed errors.

## Non-goals

The first version is not:

- a dependency solver or general-purpose package manager;
- a deployment, reconciliation, or desired-state engine;
- a container image builder or runtime;
- a registry server;
- a secrets manager;
- a semantic validator for arbitrary payload types;
- a mechanism for executing code carried inside a bundle;
- a byte-for-byte preservation format for every operating-system filesystem
  feature.

## Core model

```text
devproof.yaml
    |
    | resolve and snapshot
    v
devproof.lock.json -----> provenance evidence
    |
    | compose and canonicalize
    v
canonical filesystem tree
    |
    | deterministic package
    v
OCI subject @ sha256:...
    |
    +---- signature and attestation referrers
    |
    +---- verify against policy
    |
    +---- safely expand to filesystem
```

The OCI subject is a function only of the canonical payload and format version.
Evidence may describe where that payload came from and who produced it, but
adding or replacing evidence does not change the subject digest.

## Documentation map

- [JSON Schemas](../schemas/): normative schemas for the manifest, lock,
  policy, and config documents, and what they cannot express.
- [Decisions](decisions.md): accepted v1 decisions and unresolved choices.
- [Architecture](architecture.md): components, data flow, ownership, and failure
  behavior.
- [Manifest and lock](manifest.md): source declarations, resolution, filtering,
  composition, and lock semantics.
- [Bundle format](bundle-format.md): canonical filesystem model, tree digest,
  OCI encoding, evidence attachment, and round-trip guarantees.
- [Go SDK](sdk.md): public packages, interfaces, operations, errors, and
  concurrency contract.
- [CLI](cli.md): commands, flags, output streams, exit codes, configuration, and
  cancellation behavior.
- [Verification policy](policy.md): integrity, trust, evidence selection, and
  policy result semantics.
- [Security](security.md): threat model, trust boundaries, policy, credentials,
  and safe extraction.
- [Testing](testing.md): golden vectors, determinism, fuzzing, interoperability,
  and failure tests.
- [Interoperability](interoperability.md): verified results against other OCI
  tooling, with commands to reproduce them.
- [Compatibility](compatibility.md): what each version number promises, and how
  to migrate across format and API versions.
- [Roadmap](roadmap.md): implementation order and exit criteria.

## Standards baseline

The design uses these external specifications as protocols rather than product
architecture:

- [OCI Image Specification 1.1.1](https://github.com/opencontainers/image-spec/tree/v1.1.1),
  including artifact guidance;
- [OCI Distribution Specification 1.1.1](https://github.com/opencontainers/distribution-spec/tree/v1.1.1),
  including subject and referrer discovery;
- [in-toto Attestation Framework 1.2](https://github.com/in-toto/attestation/tree/v1.2.0),
  including Statement v1 and DSSE envelopes;
- [Sigstore bundle specification](https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md)
  and verification material; and
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
  where canonical JSON is required.

An implementation must pin tested library and protocol versions. A standards
update must not silently change bytes emitted for an existing DevProof format
version.

## Requirement language

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative in the
format, manifest, SDK, CLI, and security documents. Examples are illustrative
unless explicitly marked as test vectors.
