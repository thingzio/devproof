# Architecture

## System boundary

DevProof transforms source material into an immutable artifact and transforms a
verified artifact back into a canonical filesystem tree. It owns the evidence
needed to explain and evaluate that transformation. It does not own the
application-specific meaning or deployment lifecycle of the files.

```text
                         DevProof
  +------------------------------------------------------+
  |                                                      |
  |  spec -> resolve -> snapshot -> compose -> package   |
  |             |                     |          |        |
  |             +------ lock ---------+          v        |
  |                                    OCI subject        |
  |                                         |             |
  |                             attest -----+             |
  |                                         |             |
  |  policy -> fetch -> verify -> expand <--+             |
  |                                                      |
  +------------------------------------------------------+
         |                                  |
         v                                  v
  source systems                     filesystem consumers
```

## Components

### Specification loader

The loader parses a versioned YAML or JSON manifest into typed data. It rejects
unknown fields, duplicate keys, unsupported versions, ambiguous scalar types,
and invalid path or source syntax. Relative local paths are resolved against
the manifest directory, not the process working directory.

### Resolver registry

The registry maps a source type to one explicitly registered resolver. Built-in
v1 resolvers are `path` and `git`. A resolver validates its own configuration,
obtains the requested material, and creates an immutable private snapshot.

Resolvers do not write to the final bundle tree. They return normalized file
records and material identity to the composer.

### Snapshot store

A snapshot is a private read-only view used for one operation. Files are copied
or streamed into storage controlled by DevProof before packaging. Packaging
never reads again from a mutable source directory or checkout.

Snapshot creation must:

- use private permissions;
- apply source filters before composition;
- reject unsupported file types and unsafe paths;
- hash content while copying;
- close all handles before publication; and
- remove partial state after failure or cancellation.

A future content cache may retain snapshots by tree digest, but cache hits must
be revalidated and cache state must not change bundle bytes.

### Composer

The composer maps each selected source path under its declared `mountPath`.
It normalizes paths and modes, assigns one source owner to every final path,
rejects collisions, sorts the result, and produces the canonical inventory and
tree digest.

Composition has no implicit precedence. Manifest source order is not an input
to identity.

### Packager

The packager serializes the canonical inventory into a config blob, serializes
the files into one canonical gzip-compressed tar layer, and creates an OCI image
manifest. It verifies the locally generated descriptors before returning an
artifact.

The packager accepts a prepared canonical snapshot rather than a live
filesystem path.

### Transport

A transport stores and retrieves OCI objects. Initial transports are a local
OCI image layout and an OCI Distribution registry. Transport code handles
authentication, retries, copy, descriptor verification, and tag assignment.

Tags are written only after every required blob and the manifest are present
and the remote manifest descriptor matches the locally prepared descriptor.
Failure before that point must not create a success result or emit a digest as
published.

### Evidence service

The evidence service creates in-toto statements whose subject is the immutable
OCI manifest digest. Provenance includes the spec digest, lock digest, resolved
materials, source resolver identities, and builder identity when available.

Signing is optional during build but may be required by publication or
verification policy. Evidence is attached as an OCI referrer and is not part of
the subject manifest.

### Verifier

Verification proceeds in ordered stages:

1. Resolve the requested reference to one manifest digest.
2. Verify every fetched blob against its OCI descriptor.
3. Parse the config using the declared format version.
4. Verify layer entries and bytes against the config inventory.
5. Recompute and compare the canonical tree digest.
6. Discover and cryptographically verify evidence.
7. Evaluate verified evidence and artifact facts against policy.
8. Optionally invoke a caller-supplied semantic validator.

Later stages do not convert an earlier failure into a warning. The report
preserves separate integrity, trust, and semantic results.

### Expander

The expander consumes a verified artifact and writes its canonical payload to a
new destination. Extraction and verification are one operation: bytes are
hashed as they are written, and no unverified result is published.

A semantic validator, when one is supplied, judges the staged tree before the
rename that publishes it. A rejected expansion therefore leaves nothing behind
rather than writing and removing, which is the same guarantee a failed policy
gives (DP-032). On `verify` the payload is materialized into a private
directory that is removed before the command returns.

## Build flow

### Manifest build

```text
load manifest
  -> validate source schemas
  -> resolve each source
  -> snapshot selected files
  -> create or compare lock
  -> compose canonical inventory
  -> compare final tree digest with lock
  -> create config and layer
  -> create and validate OCI manifest
  -> write local layout or push by digest
  -> attach evidence when requested
  -> assign tag last
  -> return subject digest and evidence descriptors
```

`--locked` behavior is the default for a manifest build when a lock file is
present. A stale lock is an error. Updating a lock is a separate operation or an
explicit build option.

### Direct single-source build

A direct path or Git build creates an in-memory one-source manifest and lock,
then follows the same pipeline. Direct mode is convenience syntax, not a
second implementation.

The synthesized manifest is not written to disk. A manifest is a document
someone maintains and reviews, and one that appeared as a side effect of a
build would be neither. `devproof init` writes one on purpose, with the
comments that make it editable.

## Fetch and expansion flow

```text
resolve tag once, if supplied
  -> fetch manifest by digest
  -> fetch config and layer by digest
  -> discover evidence for the subject digest
  -> verify integrity and policy
  -> create private sibling staging directory
  -> stream and validate each entry
  -> fsync files when supported
  -> atomically rename staging directory to destination
```

The destination must not exist in v1. A caller that needs replacement semantics
must coordinate them outside DevProof after a successful expansion.

## State ownership

DevProof operations are finite and caller-driven. There is no daemon or
background reconciliation loop.

- The source owner controls source availability and authentication.
- DevProof owns temporary snapshots and local OCI staging during an operation.
- The registry owns durable OCI blobs, manifests, tags, and referrer indexes.
- The caller owns manifests, locks, policies, output directories, and retention.
- A consumer owns any interpretation or execution of expanded files.

DevProof does not delete remote content as part of a failed push. Registries are
content-addressed and may retain untagged blobs until their own garbage
collection policy removes them.

## Concurrency

Independent source resolution may run concurrently under a configured bound.
The default bound must be conservative. Every result is collected by source
name and sorted before composition; completion order cannot affect output.

On the first source failure, the operation cancels outstanding work and returns
one primary typed error plus structured secondary failures when available. It
does not produce a partial lock or bundle.

Blob uploads may run concurrently after all local descriptors are frozen.
Manifest and tag writes remain ordered publication barriers.

## Retry and timeout policy

Retries are allowed only for classified transient operations such as registry
timeouts, throttling, and temporary service failures. They use bounded
exponential backoff with jitter and honor the parent context deadline.

No retry is performed for invalid input, authentication denial, digest
mismatch, policy failure, unsafe content, unsupported format, or a non-idempotent
operation without a stable upload identity.

All network attempts have per-attempt timeouts inside an overall operation
timeout. Cancellation stops new work immediately and is checked between file
operations; an individual blocking operating-system read may return only when
the operating system releases it.

## Observability

SDK operations accept an optional structured logger and tracing hooks. Events
must identify the operation and source by sanitized logical name, not by secret
URLs or credential-bearing headers.

Required measurements include:

- operation duration and outcome;
- source resolution duration and bytes;
- file count and uncompressed/compressed bytes;
- cache hit or miss, when caching exists;
- registry retries and transferred bytes;
- verification stage and stable failure code; and
- expansion duration and limit rejection.

Metrics and logs are never inputs to artifact identity.

## Go package boundaries

```text
github.com/thingzio/devproof
  pkg/devproof/          top-level SDK facade
  pkg/source/            public source contracts
  pkg/source/path/       built-in local resolver
  pkg/source/git/        built-in HTTPS Git resolver
  pkg/bundle/            public spec, lock, inventory, and result types
  pkg/artifact/          public artifact descriptors
  pkg/evidence/          public evidence and attester contracts
  pkg/policy/            public policy and verification result types
  pkg/conformance/       independent format reader, shares no code (DP-034)
  internal/canonical/    path, record, JSON, tar, and gzip encoding
  internal/compose/      closed-world source composition
  internal/oci/          OCI layout and registry implementation
  internal/safefs/       snapshot and extraction protections
  internal/cli/          command tree, output, credentials
  internal/version/      build identity
  cmd/devproof/          CLI wiring only
```

Everything importable lives under `pkg/`, so the repository root holds only
`cmd`, `docs`, `internal`, `pkg`, and `tools`. `internal/` is the boundary the
compiler enforces; `pkg/` is the one a reader can see at a glance.

Only types that callers need to configure, extend, invoke, or inspect belong in
public packages. Canonical byte production stays internal and is exposed
through stable high-level operations rather than low-level knobs.

## Interoperability boundary

The subject uses an OCI image manifest and one standard gzip filesystem layer.
Consumers that understand generic OCI filesystem artifacts may extract the
layer without understanding provenance. Full DevProof verification additionally
requires the DevProof config and evidence policy.

Interoperability is verified behavior, not inferred from schema compatibility.
The test plan includes multiple registries and filesystem-oriented OCI
consumers. A consumer-specific workaround must not change v1 subject bytes.
