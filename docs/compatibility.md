# Compatibility and migration policy

DevProof versions three things independently, because they change for
different reasons and break different people:

| Surface | Identifier | Breaks |
| --- | --- | --- |
| Bundle format | `devproof-bundle-v1` | every artifact already published |
| Go module API | semantic version | code that imports the SDK |
| CLI contract | semantic version | scripts and pipelines |

A change that is routine for one is catastrophic for another. Adding a Go
method is a minor release; changing one byte of the tar encoder changes every
digest that has ever been computed.

## Bundle format

### What the format identifier promises

`devproof-bundle-v1` names an exact byte-level encoding. For a given canonical
tree, every conforming implementation on every supported platform produces the
same tree digest, the same layer bytes, the same config bytes, and therefore
the same subject digest — now and in five years.

This is stronger than "compatible". Two v1 implementations do not merely
interoperate; they are byte-identical. That is what makes a digest a stable
name rather than a coincidence of one toolchain.

### What may never change in v1

- the tree-record encoding and its domain separator;
- path normalization, mode normalization, and sort order;
- tar entry order, header fields, and PAX record encoding;
- the DEFLATE encoder and gzip header fields;
- config JSON canonicalization and field semantics; and
- manifest structure, media types, and cardinality.

The frozen DEFLATE encoder lives in `internal/canonical/deflate` for exactly
this reason (DP-016). A Go release that improved `compress/flate` would
otherwise silently change every layer digest — a correctness improvement
upstream is a compatibility break here.

### What may change in v1

Anything that does not affect produced bytes: performance, diagnostics, error
messages, logging, resource limits, CLI ergonomics, and which sources or
evidence backends exist. New source resolvers and new evidence formats are
additive and do not touch the format.

### What a v2 would require

A new format version is introduced when a byte-affecting change is genuinely
needed — a stronger digest algorithm, a new file type, a different compression
scheme. It must:

1. use a new format identifier and new config and artifact media types;
2. ship normative golden vectors before any implementation is released;
3. document whether and how a v1 canonical tree maps to a v2 canonical tree;
   equal logical content is **not** assumed to keep the same digest across
   versions; and
4. leave the v1 reader in place.

Readers dispatch on the config format and artifact media type, and reject what
they do not recognize rather than guessing. A v1-only reader encountering a v2
artifact fails with an unsupported-version error, which is the correct outcome:
a reader that guessed would verify something other than what it read.

### Migrating artifacts across format versions

There is no in-place upgrade, and there is deliberately no tool that rewrites a
v1 artifact into a v2 one while claiming it is the same thing. It is not the
same thing: it has a different digest, so every lock, policy, attestation, and
deployment that named the old digest still names the old artifact.

Migration is a rebuild. Build the same sources with a v2-capable builder,
publish the new subject, re-attest it, and update whatever referenced the old
digest. The old artifact stays valid and verifiable for as long as a v1 reader
exists, which is indefinitely.

Both versions can coexist in one repository. They are different subjects with
different digests, distinguishable by media type without fetching content.

## Go module API

After the first stable release the module follows semantic versioning.

### Covered

Everything exported from the module root and from `bundle`, `policy`,
`evidence`, `artifact`, `source`, and `conformance`.

### Not covered

- anything under `internal/`, which is enforced by the compiler;
- the exact text of error messages. Error *codes* are API; the sentences are
  written for the human deciding what to do next, and nothing should parse
  them;
- the order of findings within a verification report, beyond what the report's
  own documentation guarantees; and
- benchmark results and resource consumption.

### Interface evolution

Public interfaces are kept small because adding a method to an exported
interface breaks every external implementation of it. Capabilities are added
by:

- a new optional subinterface, discovered with a type assertion; or
- a new field on a request struct whose zero value preserves existing
  behavior.

A request struct gaining a field is not a breaking change. This is why
operations take request structs rather than long parameter lists.

### Deprecation

A deprecated symbol is marked with a `Deprecated:` comment naming its
replacement, keeps working for the remainder of the current major version, and
is removed only in the next major version. Nothing is removed without a
release in which it is both present and documented as deprecated.

## CLI contract

The CLI is versioned with the module, and the following are the contract:

- command names, flag names, and flag semantics;
- the stream discipline — stdout carries the result and nothing else;
- the exit-code mapping (DP-023);
- the JSON envelope shape and its `apiVersion`; and
- the `code` field of the JSON error object.

Human-readable text output is **not** contract. It is written to be read, and
it will be improved. A script that parses it will break; `--format json` or
`--quiet` exists so that it does not have to.

The JSON envelope carries its own `apiVersion`
(`devproof.thingz.io/cli/v1alpha1`), versioned separately from the bundle
format because the two change for different reasons.

New flags and new commands are additive. A flag is removed only across a major
version, after a release in which using it warns.

## Manifest, lock, and policy documents

These carry `apiVersion` and `kind`, and decoding is strict: an unknown field
is an error.

Strictness is the point. A reader that ignored an unrecognized field would
silently not enforce a rule someone wrote down, turning a strict policy into a
permissive one. The cost is that adding a field to any of these documents
requires a new `apiVersion`, and that cost is worth paying.

When a new document version is introduced, the previous version continues to
be accepted for the remainder of the major version.

## Supported platforms

Supported: Linux and macOS, on amd64 and arm64. All four cells run the full
suite on every push and all four gate a release, so byte identity across the
matrix is a result rather than a claim.

Best-effort: Windows on amd64 and arm64. Binaries are built and the code
supports it, but its CI cell reports without gating and it is not a release
requirement.

Windows carries one stated limitation, and only one. Building from a **local
directory** on Windows records every regular file as `0644`, because Windows
reports no execute bit to normalize. A tree containing files that would be
executable on POSIX therefore produces a different subject digest there.

Nothing else is affected. Reading, verifying, copying, and expanding a bundle
from any platform is unaffected, and so are Git sources, whose modes come from
the commit tree rather than the filesystem. The CLI warns when it builds from
a path source on a platform that cannot observe the bit. See DP-035.

## Verifying these claims yourself

The `conformance` package is an independent reader built only from the Go
standard library and the format specification. It imports no other DevProof
package — not the media types, not the encoders, not the digest helpers — so
it can disagree with the main implementation, and a disagreement means one of
them is wrong.

Point it at any bundle to check that bundle against the specification rather
than against the code that produced it.
