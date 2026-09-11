# Design decisions

Status: accepted for the initial implementation unless listed under Open
decisions.

These decisions define the boundaries that implementation work must preserve.
Changing one requires an explicit design update and, after the first release,
a compatibility assessment.

## DP-001: SDK first, CLI second

All core operations are Go APIs. The CLI parses user input, constructs SDK
requests, renders SDK results, and maps typed errors to exit codes. Core logic,
registry operations, authentication policy, or filesystem mutation must not
exist only in a command handler.

Consequence: every documented CLI operation must be possible through a public
SDK call without invoking the CLI process.

## DP-002: Payload content defines subject identity

The OCI subject digest is derived only from:

- the canonical file paths, modes, sizes, and content digests;
- the deterministic layer encoding;
- the deterministic config and manifest encoding; and
- the DevProof bundle format version.

Names, source URLs, Git references, build timestamps, builders, signatures,
attestations, tags, and registry locations do not affect subject identity.

Consequence: equal canonical payloads have equal subject digests even when they
were assembled from different sources or by different builders.

## DP-003: Provenance is evidence attached to the subject

Source and build provenance is represented by signed or unsigned evidence that
names the immutable OCI subject digest. Evidence is stored as an OCI referrer or
in an offline OCI layout alongside the subject. It is not embedded in the
subject payload.

Consequence: evidence can be added, renewed, or copied without changing the
payload identity. Policy decides which evidence is required and trusted.

## DP-004: Intent and resolution are separate documents

`devproof.yaml` records user intent and may contain mutable references.
`devproof.lock.json` records immutable resolutions, source tree digests, file
ownership, and the final tree digest. A locked build fails if current material
does not match the lock.

Consequence: changing a branch, tag, URL response, local file, filter, mount
path, or resolver version requires an explicit lock refresh.

## DP-005: Version 1 uses a portable filesystem profile

The v1 payload supports regular files and implicit directories. It normalizes
file modes to `0644` or `0755`, directory modes to `0755`, and all ownership and
time metadata to fixed values. It rejects symlinks, hard links, devices,
sockets, FIFOs, path aliases, and case-fold collisions. Empty directories are
not represented.

Consequence: v1 does not preserve every native filesystem feature. A future
profile that adds a feature must use a new format version or a separately named
profile and cannot weaken extraction safety.

## DP-006: Version 1 is one standard gzip filesystem layer

A bundle is an OCI image manifest with a DevProof artifact type, one DevProof
config blob, and exactly one `tar+gzip` filesystem layer. The layer contains
only canonical payload files and their required parent directories.

Consequence: generic consumers can materialize one archive layer, while the
DevProof config provides the exact inventory required for verification.

## DP-007: Digests are authoritative; tags are pointers

Commands may accept a tag for discovery, but must resolve and report its digest
before use. Verification policy may require a digest reference. Results and
evidence always identify the subject by digest.

Consequence: a tag move does not change the identity of an already resolved
operation.

## DP-008: Expansion is staged and atomic

Expansion writes only to a newly created private staging directory. It verifies
every entry against the config inventory and publishes the completed directory
with a same-filesystem rename. The destination must not exist in v1.

Consequence: a failed, canceled, malicious, or incomplete extraction never
leaves a destination that looks successful.

## DP-009: Extensibility uses explicit Go registration

The SDK supports registered source resolvers, transports, attesters, and policy
evaluators. Registrations are supplied when constructing a client. V1 does not
load Go plugins, execute binaries discovered on `PATH`, or run code from a
bundle.

Consequence: applications can extend behavior while retaining dependency,
configuration, and trust control.

## DP-010: Integrity, trust, and semantics are distinct

Verification reports three independent dimensions:

- integrity: the OCI descriptors, config inventory, layer, and tree agree;
- trust: supplied evidence satisfies the selected verification policy;
- semantics: an optional caller-supplied validator accepts the payload.

Core verification never reports trusted merely because integrity passed. Core
verification never reports semantic correctness without a validator.

## DP-011: Source composition is closed-world

Every final payload path has exactly one source owner. Sources declare explicit
mount paths and filters. Collisions fail even when colliding files have equal
bytes. Source ordering does not affect output.

Consequence: overlays and replacement precedence are excluded from v1. They may
be introduced only with explicit manifest syntax and provenance recording.

## DP-012: No ambient or hidden inputs

Build output must not depend on current time, hostname, user identity, working
directory, locale, umask, filesystem enumeration order, Git configuration,
archive tool version, or registry response ordering. Any allowed dependency is
an explicit request value, resolved material, or format constant.

Consequence: implementations must inject clocks, credentials, clients, and
filesystem roots rather than reading process-global state in core packaging.

## DP-013: Network and credential behavior is explicit

Source resolution and registry operations have bounded timeouts, honor context
cancellation, and do not forward credentials across host-changing redirects.
Secrets are supplied through credential providers, environment variables,
standard credential stores, or protected files; never through ordinary CLI
flags or persisted lock data.

## DP-014: Verification fails closed on required evidence

An absent, malformed, unverifiable, expired, or policy-incompatible required
attestation is a trust failure. Unsupported policy fields and unknown policy
versions are errors rather than ignored input.

## DP-015: Format bytes are a compatibility surface

Canonical tree records, config JSON, tar headers, gzip headers, and OCI manifest
JSON are covered by fixed golden vectors. Refactoring or dependency upgrades
must not change those bytes for the same format version.

Consequence: improvements that change subject bytes require an explicit new
format version and coexistence rules.

## Open decisions

The following must be resolved before the corresponding implementation phase:

1. Exact Sigstore referrer media types and whether signatures and provenance use
   one or separate referrers.
2. Referrer-tag fallback behavior for registries without the OCI referrers API,
   including concurrency and copy semantics.
3. Default and maximum file count, expanded size, compressed size, path length,
   and compression-ratio limits.
4. Whether the first CLI release supports Windows or only guarantees that
   Windows produces and consumes the same portable format once supported.
5. Whether local source evidence records a user-supplied logical label only or
   may opt in to recording an absolute path.
6. Which semantic-validator interface is public in v1; no validator execution
   is required for the first bundle-format release.
