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

## DP-016: The DEFLATE encoder is frozen, not borrowed

`internal/canonical/deflate` contains a pinned copy of the Go standard
library's DEFLATE encoder. Format v1 compresses with that copy at level 9, not
with whatever `compress/flate` ships in the building toolchain.

The Go standard library does not promise byte-stable compressor output across
releases, and neither does any third-party encoder. DP-015 makes layer bytes a
compatibility surface and DP-002 derives subject identity from the encoded
layer, so an unfrozen encoder would let a toolchain upgrade silently change
every subject digest DevProof has ever produced.

Only the encoder is frozen. Decompression may use any correct DEFLATE
implementation, because inflation of a valid stream is unambiguous.

Consequence: upgrading Go does not change emitted bytes. Changing the frozen
encoder is a new bundle format version. The copy is not reformatted, relinted,
or refactored; its provenance and license are recorded in `NOTICE`.

## DP-017: Unicode tables are a format constant

Path canonicalization normalizes to NFC and enforces case-fold uniqueness.
Both depend on Unicode data tables that change between Unicode releases, and
both feed the tree digest. Format v1 therefore pins:

- Unicode 17.0.0, recorded in `.versions.yaml` under `specs.unicode`;
- NFC as defined by that version; and
- **simple** case folding, non-Turkic, per that version's `CaseFolding.txt`
  `C` and `S` entries.

Simple folding is specified rather than full folding because the rule exists
to model what a case-insensitive filesystem does, and no shipping filesystem
performs full folding. APFS, HFS+, and NTFS all use one-to-one mappings, so
full folding would reject `ß.txt` alongside `ss.txt` — a pair that coexists
perfectly well everywhere DevProof expands. Simple folding still catches every
pair those filesystems actually merge, including `ß`/`ẞ` and the Kelvin sign
against ASCII `K`.

Uniqueness is enforced with a canonical fold key — each rune mapped to the
lowest member of its `unicode.SimpleFold` orbit — rather than pairwise
comparison, so collision detection is a map lookup and cannot depend on the
order paths were visited.

Consequence: an implementation must pin both its normalization tables
(`golang.org/x/text/unicode/norm`) and its folding tables (the standard
library's `unicode` package), and assert their versions in a test. They are
separate data sets that can drift apart. A dependency or toolchain upgrade
that advances either is a format-version decision.

## DP-018: One organization identity, three spellings, all fixed

Two of these are compatibility surfaces and cannot drift:

```text
manifest and policy API group   devproof.thingz.io
OCI media type vendor tree      application/vnd.thingz.devproof.*
Go module path                  github.com/thingzio/devproof
```

The spellings differ because their namespaces have different rules, not by
accident: the API group is a DNS name, the media-type vendor tree follows the
`vnd.` convention, and the Go module path follows the repository host, where
`thingz.io` is not a legal organization name.

## DP-019: Tar and gzip header fields have exactly one legal value

Format v1 emits, for every entry:

```text
uid / gid        0
uname / gname    empty
mtime            0
atime / ctime    absent
linkname         empty
devmajor/minor   0
```

`atime` and `ctime` are omitted rather than written as epoch, because emitting
them requires PAX records that a USTAR-only reader would have to skip and that
add bytes to the subject for no information. "Epoch or absent" was ambiguous:
two conforming writers would have produced different subject digests for the
same tree.

A PAX extended header is emitted for exactly one reason: a path too long for
the 100-byte USTAR name field. It carries a single `path` record. No other
record, and no global header, may appear.

Two alternatives were rejected. The USTAR `prefix` field is never written,
because using it requires choosing where to split a path and two encoders that
split differently produce different bytes for the same tree. A PAX `size`
record is never written either; instead a file larger than the USTAR size
field can represent — eleven octal digits, one byte short of 8 GiB — is
rejected, and that bound is the ceiling for `maxFileBytes`. Supporting it would
have added a branch in the code that decides artifact identity which no test
could exercise without an 8 GiB fixture.

The extended header's own entry is named `PaxHeaders/<n>`, where `n` is the
zero-based ordinal of the entry it describes. A conforming reader never
interprets that name; deriving it from the ordinal rather than from the path
keeps it short, unique, and incapable of needing a PAX record itself. The
described entry's USTAR name field carries the path truncated to the longest
prefix of at most 100 bytes that ends on a rune boundary.

Padding is zero, exactly two zero blocks terminate the archive, and no bytes
follow them.

## DP-020: Resource limits have documented defaults and hard ceilings

```text
                        default        ceiling
files                   100000         1000000
file bytes              1 GiB          8 GiB - 1 B
expanded bytes          8 GiB          64 GiB
compressed bytes        2 GiB          16 GiB
compression ratio       200:1          1000:1
canonical path bytes    1024           4096
path segment bytes      255            255
path depth              64             256
config bytes            64 MiB         256 MiB
manifest bytes          4 MiB          4 MiB
spec bytes              1 MiB          16 MiB
lock bytes              16 MiB         64 MiB
referrers               256            4096
evidence bytes          16 MiB         64 MiB
parallel sources        4              64
```

Ceilings are refused at configuration time; defaults apply when a caller
supplies none. Segment length is capped at 255 bytes because that is the limit
most filesystems enforce, so a larger value would produce bundles that cannot
be expanded anywhere.

Limits are enforced against both declared sizes and actual streamed bytes. A
small declared size never disables the streaming check.

These numbers were guesses when they were written and are now measured. The
benchmarks in `benchmark_test.go` are the measurement, and what they establish
is that the limits are bounded by disk and time rather than by memory: build,
verify, and expand all allocate independently of payload size (DP-033). On an
Apple M3 Pro, an 80 MiB payload builds with a peak heap of roughly 17 MiB and
expands with roughly 240 KiB of allocation.

Without that property the 8 GiB expansion default would have been dishonest —
a limit a caller is invited to configure, but which their RAM would refuse
first.

## DP-021: Limits compose by intersection; the strictest value wins

Three inputs can bound one operation: the client's `Limits`, a per-request
`Limits`, and a verification policy's `spec.limits`. The effective value for
each bound is the minimum of those supplied, and the verification result
records which input supplied each effective value.

A policy may therefore tighten a bound but never relax one. This keeps a
policy from being usable as a privilege escalation against the embedding
application's own configuration.

## DP-022: Expansion stages beside the destination and publishes exclusively

The staging directory is created as a sibling of the destination, with mode
`0700`, so that publication is a same-filesystem rename. `WithTempRoot` does
not apply to expansion staging; it configures snapshot and layout scratch
space only.

Publication uses an exclusive rename — `renameat2(RENAME_NOREPLACE)` on Linux,
`renamex_np(RENAME_EXCL)` on macOS. Plain `rename(2)` silently replaces an
existing empty directory, which would let a destination that appeared between
the pre-flight check and publication be overwritten. Where no exclusive rename
is available the implementation must fail rather than fall back to a racy
rename.

The destination's parent directory is a trusted input. DevProof validates that
it is a real directory it can open, but a caller that stages into a
world-writable parent has already lost.

## DP-023: Exit codes are a coarse projection of error codes

The CLI maps every typed SDK code onto the documented exit codes:

```text
2   invalid-input, unsupported-version, unsupported-source
3   source-resolution, stale-lock, unsafe-path, unsupported-file,
    path-collision
4   digest-mismatch, invalid-artifact, destination-exists, limit-exceeded
5   evidence-invalid, policy-failed
6   authentication, authorization, transport, timeout
10  internal
130 canceled, when caused by SIGINT
```

Exit `1` is not in that table because no error maps to it. It is reserved for
the opposite case: a command that completed successfully and whose answer is
"no". Only `diff` returns it, when the two sides differ.

The distinction is worth the reserved code. A difference is not a failure —
the command did exactly what was asked — and collapsing the two would mean a
script branching on "they differ" could not tell that case from a registry
timeout. `diff`, `grep`, and `git diff --exit-code` all made the same choice.
`TestExitCodeNeverReturnsOne` keeps `1` unreachable from any error code, so
the two can never blur.

`limit-exceeded` maps to `4` because a limit is a property of the artifact
being constructed or consumed. `timeout` maps to `6` because every bounded
operation that can time out is a network or registry operation. Programmatic
cancellation that did not come from SIGINT reports `canceled` in JSON and uses
the exit code of the operation it interrupted.

The JSON envelope always carries the finer code. Exit codes stay coarse so
shell callers can branch on them stably.

## DP-024: Provenance uses a DevProof predicate, not bare SLSA

Evidence carries predicate type
`https://devproof.thingz.io/provenance/v1`. It embeds a SLSA Provenance v1
document unchanged and adds a DevProof section recording the manifest digest,
lock digest, per-source resolution and filtered tree digest, resolver
identities, and bundle format version.

Neither substitution worked alone: SLSA v1 has no field that means "lock
digest" or "per-source canonical tree digest", so a policy rule like
`requireLockDigest` would have had to read them out of `internalParameters` by
convention. Discarding SLSA would have given up every existing consumer of
SLSA provenance.

A policy may require either predicate type. When a policy requires SLSA v1, the
embedded document satisfies it.

## DP-025: Local sources are named by label, never by absolute path

Evidence for a `path` source records the manifest-relative path or a
caller-supplied logical label, plus the filtered tree digest. It never records
an absolute path, and there is no opt-in to change that in v1.

The tree digest already identifies the material exactly. An absolute path adds
no verifiable fact and discloses workstation or build-agent structure to
everyone who can read the published evidence.

## DP-026: The semantic validator interface stays internal in v1

`Validator` is defined but unexported. `verify` and `expand` report
`semantics: not-evaluated` unless an embedding application supplies one
through an internal seam.

A public interface is a permanent compatibility obligation, and DevProof does
not yet have two real validators to prove the shape is right. Keeping it
internal costs nothing: no v1 operation requires validator execution.

Consequence: the interface may be promoted in a later minor release without a
format change. It may not be narrowed once exported.

## DP-027: One referrer carries one signed statement

Signatures and provenance are one referrer, not two. A referrer is a DSSE
envelope containing an in-toto Statement, stored with these media types:

```text
artifact type: application/vnd.thingz.devproof.evidence.v1
blob:          application/vnd.dev.sigstore.bundle.v1+json
```

Splitting them would mean a signature object that names a provenance object
that names the subject, and a consumer would have to decide what an
unsigned-but-present provenance means, or a signature whose statement is
missing. One object with one subject binding has one answer: it verifies or it
does not.

The artifact type identifies DevProof evidence so that referrer discovery can
filter before fetching. The blob media type is the Sigstore bundle type so
that generic Sigstore tooling can read what DevProof writes.

## DP-028: Referrer-tag fallback is explicit and reported

Where a registry has no referrers API, evidence is stored under a tag derived
from the subject digest:

```text
sha256-<hex>.evidence
```

That is one tag for one subject, so two evidence objects for the same subject
under a fallback registry overwrite each other rather than accumulating. A
registry without the referrers API cannot express a set, and pretending
otherwise — by appending an index, say — would make "which evidence exists"
depend on a read-modify-write race that has no locking.

The consequence is reported rather than hidden. A verification result records
which storage mode was used, and a policy may refuse the fallback entirely.
An operation that needs to attach a second evidence object to a subject on a
fallback registry fails rather than silently replacing the first.

## DP-029: Keyless signing works out of the box

`evidence.Attester` and `evidence.Verifier` are interfaces, and the module
ships two implementations of each: Sigstore keyless, and a local ECDSA or
Ed25519 key.

Keyless is included rather than left to an embedding application even though
it brings a large dependency tree — TUF, Rekor, Fulcio, protobuf. The
alternative was an SDK where the default signing story required a caller to
assemble it themselves, and a supply-chain tool whose batteries are sold
separately is one most people will use unsigned. The cost is dependency
weight; the benefit is that `--sign` works with nothing configured on a CI
runner that already has an OIDC token.

"Works with nothing configured" was not true when it was written. Ambient
detection only read SIGSTORE_ID_TOKEN, and GitHub Actions does not set it — it
provides a URL and a request token that must be exchanged for an identity token
at a specific audience. So the one CI system this claim was made about was the
one where it failed, and the post-merge keyless job is what found it. The
exchange is implemented now, and the claim is true.

The local-key attester stays for air-gapped builds, tests, and callers who
already manage keys, and because it is the implementation that proves the
interface is not shaped around one provider.

Trust material comes from the Sigstore TUF root by default, refreshed and
cached, or from a caller-supplied trusted root for offline verification.
Neither path lets an artifact influence the trust material used to judge it.

Policy is written against a verified identity — either a key identifier or an
OIDC issuer and subject — so the same rules apply whichever attester produced
the evidence.

Consequence: a caller who signs with a local key still pays for the Sigstore
dependency tree at build time. That is the trade, taken deliberately. If it
becomes a problem, the split is a separate module, not a change to these
interfaces.

## DP-030: Configuration cannot name an artifact

The CLI resolves settings in one order: a command-line flag, then a
`DEVPROOF_`-prefixed environment variable, then the configuration file, then
the built-in default.

The order is conventional and the alternatives are each worse. A file that
overrode a flag would make a one-off override impossible. An environment
variable that overrode a flag would let a CI runner's ambient settings
silently win over what a script explicitly asked for.

The file holds only settings that are safe to persist: output format,
diagnostic level, timeout, and the trust material and policy to apply. It
cannot name a reference, a destination, or a tag. A configuration file that
could change *which* artifact a command acted on would make the same command
line mean different things on different machines, and would turn a file into
part of an artifact's attack surface.

For the same reason the file is read from the per-user configuration directory
and never from the working directory. A file discovered by walking upward
would mean that cloning a repository and running a command inside it could
change what that command does.

Decoding is strict: an unknown key is an error. A misspelled setting is one
that silently does not apply, and the failure surfaces much later as behavior
nobody can explain.

A configured policy can only make verification stricter. There is no setting
that relaxes it, because a file that could turn integrity checking off would
be the most valuable file on the machine to an attacker.

## DP-031: Registry credentials come from the Docker configuration

The CLI resolves credentials from `~/.docker/config.json` — the `auths`
entries, `credHelpers`, and `credsStore` — rather than defining its own
credential store.

`docker login` is what every operator and CI runner has already run, and a
tool that required a second, parallel login would mostly be used
unauthenticated. Credential helpers are included because that is how cloud
registries issue short-lived tokens; leaving them out would exclude ECR, GCR,
and every other helper-based registry.

Lookup is by host, and a host with no entry gets anonymous access rather than
an error: public registries exist, and failing closed here would make an
unauthenticated pull impossible on a machine that has never logged in.

A credential is never offered to a host other than the one it was stored for,
which is DP-013 applied to the CLI's own resolution: matching is on the full
host, so neither a suffix nor a prefix of a configured registry attracts its
credential.

Helper results are cached per host for the process lifetime. A helper reaches
the network, and a push touching one registry a few hundred times must not run
a few hundred subprocesses.

## DP-032: A gated expansion writes nothing when the policy fails

`Expand` accepts a policy and evaluates it before extracting. An unsatisfied
policy produces no destination at all.

The alternative — extract, then evaluate, then clean up — was rejected because
content that is written and later removed has already been readable by
anything watching the directory. Cleanup is not the same guarantee as never
having written it, and the entire reason to gate an expansion is that
untrusted content must not reach the filesystem.

This also closes a gap where the CLI accepted `--policy` on `expand` and
silently ignored it, which advertised a gate that did not exist. A flag that
claims to enforce something and does not is worse than no flag: it produces
confident, unfounded trust.

Verification remains three-dimensional here as everywhere else. Without a
policy, expansion still checks integrity and reports trust as not-evaluated
rather than as passing.

## DP-033: Memory is independent of payload size

No operation holds a payload-sized buffer. Build stages the encoded layer to an
unlinked temporary file, the layout transport hashes and writes blobs as they
stream, copy streams from source to staging to destination, and expansion has
streamed since it was written.

This is a correctness property, not a performance one. The default limits allow
an 8 GiB expansion and a 2 GiB compressed layer. If memory tracked payload
size, those numbers would be fiction: the real limit would be the caller's RAM,
it would differ on every machine, and it would be discovered by being killed
rather than by a typed error. A limit the caller configures should be bounded
by what they configured.

Content-addressed storage cannot name a blob before it knows its digest, so the
bytes must all exist before the manifest does. That constrains *ordering*, not
*residency*, and the two were conflated in the first implementation: the layer
was accumulated with `append`, which allocated roughly seven times the payload
and peaked at about twice it.

The staging file is unlinked immediately after it is created. Nothing opens it
by name, so removing the directory entry means a crash cannot leave scratch
behind and no other process can observe or substitute it.

The staged layer is handed to transports as a reader exposing nothing but
`Read`. Passing the `*os.File` directly let a transport see an `io.Closer` and
close a file it did not open, taking it away from its owner before the next
blob was pushed, and let `net/http` reach for `sendfile`, which is unavailable
in some sandboxed environments. Neither is the transport's decision.

`TestBuildMemoryDoesNotScaleWithPayload` measures bytes allocated rather than
allocation count, because buffering a payload changes how much is allocated
while barely changing how many times.

## DP-034: The conformance reader shares no code with the writer

`conformance` is a second implementation of the read side, built only from the
Go standard library and the format specification. It imports no other DevProof
package: not the media-type constants, not the canonical encoders, not the
digest helpers. Every value it compares against is transcribed from the
specification, and every structure it parses it parses again from scratch.

A test that checks a writer against its own reader proves only that the two
agree. If both share a constant, a sort order, or an encoding helper, they
share its bugs, and a round trip passes while the artifact is unreadable by
anyone else. The whole value of this package is that it *can* disagree.

It earned its place immediately: it found that the specification's description
of tar entry order did not match what the encoder produced. The encoder emits
every required directory in sorted order and then every file in sorted order;
the specification described a single merged path order. The specification was
corrected rather than the encoder, because both schemes are deterministic and
both put every parent before its first child, while changing the encoder would
have altered every layer digest ever produced.

It is deliberately simple and unoptimized. It buffers where a streaming reader
would not, because being obviously correct matters more here than being fast,
and a second implementation clever enough to be wrong in the same way as the
first has no value.

## DP-035: POSIX only; Windows is out of scope

Supported platforms are Linux and macOS on amd64 and arm64 — four shipped
targets, three tested cells: `linux/amd64`, `linux/arm64`, and `darwin/arm64`.
All three gate a merge and a release, which is what makes "byte-identical
across the matrix" a result rather than a claim.

Three rather than four because the cells cover dimensions, not combinations.
Architecture cannot reach canonical bytes — every integer written into one goes
through an explicit byte order, with no cgo and no `unsafe` — and it is tested
anyway on Linux arm64 because the claim is worth checking. The operating system
genuinely can reach them, through case-folding and filesystem semantics, which
darwin/arm64 covers. `darwin/amd64` is the intersection of two dimensions both
already covered, and it was the cell whose runner label kept being retired.

Arch-specific runners were never needed to *build*: goreleaser cross-compiles
every target from one machine. They buy running the tests there, and nothing
else, which is why the question is what each one can catch.

Naming the runner label alone was not enough: `macos-latest` is arm64 and
`ubuntu-latest` is amd64, so a matrix listing only those two silently covered
half the cells while reading as though it covered all of them. Each cell now
declares the platform it represents and asserts `go env GOARCH` against it, so
a label that changes architecture fails loudly instead of quietly dropping
coverage.

Windows is not supported, and `exclusiveRename` refuses to run there rather
than falling back to something racy (DP-022).

Windows support was built and then removed. It worked, and the cost was not the
building — it was that every guarantee this project makes had to be re-proven
against a filesystem with different rules, and each one had to be discovered
through a CI round trip because it could not be run locally. Unlinking an open
file, renaming a directory while a handle is open, POSIX permission bits,
reserved device names: four separate mechanisms, each needing its own
platform-specific branch and its own justification for why the weaker guarantee
was acceptable.

For a tool whose value is that it behaves identically everywhere, carrying a
platform where several guarantees are merely approximated is a poor trade.
Windows users reach this through WSL, where every guarantee holds exactly as
written, and that path needs no code at all.

One thing from the attempt is kept: a colon only introduces a tag when nothing
after it is a path separator, counting backslashes as separators. That was
found because a Windows drive letter parsed as a tag, but the rule is correct
independent of platform — a backslash is a legal filename character on Linux,
and an OCI tag cannot contain a separator, so anything that does was never a
tag.

## DP-036: Everything the CLI can do, the SDK can do

DP-001 said the CLI is a thin adapter over the SDK. That was true of the
operations and false of two things underneath them, both found by auditing the
public surface rather than by reading the intent.

**The typed error model is public.** `Error` and `Code` were aliased out of
`internal/fault`, which works for reading an error and fails for producing
one. The extension points are public: a custom `source.Resolver`, transport,
or attester returns errors into the same pipeline the built-in ones do, and an
error that is not a `fault.Error` classifies as `CodeInternal` — exit 10,
"unexpected internal error". An extension that could not construct a
classified error would report every missing file and refused credential as a
bug in DevProof. `pkg/fault` exports `New` and `Wrap` so it can.

It also fixes the documentation: an alias into `internal/` renders on
pkg.go.dev as a link nobody can follow, so the fields of the primary error type
were undiscoverable.

**Docker credential resolution is public.** It was three hundred lines inside
the CLI — configuration parsing, credential helpers, the token sentinel, host
scoping, caching — implementing a public interface that no SDK caller could
reach. A program embedding the SDK had to reimplement all of it to push to a
registry the operator had already logged in to, which is the same "batteries
sold separately" failure that DP-029 rejected for signing. It is
`pkg/credentials` now, taking an `slog.Logger` rather than the CLI's printer,
because a library that wrote to stderr on its own would be unusable in a
server.

What stays in the CLI is what has no meaning without a terminal: flag parsing,
output rendering, stream discipline, progress, and the configuration file.
Those are not capabilities, they are presentation.

Consequence: a capability that exists only in `internal/cli` is a bug, not a
layering choice. The test for whether something belongs there is whether an
embedding application would ever want it, not whether the CLI currently owns
it.

## Open decisions

None. Every decision needed for format v1 is recorded above.
