# Test strategy

## Test objectives

Tests must demonstrate, rather than assume:

- deterministic identity across supported platforms;
- exact filesystem-to-OCI-to-filesystem-to-OCI round trips;
- closed-world source composition;
- descriptor and content verification;
- safe failure for hostile source and archive input;
- bounded behavior under partial network and filesystem failure;
- SDK and CLI behavioral parity; and
- compatibility of released format versions.

## Normative golden vectors

`internal/canonical/testdata/format/v1` holds the fixtures and expected:

- normalized file inventory;
- binary tree-record stream;
- tree digest;
- canonical config JSON and digest;
- uncompressed tar bytes and digest;
- gzip layer bytes and digest;
- OCI manifest JSON and digest; and
- expanded filesystem inventory.

At minimum, vectors cover:

1. one empty file;
2. text and arbitrary binary bytes;
3. nested directories;
4. executable and non-executable files;
5. multibyte NFC path names;
6. a path requiring deterministic PAX encoding;
7. multiple sources mounted at separate roots;
8. source and manifest order permutations; and
9. the largest values supported without crossing configured limits.

Golden bytes are immutable for a released format version. An intentional byte
change adds a new format-version fixture rather than updating v1 expectations.

## Determinism matrix

The same vectors run on three cells, and every cell gates:

| Cell | Runner | Covers |
| --- | --- | --- |
| `linux/amd64` | `ubuntu-latest` | the baseline |
| `linux/arm64` | `ubuntu-24.04-arm` | the architecture dimension |
| `darwin/arm64` | `macos-latest` | the operating-system dimension |

Four targets ship; three are tested. `darwin/amd64` is built and vetted on
every push but its suite is not run, because its architecture is covered by
`linux/amd64` and its filesystem by `darwin/arm64` — it only ever repeated what
two other cells already proved.

Architecture is the cheap dimension to be confident about here. Every integer
written into a canonical byte stream goes through an explicit
`binary.BigEndian` or `binary.LittleEndian`, and there is no cgo and no
`unsafe`, so native word order and alignment cannot reach the output. It is
tested anyway: "cannot" is a claim worth checking, and an arm64 Linux runner is
cheap.

The operating system is where the real differences are. APFS folds case and
ext4 does not, which is precisely what the path-collision rules exist to
handle, so a macOS cell earns its place on filesystem behavior rather than on
instruction set.

Each cell declares the platform it represents and asserts `go env GOARCH`
against it. A runner label alone is not self-describing — `macos-latest` is
arm64 — so a matrix that named only labels could silently cover half the cells
while reading as though it covered all of them.

Every cell also carries a job timeout. A retired runner label does not fail: it
queues forever with no runner ever assigned, which hangs the whole run instead
of reporting anything. `macos-13` did exactly that before it was replaced by
`macos-15-intel`.

Windows is not supported (DP-035). Every release target is additionally
cross-compiled and vetted on every push, so a platform-specific build tag fails
at push time rather than at release time.

Tests build each fixture at least twice with varied:

- source creation order;
- process umask;
- locale and time zone;
- working directory;
- source modification times and ownership where controllable;
- map and goroutine completion order;
- temporary root; and
- manifest YAML formatting and key order.

Every run must produce equal logical, layer, config, and manifest digests.

## Round-trip properties

For every valid fixture:

1. Build subject `A` from canonical source tree `T`.
2. Verify and expand `A` to new tree `T2`.
3. Compare canonical inventories for `T` and `T2`.
4. Build subject `B` from `T2` with the same format version.
5. Assert equal tree, tar, layer, config, and manifest digests for `A` and `B`.

Evidence is tested separately: a second build may produce different evidence
but it must bind to the same subject digest.

Property tests generate valid trees under configured bounds and repeat the same
round trip. Invalid-tree generators exercise normalization, collision, file
type, and limit rejection.

## Manifest and lock tests

Tests cover:

- YAML and JSON equivalence after typed normalization;
- duplicate and unknown field rejection;
- manifest and lock API version rejection;
- stable source and pattern set ordering;
- relative paths based on manifest location;
- stale local content, Git ref, commit, filter, mount, and resolver identity;
- no partial lock after multi-source failure;
- collision behavior independent of source ordering;
- lock replacement atomicity; and
- absence of credentials and absolute local paths from persisted data.

Each built-in resolver has contract tests shared with extension test helpers.

## Source resolver tests

### Local path

- file and directory roots;
- mutation during snapshot;
- symlink and hard-link attempts;
- permission denial and blocking reads;
- special files;
- include and exclude patterns;
- Unicode and case aliases;
- cancellation and cleanup; and
- locked tree mismatch.

### Git

- branch and tag resolution to exact commit;
- ref movement between lock and build;
- annotated and lightweight tags;
- unreachable commit and shallow-fetch fallback;
- repository and subpath filtering;
- executable bits from Git tree metadata;
- disabled hooks, submodules, and LFS materialization;
- authentication and authorization errors;
- host-changing redirects and credential isolation;
- truncated or interrupted fetch; and
- cancellation and private checkout cleanup.

Remote Git tests use local deterministic servers where possible. Tests requiring
external services are isolated and are not substitutes for hermetic contract
tests.

## Archive and expansion adversarial tests

Fixtures must include:

- absolute paths and every `..` form;
- slash and backslash confusion;
- duplicate entries;
- file/directory ancestor conflicts;
- symlink, hard-link, device, socket, and FIFO headers;
- case-fold and Unicode-normalization aliases;
- Windows reserved names and trailing spaces or periods;
- negative, overflowing, and inconsistent sizes;
- truncated headers and bodies;
- extra entries absent from config;
- missing entries declared by config;
- content, tree, layer, config, and manifest digest mismatch;
- gzip concatenation and trailing data;
- high compression ratio and total expanded size;
- excessive file count, path length, and directory depth;
- destination races and preexisting destinations;
- cancellation at each extraction stage; and
- cleanup failure joined with a primary failure.

Tests assert that no path outside the private staging root changes and no final
destination appears after failure.

## Fuzzing

These fuzz targets exist:

| Target | Package | What it asserts |
| --- | --- | --- |
| `FuzzExtractLayer` | `internal/safefs` | never panics on arbitrary layer bytes, and a failed extraction leaves no destination and no staging directory |
| `FuzzParseReference` | `pkg/artifact` | never panics, never yields both a tag and a digest, and is deterministic |
| `FuzzParseDigest` | `pkg/bundle` | an accepted digest round-trips to exactly one lowercase spelling |
| `FuzzFoldStringIsDeterministic` | `internal/canonical` | case folding is deterministic |
| `FuzzCanonicalizeJSONIsIdempotent` | `internal/canonical` | RFC 8785 canonicalization is idempotent |

`FuzzExtractLayer` is the one that matters most. Extraction is the only place
DevProof processes bytes it did not produce and has not yet proven anything
about: a registry can serve whatever it likes, and the layer reaches the tar
reader before any of it is trusted. A panic there is a denial of service in
anything embedding the SDK, where no process boundary absorbs it.

Not yet covered, and listed here rather than implied: selection-pattern
matching, manifest and lock decoding, policy decoding, tree-record decoding,
and credential redaction. Decoding is strict and rejects unknown fields, so the
decoders are lower risk than the extractor, but that is an argument about
priority rather than a substitute for a target.

Any crash, panic, hang, escape, or nondeterministic result becomes a permanent
regression corpus entry under `testdata/fuzz/`.

## OCI transport tests

Run contract tests against:

- local OCI image layout;
- a conformant local registry with referrers support;
- a registry path exercising the specified referrer-tag fallback;
- authentication and repository authorization boundaries;
- redirects with same-host and cross-host behavior;
- existing and moving tags;
- interrupted and retried blob upload;
- remote descriptor mismatch;
- concurrent attachment publication; and
- subject plus selected-referrer copy.

Tests verify that tags are assigned last and that no success result is returned
when remote verification or evidence attachment required by the request fails.

## Evidence and policy tests

- subject digest binding;
- valid and invalid DSSE envelopes;
- keyless, public-key, and KMS verification fixtures;
- issuer and identity exact and regular-expression matching;
- threshold counting and duplicate identity handling;
- transparency proof presence and absence;
- authenticated and unauthenticated time;
- expired certificates and policy age;
- provenance material and lock matching;
- allowed source host and type rules;
- malicious unrelated referrers;
- malformed matching evidence;
- missing evidence;
- offline trust roots;
- unknown and contradictory policy rules; and
- deterministic findings and policy digest.

No network-dependent public identity service is required for the main unit-test
suite. Recorded or locally generated verification material must cover offline
behavior.

## Failure and concurrency tests

Use injected dependencies to fail every meaningful I/O boundary before and
after partial progress. Confirm:

- primary errors are retained;
- cleanup errors are joined but do not replace the cause;
- retries occur only for classified transient errors;
- retry and concurrency bounds are respected;
- cancellation stops scheduling new work;
- goroutines, files, and transports are not leaked;
- multi-source results are ordered deterministically; and
- publication barriers prevent partial success reporting.

Run unit and integration packages under `go test -race`.

## SDK and CLI parity

CLI tests use an in-process SDK with controlled dependencies and assert:

- every command maps to a public SDK operation;
- stdout contains only result data;
- stderr contains diagnostics only;
- JSON schemas and exit codes match typed results and errors;
- help and version have no I/O side effects;
- non-interactive mode never prompts;
- secrets are redacted; and
- SIGINT returns the documented outcome after cleanup.

Examples in CLI help and documentation run as tests.

## Secret and license scanning

`make secrets` runs gitleaks over the working tree and the full history, and it
gates. Scanning only the working tree would miss the case that matters: a
secret committed and then removed is still published, because the object stays
reachable in the history, in every fork, and in every cache. The only version
of this check that helps runs before the push.

`make notices` regenerates `THIRD_PARTY_NOTICES.md` from the build graph, and
`make tidy` calls it, so a dependency cannot enter the binary without its
license being recorded.

## Release gates

A release candidate must pass:

```text
format golden vectors
unit and package tests
race detector
fuzz smoke corpus
round-trip property suite
registry and referrer integration suite
SDK and CLI contract tests
static analysis and formatting
dependency, vulnerability, and license checks
```

Format v1 cannot be declared stable until at least two separately implemented
read paths, or one implementation plus an independent conformance verifier,
agree on all normative vectors.
