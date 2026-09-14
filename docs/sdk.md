# Go SDK design

## API status

These APIs ship. The module is `v1alpha1` and, until 1.0, a minor version may
carry a breaking change; see [compatibility](compatibility.md).

Where this document and the code disagree, the code is right and this document
is a bug.

## Principles

- The SDK owns every operation available through the CLI.
- Every operation that can block or perform I/O accepts `context.Context`.
- Requests and results are typed; core packages do not accept CLI flag maps.
- Dependencies and extensions are explicit client construction options.
- Core methods return errors and never call `os.Exit`, print, prompt, or open a
  browser.
- The client is safe for concurrent operations after construction.
- Results are complete or failed. Partial state is represented only in a typed
  error's diagnostic details, never as a successful artifact.
- Secrets and mutable byte slices are not retained longer than required.

## Top-level client

The root package provides the stable facade:

```go
package devproof

type Client struct {
    // private immutable dependencies and bounded shared resources
}

func New(opts ...Option) (*Client, error)
func (c *Client) Close() error

func (c *Client) Lock(ctx context.Context, req LockRequest) (*LockResult, error)
func (c *Client) Build(ctx context.Context, req BuildRequest) (*BuildResult, error)
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*policy.Report, error)
func (c *Client) Expand(ctx context.Context, req ExpandRequest) (*ExpandResult, error)
func (c *Client) Diff(ctx context.Context, req DiffRequest) (*DiffResult, error)
func (c *Client) Copy(ctx context.Context, req CopyRequest) (*CopyResult, error)
func (c *Client) Inspect(ctx context.Context, req InspectRequest) (*InspectResult, error)
```

A starter manifest comes from `bundle.Template`, which returns the commented
document `devproof init` writes. It is a package function rather than a client
method because it performs no I/O and needs no configuration.

`Close` releases client-owned transports, credential providers, and caches. It
does not remove caller-owned artifacts or output directories. Calls after
`Close` return a typed invalid-state error.

## Construction options

```go
WithLimits(Limits)                          // bounds, intersected with policy
WithResolver(source.Resolver)               // an additional source type
WithAbsolutePathSources()                   // allow absolute local paths
WithTransport(artifact.Transport)           // an additional reference scheme
WithRegistryCredentials(credentials.Provider)
WithInsecureRegistry()                      // plain HTTP; warns
WithOffline()                               // refuse anything that needs the network
WithSigstore(evidence.SigstoreOptions)      // keyless signing and verification
WithAttester(evidence.Attester)             // sign with something else
WithVerifier(evidence.Verifier)             // verify with something else
WithTrustRoots(...[]byte)                   // trust material for verification
WithTempRoot(string)                        // scratch space for snapshots
WithClock(Clock)                            // evidence and diagnostics only
WithLogger(*slog.Logger)
```

There is no option to replace the verification-policy evaluator, and that is
deliberate. Signing and transport have two implementations each, which is what
proved those interfaces were shaped around the contract rather than around one
provider; trust evaluation has one, and exporting an interface for it now
would be a permanent compatibility obligation taken on a guess (DP-026 makes
the same argument about the semantic validator).

The seam that domain-specific rules actually want is the semantic validator,
which judges payload *meaning*. Trust evaluation asks who signed this and do I
accept them, which is the same question in every domain.

Construction validates duplicate extension names and incompatible
dependencies. There is no mutable global extension registry.

Defaults must be safe and deterministic. The clock is used for evidence and
diagnostics only; canonical artifact code has no clock dependency.

## Source resolver contract

```go
package source

type Resolver interface {
    Type() string
    Identity() ResolverIdentity
    Resolve(context.Context, ResolveRequest) (Snapshot, error)
}

type ResolverIdentity struct {
    Name    string
    Version string
}

type ResolveRequest struct {
    Name       string
    Config     json.RawMessage
    SubPath    string
    Include    []string
    Exclude    []string
    BaseDir    string
    Locked     *LockedSource
    Limits     Limits
}

type Snapshot interface {
    Material() Material
    Records() []bundle.FileRecord
    Open(context.Context, bundle.Path) (io.ReadCloser, error)
    Close() error
}
```

Every type here is public. That is load-bearing rather than tidy: this
interface previously returned types under `internal/`, which Go forbids an
external module from naming, so a resolver could be described and registered
and never actually written by anyone outside this repository. A module under
`internal/repo/testdata` implements the contract and is compiled by the test
suite, because no test inside this module could have caught it.

`Files` returns source-relative canonical records in sorted order. Returned
slices are immutable from the caller's perspective. `Open` accepts only a path
previously returned by `Files` and reads from frozen snapshot storage.

`Material` contains public provenance facts, never credentials. A resolver must
verify a supplied `LockedSource` or return a stale-lock error.

The SDK closes every successfully returned snapshot exactly once, including on
later failure or cancellation. A resolver remains responsible for cleaning up
state created before `Resolve` returns.

## Artifact transport contract

```go
package artifact

type Transport interface {
    Scheme() string
    Resolve(context.Context, Reference) (Descriptor, error)
    Fetch(context.Context, Descriptor, Store) error
    Publish(context.Context, PublishRequest) (*PublishResult, error)
    Referrers(context.Context, Descriptor, ReferrerQuery) ([]Descriptor, error)
    Attach(context.Context, AttachRequest) (*Descriptor, error)
    Close() error
}
```

A `Reference` distinguishes a mutable tag from an immutable digest. `Resolve`
returns one frozen descriptor. Later fetches in the same operation use the
descriptor, not the original tag.

`Publish` accepts a locally frozen OCI store and subject descriptor. It uploads
content by digest, verifies the remote manifest descriptor, and assigns any tag
last. A successful result includes the canonical digest reference and reports
whether a tag was assigned.

`Attach` may mutate a referrer index or fallback tag but must never mutate the
subject. Implementations report referrer discovery capabilities explicitly.

## Evidence contract

```go
package evidence

type Attester interface {
    Name() string
    Attest(context.Context, AttestRequest) (*Statement, error)
}

type AttestRequest struct {
    Subject    artifact.Descriptor
    SpecDigest bundle.Digest
    LockDigest bundle.Digest
    Materials  []source.Material
    Builder    Builder
}
```

The service constructs the canonical statement. An attester provides signing
identity and returns a verifiable envelope or Sigstore bundle. Attesters do not
receive registry credentials unless the same explicitly configured provider is
intended for both roles.

An unsigned provenance statement is a supported evidence object but never
satisfies a policy requiring an authenticated identity.

## Policy contract

```go
package policy

func Evaluate(doc *Document, input Input) *Report

type Input struct {
    SubjectDigest           string
    Format                  bundle.Format
    SuppliedDigestReference bool
    FileCount               int64
    TotalBytes              int64

    Evidence []VerifiedEvidence
    Rejected []RejectedEvidence

    EvaluatedAt time.Time
}
```

A function rather than an interface, for the reason in the construction
options above: one implementation is not enough to know what an exported
interface should look like.

Only cryptographically verified evidence reaches `Evidence`. Candidates that
failed verification are in `Rejected`, separately, so that "the policy was not
satisfied" and "somebody attached junk to this repository" stay
distinguishable and neither can be mistaken for the other. The evaluator has
no access to unverified claims at all; that is a structural guarantee rather
than a rule it follows.

Evaluation is deterministic for a given document, subject, evidence set, and
evaluation time. When a time-dependent rule is used, the result records the
time it used.

## Semantic validator contract

A semantic validator is optional and supplied by the embedding application:

```go
type Validator interface {
    Name() string
    Validate(context.Context, fs.FS, ValidationContext) (*ValidationReport, error)
}
```

The filesystem is a verified, read-only view. The SDK does not discover a
validator inside the artifact and does not execute payload files. Validators
return stable rule identifiers, severity, paths, and messages.

**Not implemented.** No validator type exists in the module, exported or
otherwise, and `semantics` is reported as `not-evaluated` unconditionally. The
sketch above is a design, not a contract — see
[the proposal](proposals/semantic-validation.md) and DP-026.

## Operation requests

### Lock

`LockRequest` contains manifest bytes or a manifest path, its base directory,
an optional existing lock for comparison, an output writer or path, and source
resolution options. It cannot specify an OCI destination or signing mode.

`LockResult` contains the typed lock, exact canonical bytes, manifest digest,
lock digest, and whether an existing lock matched.

### Build

`BuildRequest` contains either:

- a manifest plus a matching lock; or
- one direct source from which the SDK synthesizes a manifest and lock.

It also contains the destination, optional tag, evidence settings, and limits.
Locked manifest builds do not refresh locks implicitly.

`BuildResult` contains:

- subject descriptor and canonical digest reference;
- tree, config, layer, and manifest digests;
- file count and byte totals;
- generated lock and lock digest for direct mode;
- published evidence descriptors;
- registry capability facts; and
- warnings with stable codes.

### Verify

`VerifyRequest` contains a reference or local OCI layout, optional policy,
trust roots, evidence-selection rules, and resource limits. It does not require
an expansion destination.

Verify returns a [`policy.Report`](../schemas/proof-report.v1.schema.json)
rather than a type of its own: the result of a verification is the proof
report, and a second type wrapping it would be a second thing to keep in step.
It carries separate integrity, trust, and semantic status values, the resolved
subject digest, the accepted signer identities and the evidence they signed,
the policy digest and trust-root digests, the effective limits, and the
findings.

The absence of a policy produces `trust: not-evaluated`, not `pass`.

### Expand

`ExpandRequest` contains the subject, destination, verification policy, trust
roots, and resource limits. It has no overwrite option in v1.

A supplied policy is evaluated before extraction, and an unsatisfied policy
writes nothing at all. Content that is written and then removed has already
been readable by anything watching the directory, so cleaning up afterwards is
not the same guarantee as never having written it (DP-032).

`ExpandResult` is returned only after atomic publication. It contains the
subject and tree digests, destination, file count, byte total, and verification
summary.

### Diff

`DiffRequest` names two operands. Each is either an OCI reference — anything
carrying a `://` scheme — or a path to a local directory, which is
canonicalized through the same composition path a build uses.

`DiffResult` reports each side's tree digest, kind, and file count, an
`Identical` flag derived from the tree digests, and the changed paths sorted
by canonical path. Each change is classified `added`, `removed`, `modified`,
or `mode-changed`, and carries both sides' mode, size, and digest so the
classification can be checked rather than trusted.

`Identical` and an empty change list always agree, because the tree digest is
a function of exactly the paths, modes, sizes, and content digests the
comparison walks.

Differences are not an error: `Diff` returns a result. The CLI is what turns
that result into exit 1.

### Inspect

`InspectRequest` reads metadata and evidence without expanding payload content.
It may optionally verify blob descriptors. The result clearly marks facts that
were parsed, digest-verified, signature-verified, and policy-accepted.

## Error model

Public operations return an error that can be inspected with `errors.Is` and
`errors.As`:

```go
type Error struct {
    Code      Code
    Op        string
    Source    string
    Path      string
    Temporary bool
    Err       error
}
```

Stable initial codes include:

```text
invalid-input
unsupported-version
unsupported-source
source-resolution
stale-lock
unsafe-path
unsupported-file
path-collision
limit-exceeded
digest-mismatch
invalid-artifact
authentication
authorization
transport
evidence-invalid
policy-failed
destination-exists
timeout
canceled
internal
```

Messages identify the failed operation and safe next action. They do not expose
tokens, embedded credentials, private-key material, or full sensitive URLs.

Multi-source failures retain a primary error and an ordered list of additional
source errors. `Temporary` is advisory for callers; the SDK itself retries only
under its bounded retry policy.

## Resource ownership

- Caller-provided readers and writers remain caller-owned unless a type
  explicitly implements a documented transfer-of-ownership contract.
- SDK-created snapshots, temporary directories, registry transports, and file
  handles are SDK-owned and closed on all paths.
- Result byte slices and collections are caller-owned copies.
- A failed operation removes private staging state when possible and joins a
  cleanup error without hiding the primary failure.

## Compatibility

The Go module follows semantic versioning after its first stable release.
Public interfaces are kept small because adding a method breaks external
implementations. Capability additions should prefer optional subinterfaces or
new request fields with safe zero values.

Format compatibility and Go API compatibility are versioned independently. A
new SDK may continue emitting format v1, and format v2 support does not require
removing v1 readers.
