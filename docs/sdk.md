# Go SDK design

## API status

The APIs in this document are proposed implementation targets, not a released
compatibility promise. The first implementation should preserve the operation
boundaries even if individual Go names change during development.

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
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error)
func (c *Client) Expand(ctx context.Context, req ExpandRequest) (*ExpandResult, error)
func (c *Client) Inspect(ctx context.Context, req InspectRequest) (*InspectResult, error)
```

`Close` releases client-owned transports, credential providers, and caches. It
does not remove caller-owned artifacts or output directories. Calls after
`Close` return a typed invalid-state error.

## Construction options

Expected options include:

```go
WithResolver(source.Resolver)
WithTransport(artifact.Transport)
WithAttester(evidence.Attester)
WithPolicyEvaluator(policy.Evaluator)
WithCredentialProvider(auth.Provider)
WithLogger(*slog.Logger)
WithTracer(trace.TracerProvider)
WithTempRoot(string)
WithMaxParallelSources(int)
WithLimits(Limits)
WithClock(Clock)
```

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
    Files() []File
    Open(context.Context, string) (io.ReadCloser, error)
    Close() error
}
```

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
    Subject       artifact.Descriptor
    ManifestDigest digest.Digest
    LockDigest     digest.Digest
    Materials      []source.Material
    Builder        Builder
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

type Evaluator interface {
    Evaluate(context.Context, Input) (*Report, error)
}

type Input struct {
    Subject    artifact.Descriptor
    Integrity IntegrityFacts
    Evidence  []VerifiedEvidence
    Policy     Document
}
```

Only cryptographically verified evidence enters `VerifiedEvidence`. Invalid
candidate evidence is retained separately in diagnostics so a policy cannot
accidentally treat parsed but unauthenticated claims as facts.

Policy evaluation is deterministic for a supplied subject, evidence set,
policy, trust roots, and evaluation time. When time constraints are used, the
result records the evaluation time.

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

The initial implementation may keep this interface internal until two real
validators establish the required public contract.

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

`VerifyResult` contains separate integrity, trust, and semantic status values,
the resolved subject digest, verified evidence identities, policy digest,
findings, and warnings.

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
