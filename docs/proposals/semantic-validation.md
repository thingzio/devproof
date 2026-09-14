# Proposal: semantic validation

**Status: proposed. Nothing described here is implemented.**

This document is a design, not a contract. Every other document under `docs/`
describes what ships; this one describes what does not. It is here rather than
in a notebook because the gap it closes is recorded in the decision log as
though it were already closed.

## The problem

`Semantics` is one of three dimensions every result carries, and it is
hard-coded to `not-evaluated` in both places it is ever set. There is no
validator type anywhere in the module — not exported, not unexported, not in
`internal/`.

DP-026 says otherwise:

> `Validator` is defined but unexported. `verify` and `expand` report
> `semantics: not-evaluated` unless an embedding application supplies one
> through an internal seam.

Neither the type nor the seam exists. The decision record describes an
implementation that was never written, and it is the load-bearing justification
for why the third dimension never has an answer. The SDK reference compounds it
with an interface sketch and a hedge about keeping it internal "until two real
validators establish the required public contract" — reasonable, except there
is nothing to keep internal.

So this is not a promotion of an existing seam. It is writing the thing the
repository already claims to have.

### Why it matters more than a missing feature

The three-dimension split is the central design idea: integrity asks whether
the bytes survived, trust asks who vouched for them, semantics asks whether the
content is valid for the consumer's use. Two of those are implemented. The
third is the one that makes the other two safe to report — it is what stops
`integrity: pass, trust: pass` from being read as "this artifact is fine".

It is also the only way a domain layer adds meaning without the core learning a
schema. Without it, a domain-neutral substrate has no place to put domain
knowledge, and every consumer either forks or re-implements verification
alongside DevProof rather than on top of it.

The firmware example states the consequence precisely, and today it is
permanent rather than temporary:

> Verifying *what a document says* would need a firmware schema, a
> required-component set, and a comparison against observed rack inventory —
> none of which is here, and the first of which DevProof deliberately does not
> define.

## Constraints this design does not get to relax

These come from decisions already made, and a design that violated one would be
changing that decision rather than implementing this one.

| Constraint | Source |
| --- | --- |
| `not-evaluated` is never `pass`; a dimension nobody checked cannot satisfy a requirement | DP-014 |
| Nothing is discovered from the artifact — not a policy, not a validator, not a hook | DP-014, security model |
| Payload content is never executed | Security model, "never execute payload content" |
| An unsatisfied gate publishes nothing, rather than publishing and retracting | DP-032 |
| Every bound that applied is recorded, with its origin | DP-021 |
| A result names what judged it | established by `policyDigest`, `policyName`, `trustRoots` |
| The core learns no domain schema | the product thesis |

## Shape

### The interface

```go
// Validator decides whether a verified payload is valid for the caller's use.
type Validator interface {
    // Name identifies the validator in results. Stable, because a report
    // names what judged it.
    Name() string

    // Validate examines a read-only view of the verified payload.
    Validate(context.Context, fs.FS, Subject) (*Verdict, error)
}

// Subject is what verification already established, so a validator does not
// re-derive it.
type Subject struct {
    Digest     string // the OCI subject digest
    TreeDigest string
    Format     string
    Files      []FileRecord // path, mode, size, content digest
}

// Verdict is what a validator concluded.
type Verdict struct {
    Findings []Finding // reuses the report's finding type
}
```

`fs.FS` rather than a path: it is read-only by construction, it cannot be
escaped with `..`, and it lets a validator be tested against `fstest.MapFS`
with no artifact at all.

`Subject` carries the inventory because the most useful validators — is every
required component present, does any file exceed a size, is the set complete —
need paths and digests and never open a file. A validator that needs only the
inventory should not pay for materialization.

### When it runs

Only when a caller supplies one. No validator means today's behaviour, byte for
byte: `semantics: not-evaluated`, nothing materialized, no cost.

- **`verify`** — the payload is already fetched and hashed. A validator that
  reads content requires materializing it to a private staging directory, which
  `verify` does not do today. That cost is paid only by callers who asked.
- **`expand`** — the payload is being written anyway. Validation runs against
  the staged tree **before** publication, so a semantic failure publishes
  nothing, exactly as a policy failure does (DP-032).

### Fail-closed rules

| Situation | `semantics` |
| --- | --- |
| No validator supplied | `not-evaluated` |
| Every validator returns no error findings | `pass` |
| Any validator returns an error finding | `fail` |
| A validator returns an error | `fail` |
| A validator panics | `fail`, recovered and reported as an internal finding |

A validator that *errors* yields `fail`, not `not-evaluated`. The distinction
matters: `not-evaluated` means nobody looked, and somebody looked and could not
finish. Treating a crashed validator as "not evaluated" would make a broken
validator indistinguishable from an absent one, which is the failure mode that
makes a gate decorative.

Recovering a panic is not defensive programming for its own sake. A validator
is third-party code running inside a verification, and a panic that killed the
process would turn a content check into a denial of service against the tool
that invoked it.

### Composition

A list, not a single validator. `semantics` is `pass` only if every one passes.
A domain will have a schema validator and a completeness validator and they are
not one thing; forcing them together would push composition into the domain
layer where it would be written once per consumer.

A slice of one interface is not a larger interface, so this does not widen the
compatibility obligation DP-026 worries about.

### What the result records

```go
// On policy.Report:
Validators []ValidatorRecord `json:"validators,omitempty"`

type ValidatorRecord struct {
    Name   string `json:"name"`
    Status Status `json:"status"`
}
```

Same principle as `trustRoots` and `policyDigest`: a passing result has to say
what produced it. A report showing `semantics: pass` without naming the
validators is not auditable, and two consumers running different validator sets
would produce identical-looking results.

Findings reuse the existing type, with `Rule` namespaced as
`semantics/<validator>/<rule>` so a reader can tell a content finding from a
trust finding at a glance, and a new finding code distinguishes them
structurally.

### Exit code

A new one. Exit codes 7, 8 and 9 are unused; 7 for a semantic failure.

Reusing `ExitPolicy` (5) would conflate "I do not trust who made this" with "I
trust who made this and the content is wrong" — which are different
remediations by different people. A CI gate that cannot tell them apart routes
every failure to whoever owns signing.

### What a validator is not given

No transport, no credential provider, no registry client, no writable path. A
validator receives a context, a read-only filesystem, and an inventory.

This is a design constraint rather than a sandbox, and the document should say
so plainly: a validator is in-process Go code the embedding application chose,
and it can do whatever that application can do. What the SDK guarantees is that
it hands over no capability of its own, so a validator cannot reach the
registry DevProof was talking to or the credentials it used.

## Deliberately excluded

- **Validators named by the artifact.** Same reason a policy is never read from
  the bundle it judges: an attacker who controls the artifact would control the
  rules applied to it.
- **Executing payload content.** A validator is compiled into the embedding
  application. Nothing in the payload is run, ever.
- **A built-in schema validator.** The core learns no domain. A JSON Schema
  validator is a perfectly good validator — it belongs in whatever package
  wants it, not here.
- **Network access from a validator.** Not technically prevented, but the SDK
  hands over nothing that enables it, and a validator that reaches the network
  breaks reproducibility of the verdict.
- **Exporting the interface now.** See below.

## Promotion path

DP-026's reasoning is sound and this design does not overturn it: a public
interface is a permanent obligation, and two real validators are needed before
the shape is trustworthy. What DP-026 got wrong is claiming the internal
version exists.

So:

1. **Implement it unexported**, in `internal/`, with the seam DP-026 already
   describes. Correct DP-026 to say what is actually true at each step.
2. **Write the first validator against the firmware catalog** — required
   component set, one file per component, no unknown subsystems. That is the
   validator the example says it is missing, and building it answers whether
   `Subject` carries enough.
3. **Write a second one for a different domain** before exporting anything. If
   the second one needs a field the first did not, the interface was wrong, and
   finding that out while it is unexported is the entire point.
4. **Export** in a minor release once two validators have not needed to change
   it. No format change is involved; this is SDK surface only.

This is the same prove-then-extract discipline the project applies to itself.
Exporting after one consumer would be guessing, which is the argument this
repository already makes against generalizing too early.

## Open questions

1. **Does `verify` materialize, or refuse?** A content-reading validator on
   `verify` needs the payload on disk. The alternatives are materializing to a
   private staging directory, or declining and telling the caller to use
   `expand`. Materializing is friendlier; refusing keeps `verify` honestly
   read-only. A `NeedsContent() bool` on the interface would let each validator
   say, at the cost of a wider interface.
2. **Should a warning-only verdict be `pass`?** Findings have severity. A
   validator returning only warnings is arguably `pass` with findings attached,
   which is how trust behaves — worth confirming rather than assuming.
3. **Ordering and short-circuit.** Run every validator and report all findings,
   or stop at the first failure? Reporting everything matches how policy
   evaluation already behaves and is probably right.
4. **Does the validator set belong in the proof report's digest story?** A
   policy is identified by digest so a result can be re-checked. Validators are
   code, not documents, so there is nothing to digest — a name and a version
   string may be the best available, and it is weaker.

## What this does not fix

Semantic validation makes the third dimension answerable. It does not make any
particular answer correct, and it adds no domain knowledge to DevProof. A
consumer with no validator sees exactly what they see today.
