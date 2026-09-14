# Verification policy

## Purpose

A DevProof policy evaluates whether verified facts about an immutable subject
satisfy a caller's trust requirements. It does not affect subject identity and
does not alter the artifact.

Policy evaluation consumes:

- a digest-resolved OCI subject;
- structural and content-integrity facts;
- cryptographically verified evidence;
- caller-provided trust roots; and
- an explicit evaluation time when a rule depends on time.

Unverified evidence claims never become policy inputs.

## Result dimensions

Verification reports independent status values:

```text
integrity: pass | fail
trust:     pass | fail | not-evaluated
semantics: pass | fail | not-evaluated
```

- Integrity is defined by the bundle format and is always evaluated by
  `verify` and `expand`.
- Trust is evaluated only when a policy is supplied or configured as required.
- Semantics is evaluated only when the caller supplies a trusted validator.

An overall operation succeeds only when integrity passes and every evaluated
required dimension passes.

## Policy example

```yaml
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release-bundles
spec:
  subject:
    requireDigestReference: true
    allowedFormats:
      - devproof-bundle-v1

  signatures:
    threshold: 1
    identities:
      - issuer: https://token.actions.githubusercontent.com
        subject: https://github.com/example/release/.github/workflows/build.yaml@refs/heads/main

  provenance:
    required: true
    predicateTypes:
      - https://slsa.dev/provenance/v1
    requireLockDigest: true
    sources:
      allowedTypes: [git]
      allowedHosts:
        - github.com
      requireImmutableResolution: true

  evidence:
    rejectInvalidMatchingEvidence: true

  limits:
    maxFiles: 10000
    maxExpandedBytes: 1073741824
```

The complete grammar is the
[verification-policy schema](../schemas/verification-policy.v1alpha1.schema.json),
which is normative: the loader is one implementation of it, and a test asserts
the two agree on required fields, unknown-field rejection, and every limit's
ceiling. The example above is exercised by the test suite, so it parses.

## Policy document rules

- Unknown API versions, kinds, fields, rule names, and enum values are errors.
- YAML duplicate keys are errors.
- Empty identity or trust-root sets cannot satisfy a positive threshold.
- Contradictory rules are rejected during policy loading.
- Defaults are explicit in the typed representation and policy report.
- A loaded policy is canonicalized with RFC 8785 and identified by SHA-256 in
  the verification result.
- The policy itself is trusted configuration supplied by the caller. DevProof
  does not bootstrap trust in the policy from the artifact being evaluated.

## Subject rules

Subject rules may constrain:

- whether the caller supplied a digest rather than a tag;
- accepted bundle format versions;
- accepted artifact, config, and layer media types;
- tree digest algorithm;
- file count and total expanded size; and
- repository or registry namespaces when location is part of local policy.

A repository-name rule is evaluated against the resolved location. It is not a
claim that repository location contributes to subject identity.

## Signature rules

Signature policy may require:

- a minimum number of distinct accepted signing identities;
- an allowed OIDC issuer and exact or regular-expression subject;
- one or more trusted public-key identifiers;
- a transparency-log inclusion proof;
- integrated-time bounds;
- certificate validity at signing time; and
- distinct signer groups for threshold decisions.

Threshold counting occurs after cryptographic verification and identity
matching. Duplicate signatures by the same policy identity count once unless a
policy explicitly defines another rule.

Identity matching is anchored and fail-closed. Regular expressions are compiled
at policy-load time and operate on normalized complete identity strings.

## Provenance rules

Provenance policy may require:

- one or more accepted predicate types (`predicateTypes`);
- an authenticated builder identity (`allowedBuilders`);
- that provenance records a lock digest at all (`requireLockDigest`);
- allowed source types or hosts (`allowedTypes`, `allowedHosts`); and
- immutable source resolutions (`requireImmutableResolution`).

Those are the rules that exist. Three that this document previously listed do
not: pinning an **expected** manifest or lock digest rather than requiring the
presence of one, and constraining a DevProof or resolver version range.
`requireLockDigest` demands a syntactically valid digest, not a match against a
value the policy names. Per-source tree digests are cross-checked against what
verification established rather than against a policy-supplied expectation.

Expected-value rules are a reasonable thing to want — they are how a policy
says "this exact qualified build" rather than "some build" — and they are
proposed rather than shipped. Until they exist, pin the subject by digest and
let the tree-digest cross-check do the rest.

Claims are cross-checked against what verification established. Provenance
naming a tree digest or bundle format other than the subject's own is a
finding, and `requireLockDigest` demands a syntactically valid digest rather
than merely a non-empty field.

A signature establishes who wrote a statement. It does not establish that the
statement is true, and a trusted signer can still publish one that contradicts
the artifact it is bound to. Malformed or internally contradictory assertions
never become verified facts.

Source rules cannot be satisfied vacuously either. A policy restricting source
types or hosts is not met by provenance recording no sources at all, and
`allowedHosts` is not met by a source that records no host to check — no URL,
an unparseable one, or one with no host component such as `file:///etc/passwd`.
A predicate is written by whoever signed it, so a rule that applied only to
statements volunteering enough detail to be checked would be no rule.

That applies to every source, which has a consequence worth knowing before
setting it: a local path source names no host either, so a policy restricting
hosts refuses one. If local sources are acceptable, name the acceptable types
with `allowedTypes` rather than leaving the host rule to decide.

Source-location rules apply to provenance evidence, not to payload identity.
Two attestations may truthfully describe different source histories for the
same subject. Policy selects which history it is willing to trust.

## Evidence selection

OCI repositories are open attachment surfaces unless registry authorization
prevents it. The presence of an unrelated or malicious referrer must not by
itself make a valid subject unverifiable.

Evaluation therefore:

1. Enumerates referrer descriptors under configured limits.
2. Selects candidates by required artifact and predicate types.
3. Fetches and verifies selected candidates.
4. Applies signature, identity, and provenance rules.
5. Reports ignored, malformed, and rejected candidates separately.

`rejectInvalidMatchingEvidence` determines whether malformed evidence that
claims a required type is itself fatal. Even when false, policy fails if the
remaining verified evidence cannot satisfy its requirements.

## Evidence age

`evidence.maxAge` bounds how old the evidence being relied on may be, written
as a Go duration such as `720h`:

```yaml
spec:
  evidence:
    maxAge: 720h
```

The rule applies to accepted evidence. Age is measured from an authenticated
signing time against the evaluation clock, never from a date the evidence
asserts about itself — an attacker replaying an old attestation writes whatever
date suits them. Evidence carrying no authenticated time cannot satisfy the
rule and is refused: treating "unknown" as "recent" would make the bound
useless against the only adversary who cares about it.

Unset means age is not considered, which is often right. A signature does not
expire on its own, and a build attestation stays true. The rule is for facts
whose truth decays even though their bytes do not.

A failing evidence-age rule reports `evidence-expired`.

## Time

Artifact integrity has no time dependency. Time-based trust rules use one
evaluation time captured at the start of verification and recorded in the
result.

Offline verification distinguishes:

- authenticated signing or transparency-log time embedded in evidence;
- certificate-validity time; and
- the caller's evaluation clock.

A missing trusted time source cannot satisfy a rule that requires one.

## Policy findings

Every failed or warning rule has:

```text
code       stable machine identifier
rule       policy path or rule identifier
severity   error or warning
subject    affected digest, evidence, source, or path
message    concise human explanation
```

Initial finding codes include:

```text
digest-reference-required
format-not-allowed
signature-threshold-not-met
signer-identity-not-allowed
transparency-proof-required
provenance-required
provenance-inconsistent
predicate-not-allowed
builder-not-allowed
lock-digest-required
source-type-not-allowed
source-host-not-allowed
immutable-resolution-required
evidence-expired
matching-evidence-invalid
resource-limit-exceeded
```

Messages are not stable APIs; codes and JSON field meanings are.

## Semantic validation

The third dimension. Integrity asks whether the bytes survived and trust asks
who vouched for them; both are questions about the artifact, so DevProof
answers both. Whether the content is *correct* is a question about a domain,
and DevProof has none — so it is answered by a validator the embedding
application supplies.

Supplying none is the default: `semantics` reports `not-evaluated`, nothing is
materialized, and the operation costs what it always did.

A validator receives a context, a read-only view of the payload, and the
verified inventory. It receives no capability belonging to DevProof — no
transport, no credential provider, no writable path. That is a statement about
what the SDK hands over rather than a sandbox: a validator is in-process code
the application chose, and what it cannot do is reach the registry DevProof was
talking to or the credentials it used.

Nothing is discovered from the artifact. A bundle cannot name its own validator
any more than it can name the policy that judges it.

### What a verdict means

| Situation | `semantics` |
| --- | --- |
| No validator supplied | `not-evaluated` |
| Every validator returns no error findings | `pass` |
| Any validator returns an error finding | `fail` |
| A validator returns an error | `fail` |
| A validator panics | `fail`, recovered and reported |

A validator that *errors* fails rather than reporting `not-evaluated`. "Nobody
looked" and "somebody looked and could not finish" are different facts, and
conflating them makes a broken validator indistinguishable from an absent one.
A panic is recovered because a validator is third-party code running inside a
verification, and one that killed the process would turn a content check into a
denial of service against the tool that invoked it.

Every validator runs even after one fails, so a consumer fixing content gets
the whole list rather than one item per run.

Findings carry the `semantics-invalid` code and a rule namespaced as
`semantics/<validator>/<rule>`, so a content finding is distinguishable from a
trust finding at a glance. The report records which validators ran and what
each concluded, for the same reason it records the policy digest and the trust
roots: a passing result has to name what produced it.

### Where it runs

On `verify`, the payload is expanded into a private directory that is removed
before the command returns — a validator needs content on disk, and the caller
asked for validation rather than for an expansion.

On `expand`, validation runs against the staged tree *before* the rename that
publishes it. A rejected expansion leaves nothing behind, which is a stronger
guarantee than writing and then removing: content that briefly existed has
already been readable by anything watching the directory (DP-032).

A semantic failure exits `7`, not the policy code. "I do not trust who made
this" and "I trust who made this and the content is wrong" are different
failures with different remediations, and a gate that cannot tell them apart
routes everything to whoever owns signing.

## Proof report

The complete verification result is the DevProof proof report. Its grammar is
the [proof-report schema](../schemas/proof-report.v1.schema.json). It records:

- subject and tree digests;
- the status of each dimension: integrity, trust, and semantics;
- policy name and digest, and the trust material by digest;
- accepted signer identities;
- accepted evidence: digest, predicate type, authenticated signing time when
  one exists, and whether a transparency-log inclusion proof was checked;
- rejected candidate summaries;
- how evidence was found — the referrers API or the fallback tag scheme;
- evaluation time when applicable;
- the effective resource limits and which input supplied each (DP-021); and
- individual findings.

Unlike the input documents, the report is output: nothing decodes it strictly,
so a consumer that ignores a field a later version added degrades rather than
fails. What does not change is the meaning of a field that is present.

Every bound appears, including the ones left at their defaults, because a
reader cannot tell a default from an omission. Text output shows only the
bounds somebody tightened; JSON carries all of them with their origins.

The report is evidence of what DevProof evaluated under a particular policy. It
is not itself signed unless a caller explicitly sends it to an attester, and it
does not claim that payload content is semantically correct.
