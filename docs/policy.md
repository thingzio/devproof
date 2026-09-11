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
      allowedSchemes: [https]
      allowedHosts:
        - github.com
      requireImmutableResolution: true

  evidence:
    rejectInvalidMatchingEvidence: true

  limits:
    maxFiles: 10000
    maxExpandedBytes: 1073741824
```

This example is illustrative until the JSON Schema and predicate contract are
frozen.

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

- one or more accepted predicate types;
- an authenticated builder identity;
- a matching manifest digest and lock digest;
- an accepted DevProof and resolver version range;
- allowed source types, schemes, hosts, or repository prefixes;
- immutable source resolutions;
- matching per-source tree digests;
- absence of unapproved source types; and
- a maximum evidence age when an authenticated time is available.

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

## Proof report

The complete verification result is the DevProof proof report. It records:

- subject and tree digests;
- integrity checks performed;
- policy and trust-root identifiers;
- accepted signer identities;
- accepted evidence descriptors and predicate types;
- rejected candidate summaries;
- evaluation time when applicable;
- individual findings; and
- overall dimension statuses.

The report is evidence of what DevProof evaluated under a particular policy. It
is not itself signed unless a caller explicitly sends it to an attester, and it
does not claim that payload content is semantically correct.
