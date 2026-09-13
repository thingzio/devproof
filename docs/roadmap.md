# Implementation roadmap

The roadmap orders work by dependency and risk. It intentionally establishes
canonical bytes and safe read behavior before registry publication or signing.

**Phases 0 through 3 are delivered. Phases 4 through 6 are substantially
built but do not meet their own exit criteria yet.** The phases are kept here
because those criteria are the standing definition of done, and because the
order explains why the codebase is shaped the way it is.

Known outstanding against the criteria above:

- **Phase 1 and 4.** Standalone `verify` does not fetch or hash the payload
  layer; it checks the manifest and config against each other and the
  manifest's layer descriptor against itself. A subject whose layer is absent
  or altered currently reports `integrity: pass`. Until that is fixed, the
  Phase 1 criterion that failures publish nothing and the Phase 4 criterion
  that policy consumes only verified claims are both unmet.
- **Phase 4.** A policy-gated `expand` evaluates its policy and gates on it
  correctly, then returns a freshly constructed report saying
  `trust: not-evaluated`. Offline verification is a flag check rather than a
  network boundary. Evidence copy is not implemented.
- **Phase 0.** Manifest, lock, config, and policy schemas are published under
  `schemas/`; the proof report and provenance predicate are not.
- **Phase 6.** `pkg/conformance` checks structure and much of the canonical
  model, not exact writer bytes, and this document and DP-019 disagree about
  PAX and time fields. A second independent read implementation does not
  exist.

That list is the real roadmap. Writing "delivered" against phases whose exit
criteria are unmet is how a roadmap stops being useful.

## Phase 0: Freeze the implementable design

Deliver:

- resolve the open decisions in [decisions.md](decisions.md) needed by phases 1
  and 2;
- machine-readable schemas for manifest, lock, config, policy, and CLI JSON;
- documented media types and format-version negotiation;
- Go module, package skeleton, linting, tests, and CI; and
- a compatibility test that fails on accidental golden-byte changes.

The normative tree-record, config, tar, gzip, and OCI manifest fixtures cannot
be produced here, because producing them requires the encoders that phase 1
delivers. What belongs to phase 0 is the mechanism that freezes them: a golden
harness that fails on any byte change, refuses to regenerate under CI, and
reports where a stream diverged. Each fixture is committed as its encoder
lands, and is immutable from that moment.

Exit criteria:

- a reviewer can implement an independent tree-digest and config verifier from
  the documentation and match the golden vectors;
- no unresolved choice can change v1 payload identity without an explicit
  format-version decision.

## Phase 1: Canonical local core

Deliver:

- portable path normalization;
- file type and collision detection;
- canonical inventory and tree digest;
- private local-path snapshotting;
- deterministic config, tar, gzip, and OCI manifest generation;
- local OCI image-layout storage;
- structural and content verification;
- safe staged expansion; and
- root SDK `Build`, `Verify`, `Expand`, and `Inspect` for local layouts.

Exit criteria:

- every local golden and adversarial fixture passes;
- a local directory round trip preserves all five required digest levels;
- failures and cancellation publish neither a final artifact nor destination;
- Linux and macOS runners produce identical bytes.

## Phase 2: Manifest, lock, and multi-source composition

Deliver:

- strict manifest and lock loaders;
- canonical manifest and lock digests;
- local-path resolver contract;
- HTTPS Git resolver with immutable commit resolution;
- include and exclude matching;
- mount-path composition and ownership inventory;
- stale-lock detection and atomic lock writes;
- bounded parallel source resolution; and
- SDK `Lock` plus direct single-source synthesis.

Exit criteria:

- source ordering and concurrency cannot change output;
- a mutable source cannot pass a locked build after changing;
- credentials and local absolute paths do not enter lock or subject bytes;
- multi-source partial failure produces no lock or artifact.

## Phase 3: OCI registry transport

Deliver:

- typed references and tag-to-digest resolution;
- authenticated registry pull and push;
- bounded blob upload concurrency and retry;
- remote descriptor verification;
- tag assignment as the final publication step;
- subject copy across repositories and registries;
- registry capability reporting; and
- end-to-end SDK operations for registry subjects.

Exit criteria:

- registry round trips preserve subject bytes and digest;
- moving a tag cannot change an in-progress operation's frozen subject;
- credential scope and redirect tests pass;
- simulated partial upload and network failures never report success.

## Phase 4: Evidence and policy

Deliver:

- provenance predicate schema;
- in-toto Statement and DSSE construction;
- selected Sigstore signing providers;
- OCI subject/referrer publication and discovery;
- specified referrer-tag fallback;
- offline subject plus evidence layouts;
- strict verification-policy loader and evaluator;
- integrity, trust, and semantic result dimensions; and
- stable proof-report JSON.

Exit criteria:

- adding or replacing evidence never changes subject digest;
- required evidence failures are fail-closed;
- policy consumes only cryptographically verified claims;
- subject and evidence copy reports complete or explicit partial failure;
- offline verification succeeds with only the exported layout and trust roots.

## Phase 5: CLI contract

Deliver:

- `lock`, `build`, `verify`, `expand`, `inspect`, and `version`;
- text, JSON, and quiet output;
- documented exit-code mapping;
- configuration precedence and environment variables;
- credential-provider integration;
- TTY-aware progress and optional interaction;
- signal cancellation and cleanup; and
- shell completions and executable documentation examples.

CLI work may begin earlier, but commands are complete only when they are thin
adapters over the stable SDK operations.

Exit criteria:

- every CLI behavior has SDK and command-level tests;
- stdout remains safely pipeable;
- non-interactive CI never prompts;
- every error class returns the documented exit code and JSON code.

## Phase 6: Interoperability and stabilization

Deliver:

- compatibility results for multiple OCI registries;
- compatibility results for filesystem-oriented OCI consumers;
- independent format conformance verifier or second read implementation;
- performance and memory benchmarks across representative bundle sizes;
- public security policy and vulnerability-reporting process;
- release SBOM, checksums, signatures, and provenance; and
- migration and compatibility policy for format and SDK versions.

Exit criteria for format v1:

- normative vectors are final and published;
- cross-platform and registry matrices are green;
- default resource limits are measured and documented;
- at least one external consumer can use an expanded bundle without bespoke
  payload transformation;
- the SDK and CLI have no known format-breaking TODOs.

## First useful milestone

The smallest useful release is a local, unsigned implementation that can:

```text
directory -> canonical OCI layout -> verify -> directory
```

and prove equal tree, layer, config, and manifest digests after the round trip.
This milestone validates the hardest identity and extraction contracts before
network services or signing obscure failures.

## First end-to-end milestone

The first end-to-end release adds:

```text
manifest with path and Git sources
  -> immutable lock
  -> canonical OCI subject
  -> registry publication by digest
  -> provenance and signature referrers
  -> policy verification
  -> safe expansion
```

## Explicitly deferred

- overlay or replacement precedence;
- HTTP blob, object-store, archive, and OCI-as-source resolvers;
- Git submodule and LFS materialization;
- nested bundles and recursive dependency locks;
- delta transfer or chunk-level deduplication;
- arbitrary metadata-preservation profiles;
- bundle-supplied validators or executable hooks;
- policy distribution or remote policy service;
- daemon, controller, or continuous synchronization modes;
- garbage collection of registry content; and
- semantic `diff` beyond canonical inventory changes. The inventory-level
  comparison shipped as `devproof diff`; what stays deferred is interpreting
  the payload, which needs the semantic validator first (DP-026).

Deferred features should be promoted only from a concrete consumer requirement
and must preserve the accepted design decisions or explicitly revise them.
