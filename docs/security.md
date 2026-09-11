# Security design

## Security objective

DevProof must let a consumer answer, independently:

1. Which exact bytes and canonical paths are in this subject?
2. Did those bytes change during storage, transfer, or expansion?
3. What authenticated evidence describes their source and builder?
4. Does that evidence satisfy this consumer's policy?

DevProof does not prove that payload contents are beneficial, vulnerability
free, licensed for a particular use, or semantically correct.

## Protected assets

- integrity and identity of subject content;
- source and builder provenance;
- verification policy and trust roots;
- Git, registry, KMS, and signing credentials;
- host filesystem outside explicitly selected source and destination roots;
- availability and bounded resource use of the caller; and
- confidentiality of private source locations and credentials.

## Trust boundaries

Treat these as untrusted until verified or explicitly configured:

- manifests, locks, policies, and semantic-validator input;
- local source directories;
- Git servers, repository content, refs, submodules, and attributes;
- registry responses, tags, manifests, blobs, and referrer listings;
- archive paths, headers, sizes, and compression ratios;
- unsigned evidence and claims inside signed but untrusted evidence;
- environment variables and user configuration files; and
- extension implementations registered by an embedding application.

Caller-supplied policy and trust roots are authoritative for that invocation.
Registered Go extensions run with the embedding process's authority and are
inside its trust boundary; DevProof cannot sandbox them.

## Threats and required controls

### Mutable-reference substitution

Threat: a Git branch or OCI tag changes between resolution, verification, and
use.

Controls:

- lock Git sources to immutable commit identifiers and DevProof tree digests;
- resolve an OCI tag once and use the returned manifest descriptor thereafter;
- report canonical digest references;
- allow policy to require digest input; and
- assign publication tags only after verifying remote manifest bytes.

### Source time-of-check/time-of-use changes

Threat: local content changes while it is inventoried or packaged.

Controls:

- copy selected content into a private snapshot;
- hash while copying;
- package only from the snapshot;
- compare bytes with the frozen inventory while packaging; and
- reject snapshot aliases, links, and unsupported file types.

### Path traversal and link attacks

Threat: a source or archive writes outside the destination or redirects writes
through a link.

Controls:

- canonical path validation before opening files;
- descriptor-relative or no-follow filesystem operations where supported;
- rejection of absolute paths, `..`, aliases, links, and special files;
- private staging outside attacker-controlled directory trees;
- verification that each parent remains a real directory; and
- atomic publication only after full validation.

String-prefix checks alone are insufficient path containment checks.

### Duplicate and ambiguous archive entries

Threat: different extractors select different values for duplicate paths,
case-fold aliases, Unicode aliases, or file/directory conflicts.

Controls:

- config inventory uniqueness;
- portable normalization and collision checks;
- exactly one tar entry for each file;
- at most one derived entry for each required directory; and
- rejection of extra, duplicate, reordered-with-conflict, or aliased entries.

### Resource exhaustion

Threat: decompression bombs, huge configs, excessive files, deep paths,
oversized evidence sets, slow sources, or unbounded retries exhaust resources.

Controls:

- configurable hard bounds for manifest, lock, config, compressed and expanded
  bytes, files, paths, depth, referrers, and evidence size;
- streaming hashing and extraction;
- bounded concurrency;
- per-attempt and overall timeouts;
- bounded retry budgets; and
- cancellation checks between I/O operations.

Limits are applied to declared sizes and actual streamed bytes. A false small
declaration does not disable the streaming limit.

### Digest or algorithm confusion

Threat: a digest is interpreted under the wrong algorithm or representation.

Controls:

- v1 accepts SHA-256 only where the format requires it;
- algorithms are explicit in typed digest values;
- encoded length and lowercase hexadecimal form are validated;
- descriptors are verified before parsing content; and
- tree, layer, config, manifest, lock, and evidence digests are different typed
  concepts in APIs and reports.

### Malicious or misleading evidence

Threat: anyone attaches evidence, a valid signature uses an untrusted identity,
or policy evaluates unverified claims.

Controls:

- cryptographic verification before claim parsing enters policy facts;
- explicit issuer, subject, key, threshold, predicate, and source policy;
- subject-digest binding;
- separation of ignored, invalid, verified, and accepted evidence;
- bounded referrer discovery; and
- fail-closed behavior for unsatisfied required evidence.

A signature authenticates an identity and bytes. It does not grant trust without
policy.

### Policy downgrade or ambiguity

Threat: unknown fields, weak defaults, or artifact-controlled policy bypass a
required rule.

Controls:

- reject unknown policy versions, fields, and rule values;
- keep policy outside the subject under evaluation;
- record the policy digest in results;
- distinguish `not-evaluated` from `pass`; and
- prohibit a command flag that disables mandatory integrity verification.

### Credential disclosure

Threat: credentials leak through arguments, URLs, locks, evidence, logs, process
inspection, redirects, or temporary files.

Controls:

- do not accept raw secrets in ordinary flags;
- use credential-provider interfaces and protected files;
- strip userinfo from persisted and displayed URLs;
- redact sensitive headers and query values;
- never persist credentials in manifest, lock, config, evidence, or result;
- do not forward authorization across host-changing redirects; and
- create temporary credential material with owner-only permissions and remove
  it on all paths.

### Arbitrary code execution

Threat: a bundle supplies a validator, hook, executable, or configuration that
DevProof runs during build or verification.

Controls:

- never execute payload content;
- no bundle-discovered plugins;
- SDK extensions are registered by the embedding application;
- semantic validators receive a verified read-only filesystem; and
- a future sandboxed validator format requires a separate threat model and
  explicit resource and capability restrictions.

### Registry and redirect attacks

Threat: a registry serves inconsistent bytes, redirects credentials, or lacks
atomic referrer behavior.

Controls:

- verify all content descriptors locally;
- freeze and compare the manifest descriptor before tag assignment;
- permit HTTPS by default and make insecure transport opt-in and prominent;
- scope credentials to a registry host and repository;
- follow redirect credential rules; and
- report referrer API and fallback behavior so policy can reject an unsupported
  storage mode.

## Local filesystem handling

Temporary roots must be explicit or selected using secure operating-system APIs.
Directories use owner-only permissions while work is in progress. Predictable
shared temporary paths are prohibited.

Cleanup validates the exact operation-owned path and must not recursively
remove a broad user, workspace, filesystem-root, or unresolved-variable path.
Cleanup failures are reported without hiding the primary error.

The destination for expansion must be absent. Parent directories are
caller-owned and are not modified beyond creation of the final destination by
atomic rename.

## Source acquisition

HTTPS is required for built-in remote Git sources in v1. Authentication is
host-scoped. Resolver implementations must disable implicit hooks and avoid
executing repository configuration.

Submodules and Git LFS materialization are disabled in v1 because they introduce
additional mutable sources and credential boundaries. Future support must model
each resolved object as provenance material and apply the same scheme, host,
redirect, and size policies.

Local absolute paths are not included in published evidence by default. A
logical label and canonical tree digest are sufficient to describe their role
without disclosing workstation structure.

## Signing and keys

Supported signing approaches may include keyless identity, protected local
keys, and KMS-backed keys. Each attester defines:

- how identity is established;
- where private operations occur;
- which public verification material is emitted or discoverable;
- whether a transparency log is used; and
- how cancellation and retry behave.

Private key bytes must not cross an API boundary for KMS-backed signing. Local
keys are read from protected files or agents, not command arguments. A build
must not silently switch signing modes when configured inputs conflict.

## Failure disclosure

User errors identify the logical source, reference, rule, or canonical path
needed to remediate the failure. Debug output may include operation stacks but
must still redact credentials.

Public verification results should not include local absolute source paths,
temporary directories, access tokens, private registry responses, or unrelated
evidence content.

## Security release gates

Before the first stable release:

- threat cases in [testing.md](testing.md) must pass under the race detector;
- archive parsing and path normalization must have fuzz coverage;
- credential redaction must have deterministic tests;
- dependencies must be scanned and license-reviewed;
- release artifacts must include checksums, an SBOM, and provenance;
- supported registries and referrer behavior must be documented from tests; and
- a vulnerability-reporting process must be published.
