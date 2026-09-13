# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/thingzio/devproof/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include, where you can: affected version or commit, a description of the
impact, and the smallest reproduction you have. A bundle, manifest, policy, or
archive that triggers the behavior is more useful than a description of it.

You should get an acknowledgement within three business days. We will tell you
whether we consider the report in scope, and keep you updated as a fix
progresses. Credit is offered by default in the advisory unless you ask
otherwise.

## Supported versions

Only the latest release receives fixes, and until 1.0 a fix ships as a new
patch or minor version rather than being backported. There is no yank
mechanism: a defective release is superseded, never withdrawn, because
something may already have consumed it.

Until 1.0 this is deliberately a narrow promise. Pin exactly if you depend on
this.

## Scope

DevProof's security claims are stated in [docs/security.md](docs/security.md).
In short, DevProof aims to let a consumer establish, independently:

- which exact bytes and canonical paths a subject contains;
- whether those bytes changed during storage, transfer, or expansion;
- what authenticated evidence describes their source and builder; and
- whether that evidence satisfies the consumer's own policy.

The following are in scope for a report:

- reading or writing outside an explicitly selected source or destination root,
  including through links, path aliases, or archive entries;
- a subject that passes verification despite differing from its config
  inventory, tree digest, or descriptors;
- a policy decision that accepts evidence it should reject, or that consumes
  claims which were never cryptographically verified;
- credential disclosure through arguments, URLs, logs, locks, evidence,
  results, or temporary files;
- a failed, canceled, or partial operation that publishes a destination or
  reports success;
- resource exhaustion that the documented limits should have bounded; and
- two supported platforms producing different subject digests for the same
  canonical tree.

The following are **not** vulnerabilities in DevProof:

- payload content that is itself malicious, vulnerable, or misleading. DevProof
  proves identity, integrity, provenance, and policy compliance. It makes no
  claim that payload bytes are correct, safe, or semantically valid;
- evidence that is cryptographically valid but attests to something a consumer
  dislikes, when their policy did not require otherwise. A signature
  authenticates an identity and bytes; policy decides trust;
- behavior of a registry, Git server, KMS, or transparency log that DevProof
  correctly reported; and
- behavior of a Go extension registered by an embedding application. Registered
  extensions run with the host process's authority and are inside its trust
  boundary. DevProof cannot sandbox them.

## Security posture

- DevProof never executes payload content, never loads plugins discovered in a
  bundle, and never runs validators or hooks found inside an artifact.
- Extraction writes only into a private staging directory and publishes the
  result atomically. A failed or canceled expansion leaves no destination.
- Verification fails closed. Unknown policy versions, unknown fields, and
  absent required evidence are errors, not warnings.
- Secrets are supplied through credential providers, environment variables,
  standard credential stores, or protected files, never through ordinary
  command-line flags, and are never persisted in a manifest, lock, config,
  evidence object, or result.
