# DevProof

DevProof is a Go-embeddable, extensible, multi-source artifact bundler with
canonical identity across platforms, provenance evidence, policy-based
verification, and safe deterministic expansion.

It turns files from local directories, Git repositories, and future source
types into immutable OCI artifacts that can be verified, redistributed, and
expanded back into their canonical filesystem form.

> **Project status:** design phase. The commands and APIs below describe the
> intended first implementation and are not available yet.

## Why DevProof

Configuration, policies, scripts, catalogs, and other filesystem resources are
often assembled from several mutable locations. Copying them into an archive
does not establish exactly what was selected, where it came from, whether it
changed, or which identities a consumer should trust.

DevProof separates those concerns:

1. A manifest describes the intended sources and where each source is mounted.
2. A generated lock resolves mutable references to immutable material.
3. The selected files are normalized into a canonical filesystem tree.
4. The tree is encoded as a deterministic OCI artifact.
5. Provenance and signatures are attached as evidence without changing the
   artifact's identity.
6. Consumers verify integrity and evidence against their own policy before
   safely expanding the files.

```text
sources -> manifest -> lock -> canonical tree -> OCI subject @ sha256:...
                                                      |
                                  signatures and provenance evidence
                                                      |
                                  verify -> safely expand to filesystem
```

## Planned capabilities

- Go SDK as the primary API, with a thin CLI over the same operations.
- Multiple named sources composed through explicit mount paths.
- Built-in local-path and HTTPS Git sources.
- Explicit SDK extension points for additional sources, transports, attesters,
  and policy evaluators.
- Human-authored manifests and canonical machine-generated locks.
- Stable tree and OCI subject digests for the same canonical content across
  supported platforms.
- Deterministic filesystem-to-OCI-to-filesystem-to-OCI round trips.
- OCI image-layout and registry publication, retrieval, and copy by digest.
- in-toto provenance and Sigstore-compatible signatures attached as OCI
  referrers.
- Policy checks for signer identity, provenance, immutable source resolution,
  evidence requirements, and resource limits.
- Closed-world inventory verification before publication or expansion.
- Safe extraction with path validation, resource limits, private staging, and
  atomic destination publication.
- Stable JSON results, typed Go errors, bounded retries, timeouts, and
  cancellation.

## Manifest

A bundle manifest declares one or more sources. Mutable references are allowed
in the manifest but must be resolved into the lock before a reproducible build.

```yaml
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example-config
spec:
  sources:
    - name: application
      type: git
      mountPath: app
      config:
        url: https://github.com/example/application.git
        ref: main
        subPath: deploy

    - name: environment
      type: path
      mountPath: environment
      config:
        path: ./production
```

The generated `devproof.lock.json` records the resolved Git commit, source tree
digests, filters, final path ownership, file inventory, and canonical bundle
tree digest. A locked build fails rather than silently accepting changed
material.

## Intended CLI workflow

```bash
# Resolve mutable source references and create the lock.
devproof lock -f devproof.yaml

# Build and publish the locked content.
devproof build -f devproof.yaml \
  --lock devproof.lock.json \
  --to oci://registry.example.com/team/config:v1

# Verify the immutable subject and its evidence.
devproof verify registry.example.com/team/config@sha256:... \
  --policy policy.yaml

# Verify and atomically materialize the canonical files.
devproof expand registry.example.com/team/config@sha256:... \
  --to ./expanded \
  --policy policy.yaml
```

Direct single-source builds are also planned:

```bash
devproof build ./content --to oci-layout://./artifact

devproof build https://github.com/example/config.git \
  --git-ref 0123456789abcdef0123456789abcdef01234567 \
  --to oci://registry.example.com/team/config:v1
```

## Identity and evidence

The OCI subject is derived only from the canonical payload and bundle-format
version. Source URLs, timestamps, builder identity, registry location, tags,
signatures, and attestations do not affect that digest.

Evidence names the immutable subject digest and may describe its sources,
builder, invocation, and signing identity. Evidence can therefore be added,
renewed, or copied without changing the payload artifact.

DevProof proves artifact identity, integrity, provenance, and policy compliance
under the supplied trust policy. It does not claim that payload content is
correct, safe, vulnerability-free, or semantically valid.

## Boundaries

DevProof is not a deployment engine, dependency solver, registry server,
container runtime, secrets manager, or general package manager. It does not
execute files or validators discovered inside a bundle.

The initial portable filesystem profile supports regular files and implicit
directories. It normalizes permissions and rejects links, special files, path
aliases, and ambiguous collisions so that consumers do not depend on
platform-specific archive behavior.

## Design documentation

The implementation contracts are documented in [docs](docs/README.md):

- [design decisions](docs/decisions.md);
- [architecture](docs/architecture.md);
- [manifest and lock specification](docs/manifest.md);
- [bundle format](docs/bundle-format.md);
- [Go SDK](docs/sdk.md) and [CLI](docs/cli.md);
- [verification policy](docs/policy.md) and [security design](docs/security.md);
  and
- [test strategy](docs/testing.md) and [implementation roadmap](docs/roadmap.md).

## License

DevProof is licensed under the [Apache License 2.0](LICENSE).
