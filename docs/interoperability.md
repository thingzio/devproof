# Interoperability

DevProof artifacts are ordinary OCI artifacts. This document records what that
claim survives contact with, and how to reproduce each result.

The claim under test is narrow and checkable: a DevProof subject can be stored,
copied, and served by general-purpose OCI tooling without any of that tooling
knowing what DevProof is, and its digest does not change when it passes
through.

## Results

Verified against `registry:3` and the tool versions noted. The subject digest
is the same value in every row, which is the point: identity is a function of
content, and a repository, a transport, or a copying tool is not content.

| Tool | Operation | Result |
| --- | --- | --- |
| `skopeo` 1.24 | `inspect --raw oci:./layout:v1` | reads the manifest, reports artifactType |
| `skopeo` 1.24 | `copy oci:./layout:v1 oci:./copy:v1` | copied; DevProof verifies the copy, same digest |
| `skopeo` 1.24 | `copy docker://… oci:./out:v1` | registry to layout; same digest |
| `crane` | `digest <registry ref>` | reports the identical subject digest |
| `oras` 1.x | `manifest fetch --oci-layout` | reads the manifest from a layout |
| `oras` 1.x | `copy … --to-oci-layout` | full content copy; DevProof verifies it |
| `docker` 29.8 | `pull` | refuses: not a runnable image (expected) |
| bsdtar 3.5 / libarchive 3.7 | `tar xzf <layer blob>` | extracts; mode `0644`, epoch mtime |
| GNU tar 1.35 | `tar xzf -` | extracts; mode `0644`, epoch mtime |
| busybox tar 1.37 | `tar xzf -` | extracts; mode `0644`, epoch mtime |

### Reproducing

```bash
docker run -d --rm -p 15000:5000 --name reg registry:3

devproof build ./src --to oci-layout://./layout --tag v1
skopeo inspect --raw oci:./layout:v1
skopeo copy oci:./layout:v1 oci:./copy:v1
devproof verify oci-layout://./copy:v1

DEVPROOF_INSECURE_REGISTRY=1 devproof build ./src \
  --to oci://localhost:15000/team/config --tag v1
crane digest --insecure localhost:15000/team/config:v1
oras copy localhost:15000/team/config:v1 --to-oci-layout ./pulled:v1
devproof verify oci-layout://./pulled:v1
```

## Notes on specific tools

### `docker pull` refuses, and should

A DevProof subject is not a runnable container image. It has one layer and a
DevProof config media type, so a runtime that tried to use it as a root
filesystem would be interpreting it as something it is not. Docker reports
`mismatched image rootfs and manifest layers` and stops, which is the correct
outcome — the artifact is not mislabeled as an image, so nothing is tricked
into running it.

Registries store and serve it fine. Storage and execution are different
questions.

### `oras pull` needs `oras copy` instead

`oras pull` is file-oriented: it extracts layers using the
`org.opencontainers.image.title` annotation as a filename, and reports
`Skipped pulling layers without file name` when there is none.

DevProof subjects carry no annotations at all, by design. An annotation on the
subject manifest would change its digest, which would make identity depend on
metadata rather than content (DP-002).

Use `oras copy --to-oci-layout` for a full content copy, or `devproof expand`
for the payload as files. Both are in the matrix above.

### The layer is a plain tar+gzip

```bash
tar tzvf layout/blobs/sha256/<layer-digest>
tar xzf  layout/blobs/sha256/<layer-digest> -C ./out
```

This is the roadmap's "external consumer can use an expanded bundle without
bespoke payload transformation" criterion, and it holds in the strongest form:
the transformation needed is `tar`.

Three unrelated tar implementations — libarchive, GNU, and busybox — extract it
with identical results, including the normalized mode and the epoch timestamp.
That the canonical encoding is strict has not made it exotic.

What `tar` does not give you is verification. It will happily extract a layer
whose content does not match its descriptor, and it applies none of the path
and mode rules that make expansion safe. Use it to confirm the payload is
ordinary, not to consume the artifact.

## Registry compatibility

The transport uses only the OCI Distribution Spec 1.1.1 pull, push, and
referrers APIs, with no registry-specific behavior.

| Registry | Push / pull | Tag and digest | Referrers API | Signed evidence |
| --- | --- | --- | --- | --- |
| distribution `registry:3` | yes | yes | native | yes |
| GitHub Container Registry | yes | yes | native | yes |
| Google Artifact Registry | yes | yes | native | yes |

All three produce the same subject digest for the same source tree, and the
same digest a local layout produces. That is the claim worth testing: identity
is a function of content, so a registry is not part of it.

Cross-registry copy was verified GHCR to GAR. The digest is unchanged by
definition — a repository name is not content — and the copy verifies at the
destination.

The referrers API is the one place where registries genuinely differ. A
registry that does not implement it causes evidence to be discovered through
the fallback tag scheme, which is reported rather than silently used, and which
a policy must opt into (DP-028). A consumer therefore always knows which
mechanism produced the evidence it is judging. All three registries above
report `storage: referrers`, so the fallback was not exercised against a real
registry; it has unit coverage only.

Credentials come from the Docker configuration in every case, so
`docker login`, `gh auth`, or `gcloud auth configure-docker` is the whole
setup. Two registries can sit in one configuration file and each credential is
offered only to its own host (DP-013), which the cross-registry copy above
exercises directly.

Untested, because they need accounts rather than code: ECR, ACR, Docker Hub,
Quay, Artifactory, Harbor, and Nexus. The sequence below is what to point at
them.

```bash
# GHCR
echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$USER" --password-stdin
devproof build ./src --to oci://ghcr.io/<owner>/<name> --tag v1

# Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev
devproof build ./src --to oci://us-central1-docker.pkg.dev/<project>/<repo>/<name> --tag v1

# Then, against either:
devproof verify oci://<ref>:v1
devproof build ./src --to oci://<ref> --tag signed --sign --key signer.pem
devproof verify oci://<ref>:signed --key signer.pub.pem --policy policy.yaml
```

## Platforms

| Platform | Ships | Suite runs in CI |
| --- | --- | --- |
| Linux amd64 | yes | yes |
| Linux arm64 | yes | yes |
| macOS arm64 | yes | yes |
| macOS amd64 | yes | built and vetted only |

Windows is not supported; use WSL (DP-035). See docs/testing.md for why three
cells rather than four.

## Independent verification

`conformance` is a second reader built only from the format specification,
sharing no code with the writer (DP-034). It is the strongest interoperability
evidence here, because it does not depend on any other tool agreeing with us —
it checks the artifact against the document that describes it.

```go
report, err := conformance.VerifyLayout("./layout", "v1", conformance.LevelCanonical)
```

It recomputes the tree digest from the layer bytes rather than reading it from
the config, so a config that agreed with itself but not with its payload is
caught. It reads raw tar blocks rather than using `archive/tar`, which accepts
GNU and base-256 encodings and silently joins the USTAR prefix field onto the
name — every one of those is a deviation this reader exists to find.

### Conformance levels

Three questions, kept separate so an implementation cannot claim more than it
checked:

| Level | Question | Checks |
| --- | --- | --- |
| `LevelStructure` | is it intact and safe to expand? | every digest recomputed, the inventory compared with what the layer held, no path escaping the destination |
| `LevelCanonical` | are these the only bytes for this tree? | entry order, the fixed header fields, the extended-header restriction, the frozen gzip header, RFC 8785 member order, the portable path rules |
| `LevelBytes` | does this writer reproduce the published vectors? | the byte vectors in [vectors/](../vectors) |

A deviation found above the requested level is recorded in
`Report.Deviations` rather than discarded, so a structural pass still reports
what it tolerated.

`LevelBytes` is a property of an implementation, not of an artifact: it is
checked by building the documented input tree and comparing the result with
`vectors/format/v1`. `conformance.VerifyVectors` runs that comparison for a
directory of vector files, which is how another implementation checks its own
output.
