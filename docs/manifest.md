# Manifest and lock specification

## Documents

DevProof uses two input documents:

- a manifest expresses desired source composition;
- a lock records the immutable resolution of that manifest.

The manifest is authored by users and may be YAML or JSON. The lock is generated
canonical JSON and must not be manually edited.

The manifest's complete grammar is the
[bundle schema](../schemas/bundle.v1alpha1.schema.json), which is normative:
the loader is one implementation of it. `devproof init` writes a commented
manifest that already conforms, which is usually a faster start than reading
either.

## Manifest example

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
      include:
        - "config/**"
        - "scripts/**"
      exclude:
        - "**/*.tmp"
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

## Top-level fields

### `apiVersion`

Required. V1 alpha manifests use `devproof.thingz.io/v1alpha1`. Unknown versions
are rejected.

The manifest API version is independent of the bundle format version. A future
manifest API may still build format v1 if it has identical canonical semantics.

### `kind`

Required. The only v1 value is `Bundle`.

### `metadata.name`

Required. A logical label used in diagnostics and evidence. It must contain
lowercase ASCII letters, digits, and hyphens, begin and end with an alphanumeric
character, and be at most 63 characters.

The name does not affect payload or OCI subject identity.

### `spec.sources`

Required and non-empty. Each entry has:

- `name`: unique source name using the same syntax as `metadata.name`;
- `type`: built-in short type or extension-qualified type;
- `mountPath`: destination below the bundle root, or `.` for the root;
- `include`: optional ordered-insensitive list of selection patterns;
- `exclude`: optional ordered-insensitive list of rejection patterns; and
- `config`: resolver-specific configuration object.

Unknown fields are errors. YAML duplicate mapping keys are errors.

## Source types

### Local path

```yaml
- name: local-policy
  type: path
  mountPath: policy
  config:
    path: ./policy
```

Rules:

- `path` is required and may identify a file or directory.
- Relative paths are resolved against the manifest's directory.
- An absolute path requires the caller to enable absolute local sources.
- The lock preserves the authored relative path or a caller-supplied logical
  label. It does not publish an absolute path by default.
- The resolver copies selected files into a private snapshot and hashes the
  snapshot. Packaging never rereads the original path.
- A locked build fails if a new snapshot differs from the locked source tree.

### HTTPS Git

```yaml
- name: release-content
  type: git
  mountPath: release
  config:
    url: https://github.com/example/release-content.git
    ref: v1.2.3
    subPath: bundles/default
```

Rules:

- `url` must use HTTPS in v1.
- `ref` is required during lock creation and may be a branch, tag, or commit.
- The lock records the resolved commit object format and identifier.
- A build fetches and checks out the locked commit, not the mutable authored
  ref, and verifies the filtered DevProof tree digest.
- `subPath` is optional and uses canonical slash-separated path syntax.
- Git configuration that changes file bytes is disabled or fixed by the
  resolver.
- Submodules and Git LFS materialization are rejected in v1. A Git LFS pointer
  is ordinary file content only when no LFS metadata marks the selected path.
- The repository's `.git` administrative directory is never source content.
- Redirects to another host require explicit authorization and never receive
  credentials intended for the original host.

The DevProof source tree digest, not the Git object identifier, is the common
content identity across source types.

### Extension sources

Extension types must contain a domain-qualified name such as
`storage.example.com/object`. Their `config` value is decoded and validated by
the registered resolver.

The lock records the exact type name and resolver identity. An unregistered
type, an unknown config field, or a resolver that cannot produce immutable
material is an error.

## Selection patterns

Patterns are evaluated against normalized source-relative paths after
`subPath` selection and before `mountPath` is added.

V1 pattern syntax is slash-separated and supports:

- `*` for zero or more non-separator characters;
- `?` for one non-separator character;
- character classes such as `[a-z]`; and
- `**` for zero or more complete path segments.

There is no negation, ordering, or `.gitignore` inheritance.

- An absent `include` means `**`.
- A path must match at least one include pattern.
- A path matching any exclude pattern is then removed.
- Pattern arrays are treated as sets and sorted in the lock.
- A pattern that escapes the selected root is invalid.
- A source selecting no regular files is an error.

## Mounting and composition

`mountPath` is normalized using the portable path rules. `.` means the bundle
root. The final path is `mountPath/sourceRelativePath`.

The composer rejects:

- two source files mapping to the same final path;
- a file whose path is an ancestor of another file;
- two paths that collide after Unicode normalization or case folding;
- a path invalid on any supported portable-profile platform; and
- a manifest whose complete selection is empty.

Collisions fail even when file contents are equal because ownership would be
ambiguous. Source list order is never precedence.

## Lock example

The complete grammar is the
[bundle-lock schema](../schemas/bundle-lock.v1alpha1.schema.json). The
structural contract is:

```json
{
  "apiVersion": "devproof.thingz.io/v1alpha1",
  "kind": "BundleLock",
  "manifestDigest": "sha256:4c...",
  "format": "devproof-bundle-v1",
  "sources": [
    {
      "name": "application",
      "type": "git",
      "resolver": "devproof.thingz.io/git/v1",
      "requested": {
        "url": "https://github.com/example/application.git",
        "ref": "main",
        "subPath": "deploy"
      },
      "resolved": {
        "objectFormat": "sha1",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "treeDigest": "sha256:8b..."
      },
      "mountPath": "app",
      "include": ["config/**", "scripts/**"],
      "exclude": ["**/*.tmp"]
    }
  ],
  "files": [
    {
      "path": "app/config/service.yaml",
      "source": "application",
      "sourcePath": "config/service.yaml",
      "mode": 420,
      "size": 913,
      "digest": "sha256:31..."
    }
  ],
  "treeDigest": "sha256:90..."
}
```

The example digests are truncated and are not test vectors.

## Lock canonicalization

The lock is serialized as UTF-8 JSON using RFC 8785 JSON canonicalization.
Arrays whose semantics are sets are sorted before serialization. `sources` is
sorted by source name and `files` by canonical final-path bytes.

The lock contains no timestamp, local absolute path, credential, hostname, user
identity, or registry destination. Its SHA-256 digest is computed over the exact
canonical bytes and may be recorded as a provenance material.

The manifest digest is computed by decoding the manifest to its typed model,
normalizing defaults and set-like arrays, encoding that model with RFC 8785,
and hashing the canonical bytes. YAML spelling, comments, key order, and line
endings therefore do not affect the digest.

## Lock operations

`lock` resolves every source and writes the complete lock atomically. It does
not emit a partial lock.

`lock --check` performs the same resolution but does not write. It succeeds only
when the existing lock's canonical bytes match the newly resolved result.

A locked build validates:

- manifest digest;
- source resolver type and compatible resolver version;
- immutable source resolution;
- per-source tree digest;
- final file inventory; and
- final tree digest.

Any mismatch is a stale-lock error. The user must explicitly refresh the lock
or restore the expected source material.

## Sensitive values

Manifest and lock schemas do not contain registry passwords, Git tokens,
private keys, OIDC tokens, credential-helper output, or secret HTTP headers.
Resolver configuration may contain a credential-provider name or host alias,
but the actual credential is obtained at runtime and redacted from diagnostics.
