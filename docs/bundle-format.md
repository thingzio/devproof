# DevProof bundle format v1

Status: proposed normative format. Golden vectors must be added before the
format is declared stable.

## Format objectives

Version 1 defines one portable representation for a canonical filesystem tree.
It must provide:

- a content identity independent of source and build provenance;
- byte-identical OCI subjects for equal canonical trees;
- exact inventory verification without trusting tar extraction behavior;
- one standard gzip filesystem layer for broad OCI interoperability; and
- safe deterministic expansion into the canonical tree.

## Media types

The proposed v1 media types are:

```text
artifact: application/vnd.thingz.devproof.bundle.v1
config:   application/vnd.thingz.devproof.config.v1+json
layer:    application/vnd.oci.image.layer.v1.tar+gzip
```

The bundle manifest uses
`application/vnd.oci.image.manifest.v1+json`.

Changing a media type changes the manifest digest and therefore requires an
explicit format compatibility decision.

## Canonical filesystem model

### Included state

Each canonical file record contains:

- normalized relative path;
- normalized mode, either `0644` or `0755`;
- byte length;
- SHA-256 content digest; and
- exact content bytes in the layer.

Parent directories are derived from file paths. They have mode `0755` and do
not participate as independent records in the tree digest.

### Excluded state

V1 does not represent:

- empty directories;
- symlinks or hard links;
- devices, sockets, or FIFOs;
- user or group ownership;
- access, change, birth, or modification times;
- ACLs, extended attributes, resource forks, or alternate data streams;
- sparse-file layout; or
- native path separators.

A source containing an excluded file type fails. DevProof does not silently
dereference links or omit unsupported entries.

### Mode normalization

A regular file with any execute bit set becomes `0755`; every other regular
file becomes `0644`. Setuid, setgid, sticky, and write/read variations are not
preserved.

For a Git source, the Git tree executable bit is authoritative. For a local
path, the platform's file mode is authoritative. A platform unable to represent
the executable distinction must use explicit locked inventory or refuse to
claim raw-directory round-trip equivalence.

### Path normalization

Paths are normalized before filtering and composition:

1. Decode as valid UTF-8.
2. Have the source adapter join native path components with `/`; never convert
   a literal filename character into a separator.
3. Normalize Unicode to NFC.
4. Remove no semantic segments; reject `.` and `..` segments instead.
5. Require a relative, non-empty path for every file.
6. Reject NUL and control characters.
7. Reject empty segments and repeated separators.
8. Reject segments ending in a space or period.
9. Reject the characters `<`, `>`, `:`, `"`, `\\`, `|`, `?`, and `*` in a
   segment. Reject the case-insensitive device names `CON`, `PRN`, `AUX`, `NUL`,
   `COM1` through `COM9`, and `LPT1` through `LPT9`, including those names with
   an extension.
10. Enforce case-fold uniqueness across the complete tree.

Two original paths that normalize to the same canonical path are an error.
The implementation must not select a winner.

The initial portable limits are subject to the limits decision, but tests must
cover multibyte UTF-8, Unicode normalization, case collisions, deep paths, and
platform-reserved names.

## Content and tree digests

File content uses SHA-256 over the exact file bytes.

The v1 tree digest is SHA-256 over this binary sequence:

```text
ASCII bytes: "devproof-tree-v1\x00"
uint64be:    number of file records

for each record, sorted by canonical UTF-8 path bytes:
  uint32be:  path byte length
  bytes:     canonical UTF-8 path
  uint32be:  normalized mode
  uint64be:  file byte length
  bytes[32]: raw SHA-256 content digest
```

There is no padding, delimiter, or terminal record beyond the fields shown.
All integer values are unsigned and encoded in network byte order.

The tree digest is independent from tar and gzip encoding. It gives callers a
stable logical payload identity while the OCI manifest digest identifies the
exact encoded artifact.

## Config blob

The config is UTF-8 JSON encoded with RFC 8785 JSON canonicalization. It has
this logical shape:

```json
{
  "schemaVersion": 1,
  "format": "devproof-bundle-v1",
  "treeDigest": "sha256:90...",
  "fileCount": 1,
  "totalSize": 913,
  "files": [
    {
      "path": "app/config/service.yaml",
      "mode": 420,
      "size": 913,
      "digest": "sha256:31..."
    }
  ]
}
```

File entries are sorted by canonical path bytes. The config contains no bundle
name, source identity, timestamp, builder identity, registry reference, tag,
annotation, or signature.

The complete JSON Schema and a maximum config size must be finalized before
v1 stability. Readers reject unknown schema versions, duplicate paths,
non-canonical ordering, invalid modes, invalid digests, inconsistent totals,
and unknown required semantics.

## Canonical tar layer

The uncompressed layer is a deterministic POSIX tar stream produced from the
config inventory and the frozen snapshot.

Entries are emitted in two runs: every required parent directory in canonical
UTF-8 path order, followed by every file in canonical UTF-8 path order. Each
directory appears at most once, and no root `.` entry is written.

Two runs rather than one merged ordering. Both are deterministic, and both put
every parent before its first child, since a parent is a byte-prefix of its
children. Separating them makes the rule checkable without reference to the
file list: a reader validates that directories ascend, that files ascend, and
that no directory follows a file. A single merged order would require a reader
to derive the expected directory set before it could tell correct placement
from incorrect, which is more work to state and more work to get right.

Every directory header has:

```text
type:     directory
mode:     0755
uid/gid:  0/0
uname:    empty
gname:    empty
size:     0
mtime:    Unix epoch
atime:    Unix epoch or absent
ctime:    Unix epoch or absent
linkname: empty
```

Every file header has the same fixed ownership and time fields, type `regular`,
the canonical path, normalized mode, and exact content size.

V1 uses a deterministic PAX encoding for values not representable directly in
a USTAR header. Only records required for the canonical path or size may be
emitted. Record order, header naming, numeric encoding, and padding are fixed by
the normative golden vectors. No implementation-specific PAX records are
allowed.

Tar padding bytes are zero. Exactly two zero blocks terminate the archive. No
bytes follow the terminator in the uncompressed stream.

The packager hashes file bytes while writing and compares them with the frozen
inventory. A mismatch fails before an OCI manifest is published.

## Canonical gzip encoding

The tar stream is compressed with the format-v1 DEFLATE settings and:

```text
compression level: 9
mtime:             0
OS:                255 (unknown)
name:              empty
comment:           empty
extra:             empty
```

The reference encoder and normative compressed golden vectors define exact v1
bytes. A runtime or dependency update that changes compressed bytes must retain
the v1 encoder behavior or introduce a new format version.

## OCI manifest

The OCI subject is a canonical JSON OCI image manifest containing:

- `schemaVersion: 2`;
- the OCI image manifest media type;
- the DevProof v1 artifact type;
- one descriptor for the DevProof config; and
- exactly one descriptor for the gzip layer.

The subject manifest has no `subject` field. V1 subject manifests omit
annotations so that non-content metadata cannot enter identity. Descriptor
sizes and SHA-256 digests are calculated from the exact canonical blobs.

The manifest JSON uses RFC 8785 canonicalization. A builder must fetch or read
back the stored manifest and compare its descriptor before reporting
publication success or assigning a requested tag.

## Provenance and signatures

Evidence names the OCI manifest digest as its subject. A provenance statement
should include:

- manifest and lock digests;
- each source's type, logical name, immutable resolution, and filtered tree
  digest;
- resolver identity and version;
- DevProof version and bundle format version;
- invocation parameters that affect evidence but not payload identity; and
- builder identity when established by the attester.

Evidence may include time. Signatures and transparency-log material are
expected to vary. None of these bytes are part of the subject.

Signed provenance uses an in-toto Statement v1 in a DSSE-compatible Sigstore
bundle. The exact predicate schema and referrer media types must be frozen
before the evidence API is declared stable.

Evidence is stored through the OCI subject/referrers relationship. Offline
export uses an OCI image layout containing the subject and selected referrers.
Copy operations must preserve subject and evidence digests and must report any
referrer that could not be copied.

## Verification rules

An artifact passes structural and content integrity only when:

- manifest, config, and layer descriptors match fetched bytes;
- media types and cardinality match format v1;
- config JSON is valid and internally consistent;
- the tar contains exactly the config inventory and required parent
  directories;
- there are no duplicate, extra, missing, or unsupported entries;
- every path and mode is canonical;
- every file size and content digest matches;
- the recomputed tree digest matches the config; and
- no configured extraction limit is exceeded.

Evidence and policy are evaluated only after the subject passes integrity.
Integrity success alone does not imply trust.

## Expansion rules

Expansion creates only the payload files and their required parent directories;
it does not write evidence, lock data, or OCI metadata into the payload tree.

The expander must reject an entry before opening its destination when the entry:

- is absent from the config inventory;
- is duplicated;
- is not a regular file or required directory;
- is absolute or escapes the staging root;
- is non-canonical or aliases another path;
- exceeds count, size, depth, or compression limits; or
- conflicts with an already created file or directory.

Files are created without following links, with private temporary permissions,
then set to their canonical mode after content verification. Ownership and
timestamps are not restored from the archive.

## Round-trip guarantees

For supported platforms capable of representing the v1 canonical model:

```text
canonical tree T
  -> build format v1
  -> OCI subject digest D
  -> verify and expand
  -> canonical tree T
  -> build format v1
  -> OCI subject digest D
```

The guarantee excludes:

- tags and registry repository names;
- signatures, attestations, and referrer indexes;
- non-canonical source metadata;
- empty directories and unsupported file types; and
- semantic meaning of payload bytes.

The second build produces new provenance evidence because its immediate source
and invocation differ, but its subject digest remains `D`.

The following are separate compatibility assertions and must be tested:

- equal tree digest;
- equal uncompressed tar digest;
- equal compressed layer digest;
- equal config digest; and
- equal OCI manifest digest.

## Versioning

The format identifier is immutable once released. Readers dispatch by config
format and artifact media type. They reject unsupported versions rather than
guessing.

A new version may change path rules, supported file types, tree-record encoding,
archive encoding, compression, config schema, or manifest structure. A new
version must document whether and how an old canonical tree maps to the new
one; equal logical content is not assumed to retain the same OCI digest across
format versions.
