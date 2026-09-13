# DevProof JSON Schemas

Machine-readable schemas for every document DevProof reads.

| Schema | Document | `apiVersion` / `kind` |
| --- | --- | --- |
| [`bundle.v1alpha1`](bundle.v1alpha1.schema.json) | bundle manifest, usually `devproof.yaml` | `devproof.thingz.io/v1alpha1` · `Bundle` |
| [`bundle-lock.v1alpha1`](bundle-lock.v1alpha1.schema.json) | lock, usually `devproof.lock.json` | `devproof.thingz.io/v1alpha1` · `BundleLock` |
| [`verification-policy.v1alpha1`](verification-policy.v1alpha1.schema.json) | verification policy | `devproof.thingz.io/v1alpha1` · `VerificationPolicy` |
| [`bundle-config.v1`](bundle-config.v1.schema.json) | the OCI config blob inside a bundle | format `devproof-bundle-v1` |

They are JSON Schema draft 2020-12. The manifest and policy may be written as
YAML or JSON; validate YAML by converting it to JSON first, since these
schemas describe the JSON value model.

## These are normative

The schemas describe the documents; the Go decoders in `pkg/bundle` and
`pkg/policy` are one implementation of them. That is the same relationship
`pkg/conformance` has to the bundle format specification, and it exists for
the same reason: a specification that is only ever compared against the code
that implements it cannot disagree with it, and a specification that cannot
disagree proves nothing.

`internal/schema` holds the test that keeps them honest. It asserts, for every
document type, that:

- a valid document is accepted by both the schema and the decoder;
- an unknown field — at the top level and inside a nested object — is rejected
  by both;
- removing any required property is rejected by both; and
- every limit's schema `maximum` equals the ceiling `bundle.Ceilings()`
  enforces, with no limit present in one and missing from the other.

A schema advertising a bound the loader refuses, or permitting one it does
not, is worse than no schema, because it is believed.

Nothing validates against these at runtime. The decoders already reject
everything the schemas forbid, and shipping a second enforcement path would
mean two things to keep in step rather than one.

## Using them

Most editors pick up a schema from a `$schema` key or a filename association.
For YAML in VS Code, via the Red Hat YAML extension:

```json
{
  "yaml.schemas": {
    "https://devproof.thingz.io/schemas/bundle.v1alpha1.schema.json": "devproof.yaml",
    "https://devproof.thingz.io/schemas/verification-policy.v1alpha1.schema.json": "*policy*.yaml"
  }
}
```

`devproof init` writes a manifest that already conforms, which is usually a
faster start than reading any of this.

## What these schemas cannot express

Every rule below is enforced by the decoder and is **not** checked by schema
validation. A document that validates is well-formed, not necessarily valid.

**Bundle manifest**

- source names must be unique within the manifest;
- a selection pattern must be syntactically valid and must not escape the
  selected root; and
- an extension source type must have a registered resolver.

**Lock**

- `files` must be sorted by path, strictly increasing, so no path repeats;
- every `files[].source` must name a source the lock records;
- `manifestDigest` must match the manifest being built; and
- every resolution must be immutable.

**Bundle config**

- `fileCount` must equal the length of `files`;
- `totalSize` must equal the sum of every entry's `size`;
- `files` must be sorted by canonical UTF-8 path bytes, strictly increasing;
- every path must be canonical: valid UTF-8, NFC-normalized, no `.` or `..`
  segments, no case-fold or normalization alias of another path, and not a
  platform-reserved name; and
- `treeDigest` must equal the digest recomputed from the entries.

**Verification policy**

- `signatures.threshold` must not exceed the number of listed identities — a
  threshold nothing could satisfy is indistinguishable from a policy that is
  working; and
- `subjectPattern` must be a valid regular expression.

The path and sorting rules are the ones worth knowing about, because they are
what make a config describe exactly one archive. JSON Schema can say an array
holds objects with a `path` string; it cannot say the array is sorted, that
its entries are unique after Unicode case folding, or that a separate digest
field was computed over them.

## Versioning

A schema's identity is its `$id`. Document versions follow `apiVersion` and
`kind`, which are versioned independently of the bundle format and of the Go
module — see [docs/compatibility.md](../docs/compatibility.md).

Decoding is strict, so adding a field to any of these documents requires a new
`apiVersion` rather than a compatible schema revision. That cost is deliberate:
a reader that ignored an unrecognized field would silently not enforce a rule
somebody wrote down.
