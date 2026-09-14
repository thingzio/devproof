# DevProof JSON Schemas

Machine-readable schemas for every document DevProof reads, and the one it
writes.

| Schema | Document | `apiVersion` / `kind` |
| --- | --- | --- |
| [`bundle.v1alpha1`](bundle.v1alpha1.schema.json) | bundle manifest, usually `devproof.yaml` | `devproof.thingz.io/v1alpha1` · `Bundle` |
| [`bundle-lock.v1alpha1`](bundle-lock.v1alpha1.schema.json) | lock, usually `devproof.lock.json` | `devproof.thingz.io/v1alpha1` · `BundleLock` |
| [`verification-policy.v1alpha1`](verification-policy.v1alpha1.schema.json) | verification policy | `devproof.thingz.io/v1alpha1` · `VerificationPolicy` |
| [`bundle-config.v1`](bundle-config.v1.schema.json) | the OCI config blob inside a bundle | format `devproof-bundle-v1` |
| [`proof-report.v1`](proof-report.v1.schema.json) | the verification result DevProof **produces** | — |

The proof report is the odd one out, and the difference matters. The other four
describe input, and their decoders are strict: an unknown field is an error,
because a field this build does not understand may be load-bearing for whoever
wrote it. The report describes output, and nothing decodes it strictly — a
consumer that ignores a field a later version added should degrade rather than
fail. What does not change is the meaning of a field that is present.

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
  working;
- `subjectPattern` must be a valid regular expression; and
- `evidence.maxAge` is measured from an authenticated signing time, so evidence
  carrying none fails the rule rather than satisfying it. The pattern here
  constrains the spelling of the duration, not what it means.

**Proof report**

- `semantics` is `pass` only if every entry in `validators` passed, and the
  absence of that array with `semantics: pass` is not a valid result; and
- a `not-evaluated` dimension is never a pass, which is a rule about how a
  consumer reads the document rather than about its shape.

The path and sorting rules are the ones worth knowing about, because they are
what make a config describe exactly one archive. JSON Schema can say an array
holds objects with a `path` string; it cannot say the array is sorted, that
its entries are unique after Unicode case folding, or that a separate digest
field was computed over them.

## Versioning

A schema's identity is its `$id`. Document versions follow `apiVersion` and
`kind`, which are versioned independently of the bundle format and of the Go
module — see [docs/compatibility.md](../docs/compatibility.md).

Decoding is strict for the four input documents, so adding a field to one of
them requires a new `apiVersion` rather than a compatible schema revision. That
cost is deliberate: a reader that ignored an unrecognized field would silently
not enforce a rule somebody wrote down.

The proof report is the exception in this direction too. It is output, nothing
decodes it strictly, and a field may be added within `v1` — which is what makes
a consumer that ignores unrecognized fields the correct kind of consumer.
