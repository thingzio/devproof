# Normative byte vectors

These files are the normative encoding of DevProof bundle format v1. They are
published rather than kept in a `testdata` directory because an implementation
in another language has to be able to read them.

Two implementations that agree on every value and disagree on a spelling give
one payload two identities. Comparing values is therefore not enough, and these
are the bytes to compare against.

## The input tree

Every file under `format/v1/` describes one tree. It is small and deliberately
awkward: it exercises an empty file, binary content, nesting, both normalized
modes, a multibyte path, byte-order sorting across cases, and a path long enough
to need a PAX extended header.

| Path | Mode | Content |
| --- | --- | --- |
| `README.md` | `0644` | `hello world\n` |
| `app/config/service.yaml` | `0644` | `a: 1\n` |
| `app/scripts/run.sh` | `0755` | `#!/bin/sh\ns\n` |
| `binary.dat` | `0644` | bytes `00 01 fe ff` |
| `café/naïve.txt` | `0644` | `utf` |
| `directory/`×12 + `deep.txt` | `0644` | `deep` |
| `empty` | `0644` | empty |

`café/naïve.txt` is NFC. The `directory/` path repeats the segment twelve times,
which puts the full path past the 100-byte USTAR name field.

## The files

| File | What it is |
| --- | --- |
| `tree-records.bin` | the canonical record stream the tree digest is taken over |
| `tree-digest.txt` | the tree digest of that stream |
| `layer.tar` | the uncompressed canonical tar |
| `layer.tar.gz` | that tar under the frozen v1 gzip encoding; the blob the layer descriptor covers |
| `config.json` | the DevProof config blob, RFC 8785 canonical |
| `manifest.json` | the OCI image manifest, RFC 8785 canonical |
| `subject-digest.txt` | the SHA-256 of `manifest.json`, which is the artifact's identity |
| `gzip-sample.gz` | a short fixed payload under the same gzip settings, to separate a compressor difference from a tar one |

`manifest.json` references `config.json` and `layer.tar.gz` by digest and size,
so the set is one artifact rather than a collection of samples.

## Using them

A Go implementation can check a set with
[`conformance.VerifyVectors`](../pkg/conformance), which reads the manifest,
config, and layer as one artifact at the canonical level and compares the
published digests against recomputed ones:

```go
report, err := conformance.VerifyVectors(os.DirFS("vectors/format/v1"))
```

Point it at your own output directory to check your encoder. An implementation
in another language compares its bytes with these files directly; the
`gzip-sample.gz` and `layer.tar` files exist so that a mismatch can be narrowed
to the compressor or the tar encoder rather than reported as "the layer digest
is wrong".

These are positive vectors. The negative ones — archives that are structurally
plausible and not conforming — are generated rather than stored, in
[`pkg/conformance/vectors_test.go`](../pkg/conformance/vectors_test.go), because
each is a one-field edit of the conforming case and a stored copy would hide
which field.

## Changing them

Regenerating these files is correct only when introducing a new format version,
never when an existing one looks wrong. A change here reissues every subject
digest under a new identity.

```sh
make regen-golden
```

See [DP-015](../docs/decisions.md) and
[docs/bundle-format.md](../docs/bundle-format.md).
