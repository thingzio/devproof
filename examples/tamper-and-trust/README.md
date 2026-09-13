# Demo: what a digest is worth

This walkthrough shows why a DevProof artifact has the same name everywhere,
what "verified" does and does not mean, and what happens when someone changes
the bytes after the fact.

It takes about five minutes, runs entirely on your machine — no registry, no
network, no keys — and leaves everything in one directory you can delete
afterwards.

You need `devproof` on your `PATH` ([install](../../README.md#install)) and
`python3`, used once to read a digest out of JSON.

> **Step 5 needs `v0.2.0` or newer.** Check with `devproof version`. Standalone
> `verify` did not read the payload before that release, so on `v0.1.1` the
> tampered artifact in that step still reports `integrity: pass` — which is the
> behaviour the fix removed, not the one the step demonstrates. Every other
> step works on any version.

```bash
mkdir devproof-demo && cd devproof-demo
```

---

## 1. A name derived from content

Configuration usually arrives as a tarball, and a tarball's name is whatever
someone typed. Build the same content twice, into two different directories:

```bash
mkdir config
printf 'replicas: 3\n'  > config/app.yaml
printf 'timeout: 30s\n' > config/limits.yaml

devproof build ./config --to oci-layout://./bundle       --tag v1
devproof build ./config --to oci-layout://./bundle-again --tag v1 --quiet
```

```console
reference:       oci-layout://./bundle@sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
subject:         sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
tree digest:     sha256:ad7902ef364cb7817493821ae9a53d409d4abbf415302ce0b0937215e5dcfe2a
format:          devproof-bundle-v1
files:           2
bytes:           25
layer bytes:     141
tag:             v1

oci-layout://./bundle-again@sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
```

**The two digests are identical.** Different directory, different moment, same
name — and you would get that same name on another machine, on another
operating system, next year.

That is the whole foundation. The digest is a function of the content and
nothing else: not the time, not the path, not the machine, not who ran it. The
`tree digest` on the line above names the payload independently of how it was
encoded; how both are computed is the
[bundle format](../../docs/bundle-format.md#content-and-tree-digests).
Everything below depends on it, because a name that drifts cannot be used to
agree about anything.

---

## 2. "Verified" is three questions, not one

```bash
devproof verify oci-layout://./bundle:v1
```

```console
subject:         sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
tree digest:     sha256:ad7902ef364cb7817493821ae9a53d409d4abbf415302ce0b0937215e5dcfe2a
integrity:       pass
trust:           not-evaluated
semantics:       not-evaluated
  [warning] policy-not-supplied: no verification policy was supplied, so trust was not evaluated; integrity alone does not establish that this artifact came from anyone in particular
```

Most tools print one green check here. DevProof reports
[three separate things](../../docs/policy.md#result-dimensions), and two of
them say `not-evaluated` rather than `pass`:

- **integrity** — are these the bytes the artifact claims? Checked always. It
  fetched the payload, hashed it, and compared every file against the
  inventory.
- **trust** — who produced them, and do you accept that? Nobody asked, so
  nothing was checked.
- **semantics** — is the content valid for your use? Reserved; always
  `not-evaluated` today.

`not-evaluated` is deliberately not a synonym for `pass`. If your trust
configuration silently failed to load, you see this instead of a green check —
which is the difference between knowing and assuming.

---

## 3. Unpacking is lossless

```bash
devproof expand oci-layout://./bundle:v1 --to ./unpacked
ls unpacked
```

```console
destination:     /your/path/devproof-demo/unpacked
subject:         sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
tree digest:     sha256:ad7902ef364cb7817493821ae9a53d409d4abbf415302ce0b0937215e5dcfe2a
files:           2
bytes:           25
integrity:       pass
trust:           not-evaluated

app.yaml
limits.yaml
```

Now rebuild from what you just unpacked:

```bash
devproof build ./unpacked --to oci-layout://./rebuilt --tag v1 --quiet
```

```console
oci-layout://./rebuilt@sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
```

**The same digest again**, after a full round trip through the filesystem.
Pack, unpack, repack — the identity survives, so an artifact that travelled
through a registry, a laptop, and an air-gapped transfer is still provably the
same artifact.

---

## 4. A failed policy writes nothing

Policy is how you say what you will accept. A
[`VerificationPolicy`](../../docs/policy.md) is a document you supply — never
read from the artifact it judges, since an attacker who controls a bundle must
not control the rules applied to it. This one requires signed
[provenance](../../docs/bundle-format.md#provenance-and-signatures), and the
bundle you built is unsigned:

```bash
cat > policy.yaml <<'EOF'
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release-gate
spec:
  provenance:
    required: true
EOF

devproof expand oci-layout://./bundle:v1 --to ./gated --policy policy.yaml
echo "exit: $?"
ls ./gated
```

```console
error: the policy was not satisfied, so nothing was written (path sha256:a7bc634e19...)
exit: 5
ls: ./gated: No such file or directory
```

Look at the last line. The destination **does not exist**. Not created and
then cleaned up — never written at all.

That distinction is the point. Content that is written and then deleted has
already been readable by anything watching the directory, so cleaning up
afterwards is not the same guarantee as never having written it. The policy is
evaluated before a single byte reaches disk, and expansion itself is
[staged and published atomically](../../docs/security.md#local-filesystem-handling).

The non-zero exit is what makes this usable as a CI gate: a pipeline step
built on it cannot pass by accident.

---

## 5. Changing the bytes is caught

This is the case everything else exists for. Build a different bundle, then
overwrite the good bundle's payload with the attacker's — keeping the original
file name, so the store still claims it is serving the original content:

```bash
mkdir attacker-content
printf 'replicas: 999\n' > attacker-content/app.yaml
printf 'timeout: 1s\n'   > attacker-content/limits.yaml
devproof build ./attacker-content --to oci-layout://./attacker --tag v1 --quiet

# A layout stores each blob in a file named after its own digest, so to
# overwrite one you first have to know its name. `devproof inspect` reports
# the payload layer's digest; python3 pulls that field out of the JSON and
# strips the leading "sha256:", leaving just the file name.
#
# Nothing about this is privileged. Anyone who can write to the store can do
# it, which is the point of the step.
layer_of() {
  devproof inspect "$1" --format json |
    python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["subject"]["layerDigest"][7:])'
}

# Overwrite the good bundle's payload with the attacker's, under the good
# bundle's file name. The store now serves bytes that are not the ones its
# name promises.
cp "attacker/blobs/sha256/$(layer_of oci-layout://./attacker:v1)" \
   "bundle/blobs/sha256/$(layer_of oci-layout://./bundle:v1)"
```

Nothing about the bundle's metadata changed. Its manifest, its config, its tag
and its digest are all exactly as they were. Only the stored payload is
different:

```bash
devproof verify oci-layout://./bundle:v1
echo "exit: $?"
```

```console
error: entry is 14 bytes, the inventory declares 12 (path app.yaml)
exit: 4
```

**It names the file.** Verification streamed the payload and checked every
entry against the inventory the manifest commits to, and `app.yaml` is not the
file that inventory describes.

Had the attacker been more careful — same files, same bytes, merely a
different compression — the layer's own digest would not have matched its
descriptor, and it would have failed there instead.

Now check the copy you built in step 1 and never touched:

```bash
devproof verify oci-layout://./bundle-again:v1
```

```console
subject:         sha256:a7bc634e197ed62ebd329cfa27c0711a1472fa4d6b6209301fa902577ea08de7
integrity:       pass
```

Two artifacts with **the same digest and the same tag**: one altered on disk,
one not. One fails, one passes. The name alone was never the guarantee —
checking it is.

---

## What we saw

- **A name derived from content.** The same input produced the same digest
  twice, and would on any supported machine, indefinitely.
- **Three answers, not one.** Integrity, trust, and semantics are reported
  separately, and a question nobody asked returns `not-evaluated` rather than
  a green check.
- **A lossless round trip.** Pack, unpack, repack, same digest.
- **A gate that writes nothing when it fails.** The destination never existed,
  and the exit code makes it usable in CI.
- **Tampering caught by reading the bytes.** Untouched metadata did not help
  the altered copy, and an identical artifact beside it still verified.

Not shown here, to keep this to five minutes: signing and trust policy against
a real identity, registries, air-gapped transfer with `--offline`, and
resource bounds set by a policy.

Clean up with `cd .. && rm -rf devproof-demo`.

## Next

- [Verification policy](../../docs/policy.md) — writing trust rules
- [Security model](../../docs/security.md) — the threats this design answers
- [Decisions](../../docs/decisions.md) — why each of these behaviors is the way
  it is
