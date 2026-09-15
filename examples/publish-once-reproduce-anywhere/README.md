# Demo: one publisher, many verifiers

One party builds an artifact and publishes it to a registry. Everyone else
gets the same artifact — and, more to the point, does not have to take the
publisher's word for what is in it. Each consumer rebuilds it from the same
pinned inputs, on their own machine, on their own operating system, and checks
that what they built is byte-for-byte the thing that was published.

That last sentence is the whole example. Distributing a file is not hard.
Distributing a file that N unrelated parties can independently *regenerate*
and confirm is a different problem, and it is the one that usually gets skipped
because it is tedious enough to skip.

About ten minutes. You need `devproof` ≥ `v0.5.0`
([install](../../README.md#install)), network access to `github.com` and
`ghcr.io`, and — for the air-gap step only — `cosign`, which is how you get a
Sigstore trusted root onto disk. DevProof has no command that emits one.

Nothing here needs a GitHub account, a key, or write access to anything. Every
command below reads.

```bash
mkdir devproof-consumer && cd devproof-consumer
```

---

## 0. What was published

```text
oci://ghcr.io/thingzio/devproof/example-baseline:v1
sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
```

A GB200 NVL72 qualified firmware stack — 48 files of component versions, the
same content the [firmware catalog example](../firmware-catalog/) builds
locally. What it contains matters less here than how it travels; that example
is the one about the payload, and it is worth reading for what signing a
version catalog does and does not claim. Nothing in this walkthrough
authenticates firmware.

It was published once, by
[`publish-example.yaml`](../../.github/workflows/publish-example.yaml), signed
keyless. It will not be republished: the digest above is permanent, so this
document can name it and stay true.

The registry is mostly incidental: the subject digest is a function of content,
so Artifact Registry or `distribution` ≥ 3.0 would give the same digest for the
same commands on a different host
([interoperability](../../docs/interoperability.md)).

Mostly, but not entirely — and section 1 is where that shows up. Registries
differ in exactly one place that matters here: whether they implement the OCI
1.1 **referrers API**, which is what lets a signature be found next to the
artifact rather than in a sidecar file somebody has to remember to copy. GHCR,
at the time of writing, answers the referrers request for this artifact with
`404`. That is not a flaw in the artifact and it does not make the signature
worth less, but it is not something a consumer should discover by accident.

---

## 1. Who published it?

Start with trust, because integrity without it answers the wrong question. A
policy is a document *you* write. It is never read from the artifact it judges
— an attacker who controls a bundle must not also control the rules applied to
it.

```bash
cat > policy.yaml <<'EOF'
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: accept-the-publisher
spec:
  subject:
    requireDigestReference: true
  provenance:
    required: true
  signatures:
    threshold: 1
    requireTransparencyLog: true
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        subjectPattern: "^https://github\\.com/thingzio/devproof/\\.github/workflows/publish-example\\.yaml@refs/heads/main$"
EOF

devproof verify \
  oci://ghcr.io/thingzio/devproof/example-baseline@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6 \
  --policy policy.yaml
echo "exit: $?"
```

```console
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
tree digest:     sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
integrity:       pass
trust:           fail
semantics:       not-evaluated
policy:          accept-the-publisher
policy digest:   sha256:9e51405c9aca8aa6c58d5786e4b7f7bb9a32680054a4c15548cba64efe5ebf95
signed by:       https://github.com/thingzio/devproof/.github/workflows/publish-example.yaml@refs/heads/main (https://token.actions.githubusercontent.com)
evidence:        tag-fallback
  [error] evidence-tag-fallback-not-allowed: this evidence was found under the fallback tag scheme, which cannot express a set of evidence and silently replaces; the policy does not allow it (sha256:9163bbcc8faa6e2140df79dbe5d12f4714a5ba7066f38bf40e3a3b50ddeb327b)
error: the policy was not satisfied: evidence-tag-fallback-not-allowed (path sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6)
exit: 5
```

**That is a refusal, and it is the most useful output in this walkthrough.**

The signature is fine. It is the right identity, and the log inclusion proof
checks out — the line above says so. What failed is *how the signature was
found*. GHCR answers the OCI 1.1 referrers request for this artifact with
`404`, so DevProof fell back to the tag scheme, and this policy did not permit
that.

You can confirm the registry's answer yourself:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" \
  https://ghcr.io/v2/thingzio/devproof/example-baseline/referrers/sha256:e48f...
```

The fallback works by storing evidence under a tag derived from the subject
digest. That is not equivalent to a referrers list: a tag holds one thing, so
it cannot express a *set* of evidence, and a second signature pushed later
silently replaces the first rather than joining it. An attacker who can write
one tag can therefore remove a signature without breaking anything a naive
reader would notice.

None of that makes the fallback useless. It makes it a decision. DevProof
reports which mechanism produced the evidence and requires a policy to opt in
(DP-028), rather than using it silently — the difference between knowing and
assuming, which is the same distinction `not-evaluated` draws elsewhere.

So decide, explicitly:

```bash
cp policy.yaml accept.yaml
cat >> accept.yaml <<'EOF'
  evidence:
    allowTagFallback: true
EOF

devproof verify \
  oci://ghcr.io/thingzio/devproof/example-baseline@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6 \
  --policy accept.yaml
```

```console
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
tree digest:     sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
integrity:       pass
trust:           pass
semantics:       not-evaluated
policy:          accept-the-publisher
policy digest:   sha256:944fcfaac583b84313c4166d9cbd31eceb9bcd39c8cc6adf9dea7d1a8f9018da
signed by:       https://github.com/thingzio/devproof/.github/workflows/publish-example.yaml@refs/heads/main (https://token.actions.githubusercontent.com)
evidence:        tag-fallback
```

`trust: pass`, and the line above it names the workflow that signed. The
`policy digest` changed with the policy, which is what makes a report auditable:
it records which rules produced this verdict, not merely that some rules did.

Now note what the policy pins. Not a key — a **workflow**. There is no public key
in that document and no secret on the publisher's side either: the signature
was made with a short-lived certificate issued against the OIDC token the CI
runner already had, recorded in a public transparency log, with the private key
discarded before the job ended. Rotating a key cannot invalidate this policy,
because there is no key to rotate.

Three details are load-bearing:

- **`subjectPattern` is anchored.** `^` and `$` are not decoration. Without
  them, a pattern matching `thingzio/devproof` also matches
  `attacker/devproof-evil`, and the certificate for that is perfectly valid.
- **It pins a workflow file and a ref**, not a repository. Anyone who can push
  a branch can otherwise run a workflow that signs as this repository.
- **`requireTransparencyLog`** demands a proven log inclusion, not merely that
  a log was mentioned. The public record is most of what keyless buys you.

A policy that accepts everything looks exactly like a policy that works, so
check that this one refuses the right thing. Derived from `accept.yaml`, so the
identity is the only difference between passing and failing:

```bash
sed 's|publish-example|some-other-workflow|' accept.yaml > wrong.yaml
devproof verify \
  oci://ghcr.io/thingzio/devproof/example-baseline@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6 \
  --policy wrong.yaml
echo "exit: $?"
```

```console
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
integrity:       pass
trust:           fail
semantics:       not-evaluated
policy:          accept-the-publisher
evidence:        tag-fallback
  [error] signature-threshold-not-met: the policy requires 1 distinct accepted signing identities, and 0 verified (sha256:e48f5b24...)
  [error] transparency-proof-required: the policy requires a transparency-log inclusion proof, and no evidence was accepted (sha256:e48f5b24...)
  [error] provenance-required: the policy requires provenance, and no verified evidence was found (sha256:e48f5b24...)
error: the policy was not satisfied: signature-threshold-not-met, transparency-proof-required, provenance-required (path sha256:e48f5b24...)
exit: 5
```

Note that the `signed by:` line is **gone**. The signature did not become
invalid — it is the same signature as before. It stopped counting, because the
identity it carries is not one this policy accepts, so zero identities were
accepted and every rule that needed one failed with it.

---

## 2. Rebuild it yourself

Here is the part that is hard without this tool.

The publisher built from two small files. Fetch them — from `main`, which is
not a trusted source and does not need to be; step 3 is what settles whether
you got the right ones:

```bash
base=https://raw.githubusercontent.com/thingzio/devproof/main/examples/publish-once-reproduce-anywhere
curl -fsSLO "$base/devproof.yaml"
curl -fsSLO "$base/devproof.lock.json"
```

The manifest records intent and names a *tag*:

```yaml
config:
  url: https://github.com/thingzio/devproof.git
  ref: v0.5.0
  subPath: examples/firmware-catalog/catalog/gb200-nvl72-1.3.10
```

A tag is a pointer, and a pointer can be moved. The lock is what makes that
harmless — it records the commit the tag resolved to when it was written, and
a build uses the commit:

```json
"requested": { "ref": "v0.5.0", ... },
"resolved":  { "commit": "48c7af841c3fcd193a8a8ee0853a12b8cbdaa18e", ... }
```

If someone moves `v0.5.0` tomorrow, your build does not quietly package
different content. It fails, and you re-lock deliberately.

Now build. No registry, no credentials, no coordination with the publisher:

```bash
devproof build -f devproof.yaml --lock devproof.lock.json \
  --to oci-layout://./rebuilt --tag v1 --quiet
```

```console
oci-layout://./rebuilt@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
```

**That is the published digest**, from section 0, produced on your machine.
Not a copy of it — a rebuild of it, from source, on whatever operating system
you happen to be running.

---

## 3. Confirm it, rather than eyeballing it

```bash
devproof diff \
  oci://ghcr.io/thingzio/devproof/example-baseline:v1 \
  oci-layout://./rebuilt:v1
echo "exit: $?"
```

```console
from:            sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
to:              sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
result:          identical
exit: 0
```

Exit `0` means identical; `1` means they differ. A difference is an answer
rather than a failure, which is what makes this usable as a pipeline step:

```sh
if ! devproof diff "$PUBLISHED" oci-layout://./rebuilt:v1 --quiet-if-same; then
  echo "the published artifact is not what these inputs build" >&2
  exit 1
fi
```

The trust chain closes here, and it is worth being precise about how. Section 1
established that a workflow you named signed the artifact. Section 2 rebuilt
the artifact from inputs you fetched over plain HTTPS from an untrusted branch.
This step says those two things are the same bytes — so a tampered lock is
caught, not because the lock was trustworthy, but because a lock describing
different content would have produced a different digest and this comparison
would have failed. You never had to trust `raw.githubusercontent.com`.

---

## 4. The same digest on a different operating system

Everything above is one machine agreeing with itself, which is the weakest
possible version of the claim. The interesting question is whether a macOS
laptop and a Linux CI runner agree.

They do, and this repository proves it continuously rather than asserting it:
the [`example-reproduce` job](../../.github/workflows/ci.yaml) runs section 2
on `ubuntu-latest` and `macos-latest` on every push and requires both to
produce the digest this document names. The
[determinism matrix](../../docs/testing.md) covers linux/amd64, linux/arm64,
and darwin/arm64 for the format as a whole.

This is not free, and it is where the comparison to rolling your own gets
concrete. Filesystems disagree about things a naive archive records: mtimes,
uid and gid, directory ordering, mode bits beyond the executable one, APFS
folding case where ext4 does not, extended attributes that macOS adds without
being asked. A `tar` of the same tree on two machines is two different files.
The [bundle format](../../docs/bundle-format.md) specifies exactly one encoding
for a given tree, which is what makes "did we get the same thing" a digest
comparison instead of a recursive diff with a list of exceptions.

---

## 5. Across an air gap

A site with no route to `ghcr.io` still needs all of this to work. Three things
have to travel, and the third is the one people forget.

On a connected machine:

```bash
devproof copy \
  oci://ghcr.io/thingzio/devproof/example-baseline@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6 \
  --to oci-layout://./transfer --tag v1

# The trusted root is a TUF target. `cosign initialize` populates the cache it
# lives in; the path inside that cache is cosign's business and has moved
# between versions, so find it rather than hard-coding it.
#
# Not `cosign trusted-root create` -- that builds a root from verification
# material you supply, for a private Sigstore, and with no arguments it
# cheerfully writes an empty one.
cosign initialize
find ~/.sigstore/root -name trusted_root.json -exec cp {} ./trusted_root.json \;
```

```console
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
from:            oci://ghcr.io/thingzio/devproof/example-baseline@sha256:e48f5b24...
to:              oci-layout://./transfer@sha256:e48f5b24...
tag:             v1
```

`copy` carries **every** referrer, not only the ones DevProof recognizes. A
mirror that silently dropped what it did not understand would leave a gap
nobody could see, and an export for an air gap gets one attempt to carry the
signature across; discovering afterwards is discovering too late.

`trusted_root.json` is the third thing. Keyless verification checks a
certificate chain and a log inclusion proof, and on the far side there is no
Fulcio and no Rekor to ask — so the trust material has to be carried like the
artifact is. `devproof verify --offline` **requires** `--trust-root` rather
than falling back to a network fetch or, worse, to skipping the check:

```bash
# ...having moved ./transfer and trusted_root.json across...
#
# By digest, not by tag: accept.yaml sets requireDigestReference, so a tag is
# refused before anything is fetched. On the far side of an air gap that rule
# earns its keep -- a tag is the one part of a transfer that can be rewritten
# without the bytes changing.
devproof verify \
  oci-layout://./transfer@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6 \
  --offline --trust-root trusted_root.json --policy accept.yaml
```

```console
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
tree digest:     sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
integrity:       pass
trust:           pass
semantics:       not-evaluated
policy:          accept-the-publisher
policy digest:   sha256:944fcfaac583b84313c4166d9cbd31eceb9bcd39c8cc6adf9dea7d1a8f9018da
signed by:       https://github.com/thingzio/devproof/.github/workflows/publish-example.yaml@refs/heads/main (https://token.actions.githubusercontent.com)
evidence:        referrers
```

Look at the last line. Reading the same artifact from GHCR reported
`tag-fallback`; reading it from the layout reports `referrers`. Nothing about
the evidence changed — `copy` rebuilds the referrer record at the destination,
and a local layout stores one properly. The air-gapped copy is, in this one
respect, better than the registry it came from.

`--offline` prohibits network access outright. It cannot pass by quietly
reaching out, which is the failure mode that makes air-gapped verification
worth so little in practice.

---

## 6. Use it

```bash
devproof expand oci-layout://./rebuilt:v1 --to ./baseline
ls baseline
```

```console
destination:     /your/path/devproof-consumer/baseline
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
tree digest:     sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
files:           48
bytes:           9414
integrity:       pass
trust:           not-evaluated

bmc
bmc-fpga-erot
cpld
hmc
host-software-components
nvos
powershelf-fw
sbios-erot
SOURCE.yaml
```

`trust: not-evaluated` because no policy was passed to *this* command, and
DevProof will not carry a verdict over from an earlier one. Pass `--policy` and
an unsatisfied policy publishes no destination at all — not written and then
cleaned up, never written, because content that existed briefly was already
readable by anything watching the directory.

---

## What we saw

- **An artifact with one name everywhere.** The digest in section 0 is the
  digest a rebuild produced in section 2, on a different machine.
- **Trust pinned to a workflow, not a key.** No secret on the publishing side,
  nothing to rotate on the consuming side, and a public log entry for the
  signature.
- **A policy that refuses, twice, for different reasons.** Once because the
  registry did not serve referrers and the policy had not opted into the
  fallback, and once because the identity was wrong. A verdict that can only
  come back green tells you nothing when it does.
- **The discovery mechanism reported rather than assumed.** `evidence:
  tag-fallback` is the kind of detail that is invisible in every tool that
  prints one green check, and it changes what a signature is worth.
- **Independent reproduction.** N consumers regenerate the artifact from
  pinned inputs and confirm by digest, without trusting the channel they
  fetched the inputs over.
- **Agreement across operating systems**, enforced on every push rather than
  claimed here.
- **A complete air-gapped transfer**, signature and trust material included,
  with no silent network fallback.

## Why not `tar` and `sha256sum`

Every individual step here has an equivalent: `tar` and `sha256sum`, `cosign`
for the signature, `oras` to push, a shell script to glue them. The example is
not that those tools are incapable.

It is that the glue is where this goes wrong. The reproduce step is the one
that decides whether any of it is worth anything, and it is the one that fails
first, because two `tar` invocations on two operating systems do not produce
the same bytes for the same tree — so the comparison becomes a recursive diff
with a growing list of excusable differences, each of which is a place a real
difference can hide. Then the signature lives in a file beside the artifact
instead of attached to it, and the air-gap export copies the artifact and
forgets the trust root, and `--offline` is a flag nobody implemented so the
verification quietly succeeded by reaching the internet.

None of that is hard to get right once. It is hard to keep right, in a script
nobody owns, across the N parties this example is about.

Clean up with `cd .. && rm -rf devproof-consumer`.

## Next

- [tamper-and-trust](../tamper-and-trust/) — what a digest is worth, in five
  minutes and with no network
- [firmware-catalog](../firmware-catalog/) — the payload used here, and what
  signing a version catalog does not claim
- [Verification policy](../../docs/policy.md) — writing trust rules
- [Interoperability](../../docs/interoperability.md) — the registries this was
  checked against
