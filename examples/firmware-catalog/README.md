# Demo: a qualified firmware stack you can verify

> **This is not an NVIDIA publication and contains no internal material.**
> Every version string here was mechanically extracted from two public
> documentation pages — [DGX GB200 NVL72 Release 1.3.10 package
> contents](https://docs.nvidia.com/dgx/dgxgb200nvl72-release-notes/package-contents.html)
> and [DGX GB300 NVL72 Release 1.0.10 package
> contents](https://docs.nvidia.com/dgx/dgxgb300nvl72-release-notes/package-contents.html)
> — by [`regenerate.py`](regenerate.py), which is committed here so anyone can
> repeat the extraction. The catalog is a **snapshot taken on 2026-09-13**, not
> a mirror; it will go stale, and the authoritative source is always the pages
> above. Nothing here is a compliance artifact, and the file layout is one
> illustrative shape among many — DevProof defines no firmware schema and is
> not trying to.

A rack firmware release is a coordinated set of versions: compute BMC and HMC,
GPU, SBIOS, EROT, CPLD, switch NVOS, network adapters, power shelf. The
release notes tell you which versions belong together. That list is a web page.

This walkthrough turns that list into an artifact with a name derived from its
content, compares two rack generations, signs it, and verifies it with the
network refused. About ten minutes.

## What this does and does not claim

DevProof does **not** sign firmware, and nothing here should be read as doing
so. Firmware packages ship `prod-signed` and are validated by the device during
installation; reference measurements are distributed as COSE-signed CoRIMs.
Device-level authenticity is solved, upstream, by people with the signing keys.

What is left unsigned is the *statement about which versions are qualified*. A
version inventory carries no bytes, no digests and no signature — so "is this
the qualified stack for 1.3.10?" is answered by trusting a page. This example
makes that statement itself into something with an identity and a signature,
so it can be pinned, diffed, transferred across an air gap, and checked on the
far side.

That is a narrow claim, and it is worth being precise about how narrow.

**`trust: pass` in this walkthrough means one key signed these bytes.** You
generate that key in step 3 and then write a policy that trusts it, so it
proves which key signed, not who owns the key and not that anyone authorised
the contents. In production the identity would be an organisational one,
distributed independently of the artifact. Here it is a key you made a moment
ago.

**Completeness and correctness are not checked.** `semantics: not-evaluated`
is the honest answer and appears in every output below: a catalog missing a
component, or naming a version that was never qualified, passes exactly as
well as a correct one provided the accepted key signed it. Verifying *what a
document says* would need a firmware schema, a required-component set, and a
comparison against observed rack inventory — none of which is here, and the
first of which DevProof deliberately does not define.

**Nothing here authenticates firmware.** The catalog records filenames and
versions. It does not carry package bytes, NVIDIA's package signatures, or
CoRIM measurements, and it says nothing about a device's secure-boot or
runtime state.

## Before you start

You need `devproof` **v0.2.0 or newer** (`devproof version`), `python3`, and
`openssl`. Everything runs locally — no registry, no network.

```bash
cd examples/firmware-catalog
```

Generated output is ignored by git, so you can delete it afterwards with
`git clean -fdx .`.

---

## 1. A qualified stack gets a name

```bash
devproof build ./catalog/gb200-nvl72-1.3.10 --to oci-layout://./stack --tag gb200-1.3.10
```

```console
reference:       oci-layout://./stack@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
subject:         sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
tree digest:     sha256:55b379a5f758b0dd4f7d3397b0bfe73e54df8b8cf200df705195391c4a180e2c
format:          devproof-bundle-v1
files:           48
bytes:           9414
layer bytes:     2128
tag:             gb200-1.3.10
```

Forty-seven components plus a `SOURCE.yaml` recording where they came from, so
forty-eight files and one digest. `gb200-1.3.10` is a label somebody typed and
could type differently tomorrow; `sha256:e48f5b24…` is what the stack *is*.
Two people who quote that digest are talking about the same set of versions,
with no further coordination.

Rebuilding tomorrow produces that same digest. The catalog is a pure function
of the two published pages — the date it was retrieved is recorded in this
document, not inside the artifact, because anything inside would reach the
digest and make identical content change its name overnight.

One file per component, grouped by subsystem, because the granularity of the
artifact decides the granularity of every later answer. A catalog kept as one
large document can only ever tell you *that* it changed.

---

## 2. What changed between two rack generations

This is the operation the whole example exists for.

```bash
devproof diff ./catalog/gb200-nvl72-1.3.10 ./catalog/gb300-nvl72-1.0.10
```

```console
added:           21
removed:         8
modified:        31

~ SOURCE.yaml
~ bmc-fpga-erot/bmc.yaml
~ bmc-fpga-erot/erot.yaml
~ bmc-fpga-erot/fpga.yaml
~ bmc/bmc.yaml
+ bmc/sma-firmware.yaml
- cpld/cpld.yaml
+ cpld/cpld1.yaml
+ cpld/cpld2.yaml
+ cpld/cpld3.yaml
+ cx8-n-s/corim.yaml
~ hmc/gpu.yaml
~ hmc/sbios.yaml
- host-software-components/cx7.yaml
+ nvos/sm.yaml
+ powershelf-fw/liteon-psu.yaml
- powershelf-fw/powershelf-psc.yaml
~ sbios-erot/sbios.yaml
…
```

Read what is **missing** from that list. `hmc/cpld.yaml`, `hmc/erot.yaml` and
`hmc/fpga.yaml` do not appear, and neither does most of the host stack: CPLD
`0.22`, EROT `01.04.0031.0000_n04`, FPGA `1.60`, the GPU driver, IMEX, MFT and
DOCA are byte-identical across two rack generations. Unchanged components are
invisible because they are genuinely unchanged, not because nobody looked.

The changes are real and they have shapes worth noticing:

- **Modified** — the GPU moves `97.00.B9.00.CD` → `97.10.4A.00.32`, SBIOS
  `02.04.17` → `02.05.21`, switch BMC `88.0002.1337` → `88.0002.1962`.
- **Added** — GB300 introduces SMA firmware, ConnectX-8, a broken-out NVOS
  (SM, NMX-C, NMX-T, GFM, switch ASIC), three separate CPLDs.
- **Removed** — ConnectX-7 and the single-vendor power shelf are gone.
- **Structural** — GB200 lists one concatenated CPLD string; GB300 lists three.
  GB200 has one power shelf vendor; GB300 has Delta and LiteON. The *shape*
  changed, not just the numbers.

One honest artifact of inventory-level comparison: `cuda-toolkit.yaml` →
`cuda.yaml` and `bf3-bfb.yaml` → `bf3.yaml` appear as a removal plus an
addition. A rename is indistinguishable from a delete-and-add when you compare
inventories, which is a thing to know before you build a catalog whose
component names drift between releases.

Exit `1` means the two differ. Exit `0` would mean identical — which is how you
check, in a pipeline, that the stack you are about to install is the stack you
qualified.

---

## 3. Signing the statement

Anyone can write a YAML file claiming a set of qualified versions. A signature
says who did.

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signer.pem
openssl ec -in signer.pem -pubout -out signer.pub.pem

# --quiet prints the canonical digest reference, which is what a policy
# should be pointed at. A tag is a label that can be moved later.
REF=$(devproof build ./catalog/gb200-nvl72-1.3.10 \
  --to oci-layout://./signed --sign --key signer.pem --quiet)
echo "$REF"
```

```console
oci-layout://./signed@sha256:e48f5b2458b1663476770a590e695afa708c19fa02b1458e31d937a4db27dbb6
```

The evidence is attached to the subject, not folded into it, so the catalog's
digest is the same as in step 1 — signing did not change what was signed.

Now require that signature. Write the policy with the key's own identity:

```bash
# The signer identity is reported by inspect; a policy names it rather than
# naming a file, so the same policy works wherever the key is kept.
KEYID=$(devproof inspect "$REF" \
  --evidence --key signer.pub.pem --format json |
  python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["subject"]["evidence"][0]["identities"][0].removeprefix("key "))')

cat > trust.yaml <<EOF
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: qualified-stack
spec:
  subject:
    # A tag can be repointed at other content after you have decided to trust
    # it. Requiring a digest means the thing verified is the thing named.
    requireDigestReference: true
  provenance:
    required: true
  signatures:
    threshold: 1
    identities:
      - keyId: "${KEYID}"
EOF

devproof verify "$REF" --policy trust.yaml --key signer.pub.pem
```

```console
integrity:       pass
trust:           pass
semantics:       not-evaluated
policy:          qualified-stack
policy digest:   sha256:4751811269beafeddbc464a6b1deb7ff94a0e95f514774b79f5916a254b85456
signed by:       key e793ffb4fce17225e10b06f37125d91ed9e3c3e595a316af6bbd8b15115630dc
```

Your key identity and policy digest will differ — you generated the key a
moment ago. The catalog's own digests will not.

The report names the policy that produced the answer and the key it believed.
`semantics: not-evaluated` is sitting there in the middle of a passing result,
and it is the honest part: nothing checked whether these are the right
versions.

The digest requirement is not decoration. Point the same policy at the tag and
it refuses before fetching anything:

```bash
devproof build ./catalog/gb200-nvl72-1.3.10 --to oci-layout://./signed --tag gb200-1.3.10 --quiet
devproof verify oci-layout://./signed:gb200-1.3.10 --policy trust.yaml --key signer.pub.pem
```

```console
error: a digest reference is required, but a tag was supplied
```

---

## 4. One version cannot move quietly

Change a single component — here, the compute GPU firmware, edited to the
GB300 value as though someone had merged a version bump into the wrong
release:

```bash
GPU=catalog/gb200-nvl72-1.3.10/hmc/gpu.yaml

# The original is kept beside the catalog rather than inside it. A .bak file
# left in the tree would be a forty-eighth file, and the digest below
# would change for the wrong reason.
cp "$GPU" gpu.yaml.orig
sed 's/97.00.B9.00.CD/97.10.4A.00.32/' gpu.yaml.orig > "$GPU"

devproof build ./catalog/gb200-nvl72-1.3.10 --to oci-layout://./altered --tag gb200-1.3.10 --quiet

cp gpu.yaml.orig "$GPU" && rm gpu.yaml.orig
```

```console
oci-layout://./altered@sha256:5e5477d508f5ad7c7027b582570586c7609092724140aa600b7c65695371940c
```

Fourteen characters in one file, in a catalog of forty-seven components, and
the stack's name went from `sha256:e48f5b24…` to `sha256:5e5477d5…`. Restore
the file, rebuild, and `e48f5b24…` comes back.

That is the property worth taking away. The per-file inventory — every path,
mode, size and content digest — is folded into the subject digest, and the
signature in step 3 is over that digest. There is no way to alter a component
and keep the signature, because there is nothing to alter *and* re-checksum
separately: the checksums are the name.

A checksum list is only as trustworthy as whatever vouches for the list. Here
the list is not a separate document to be trusted; it is what the artifact is
called.

---

## 5. Verifying with the network refused

Rack firmware lives behind an air gap. `--offline` is a capability boundary,
not a preference: a transport that has not promised to stay local is rejected
when it is selected, before a reference is resolved or a byte is fetched.

A public key *is* local trust material, so `--key` is all this needs.
`--trust-root` is for the other trust model — a Sigstore trusted root, for
certificate-based identities — and the two cannot be combined.

```bash
devproof verify "$REF" --policy trust.yaml --key signer.pub.pem --offline
```

```console
integrity:       pass
trust:           pass
```

The same answer as step 3, reached with nothing dialled. Try it against a
registry reference and it refuses before touching the network at all:

```bash
devproof verify oci://registry.example.com/stacks/gb200:1.3.10 \
  --key signer.pub.pem --offline
```

```console
error: this client is offline, and "oci" references need the network
```

---

## What we saw

- **A version list became an artifact.** Forty-seven components, one digest,
  and a label anyone could retype is no longer what identifies the stack.
- **Two rack generations diffed at component granularity.** Real adds, removes
  and modifications — and the components that did not change stayed silent.
- **A statement with a signer.** Provenance attached to the subject without
  changing it, and a policy that names the identity it will accept.
- **Fourteen characters renamed the stack.** The inventory is the identity, so
  a component cannot be altered and re-checksummed into looking unchanged.
- **An answer reached with the network refused**, which is the condition the
  rack is actually in.

And what it does not show, restated because a passing result is persuasive:

| Proved | Not proved |
| --- | --- |
| These exact catalog bytes are unchanged | Firmware package bytes are unchanged |
| A key you configured signed them | That NVIDIA signed or approved anything |
| Which components differ between catalogs | That either catalog is complete or correct |
| Verification with no network | Device secure boot, CoRIM or SPDM attestation |

The packages themselves are signed by the people who built them, and that is
the right place for it. This verifies a claim about which versions belong
together — the part that was, until now, a page.

## Regenerating the catalog

```bash
python3 regenerate.py           # re-derive from the public pages
python3 regenerate.py --check   # compare without writing
```

`--check` fails if the published pages no longer match what is committed, which
is the honest way to discover that a snapshot has aged. It is deliberately not
run in CI: a test suite that reached `docs.nvidia.com` would fail for reasons
that have nothing to do with this repository.

## Next

- [tamper-and-trust](../tamper-and-trust/) — the shorter introduction, if you
  have not run it
- [Verification policy](../../docs/policy.md) — the rules available to a gate
- [Security model](../../docs/security.md) — what the threat model does and
  does not cover
