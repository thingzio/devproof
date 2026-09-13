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

That is a narrow claim. It is also the one nobody else is making.

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
reference:       oci-layout://./stack@sha256:65ab27289c09f644fe839c98222258ed0d6dba2073e5135e7be4b953d22eb1c7
subject:         sha256:65ab27289c09f644fe839c98222258ed0d6dba2073e5135e7be4b953d22eb1c7
tree digest:     sha256:48d778e8c5566c4a5c3682031dcf5b73f52f74aa28b190b9dfa76a9070c71c8d
format:          devproof-bundle-v1
files:           37
bytes:           7141
layer bytes:     1810
tag:             gb200-1.3.10
```

Thirty-seven components, one digest. `gb200-1.3.10` is a label somebody typed
and could type differently tomorrow; `sha256:65ab2728…` is what the stack
*is*. Two people who quote that digest are talking about the same set of
versions, with no further coordination.

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
added:           19
removed:         7
modified:        21

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

devproof build ./catalog/gb200-nvl72-1.3.10 \
  --to oci-layout://./signed --tag gb200-1.3.10 \
  --sign --key signer.pem
```

```console
evidence:        sha256:c51ac1f90d60686f6626aead1eb5abc9310bc4784d522dc577926b6d03a440e7
attester:        devproof.thingz.io/key/v1
storage:         referrers
```

The evidence is attached to the subject, not folded into it. The catalog's
digest is the same as in step 1 — signing did not change what was signed.

Now require that signature. Write the policy with the key's own identity:

```bash
# The signer identity is reported by inspect; a policy names it rather than
# naming a file, so the same policy works wherever the key is kept.
KEYID=$(devproof inspect oci-layout://./signed:gb200-1.3.10 \
  --evidence --key signer.pub.pem --format json |
  python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["subject"]["evidence"][0]["identities"][0].removeprefix("key "))')

cat > trust.yaml <<EOF
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: qualified-stack
spec:
  provenance:
    required: true
  signatures:
    threshold: 1
    identities:
      - keyId: "${KEYID}"
EOF

devproof verify oci-layout://./signed:gb200-1.3.10 --policy trust.yaml --key signer.pub.pem
```

```console
integrity:       pass
trust:           pass
semantics:       not-evaluated
policy:          qualified-stack
policy digest:   sha256:157eb40e2c042edaf074dd5214fc8fda2f7896bc0780593741278de64d33b501
signed by:       key 339f0eef1a73b63f313380efae736d9a3c303fdc50c97e84f030cdfb1db4cfae
```

Your key identity and policy digest will differ — you generated the key a
moment ago. The catalog's own digests will not.

`trust: pass`, and the report names the policy that produced it and the key it
believed. Point it at the unsigned bundle from step 1 instead and it refuses,
writing nothing.

---

## 4. One version cannot move quietly

Change a single component — here, the compute GPU firmware, edited to the
GB300 value as though someone had merged a version bump into the wrong
release:

```bash
GPU=catalog/gb200-nvl72-1.3.10/hmc/gpu.yaml

# The original is kept beside the catalog rather than inside it. A .bak file
# left in the tree would be a thirty-eighth component, and the digest below
# would change for the wrong reason.
cp "$GPU" gpu.yaml.orig
sed 's/97.00.B9.00.CD/97.10.4A.00.32/' gpu.yaml.orig > "$GPU"

devproof build ./catalog/gb200-nvl72-1.3.10 --to oci-layout://./altered --tag gb200-1.3.10 --quiet

cp gpu.yaml.orig "$GPU" && rm gpu.yaml.orig
```

```console
oci-layout://./altered@sha256:9ef35c18b032e595268a7abe00ff812fe797ab17977d0d34664f95427a397e19
```

Fourteen characters in one file, in a catalog of thirty-seven, and the stack's
name went from `sha256:65ab2728…` to `sha256:9ef35c18…`.

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

```bash
devproof verify oci-layout://./signed:gb200-1.3.10 \
  --policy trust.yaml --key signer.pub.pem --offline --trust-root signer.pub.pem
```

```console
integrity:       pass
trust:           pass
```

The same answer as step 3, reached with nothing dialled. Try it against a
registry reference and it refuses before touching the network at all:

```bash
devproof verify oci://registry.example.com/stacks/gb200:1.3.10 \
  --offline --trust-root signer.pub.pem
```

```console
error: this client is offline, and "oci" references need the network
```

---

## What we saw

- **A version list became an artifact.** Thirty-seven components, one digest,
  and a label anyone could retype is no longer what identifies the stack.
- **Two rack generations diffed at component granularity.** Real adds, removes
  and modifications — and the components that did not change stayed silent.
- **A statement with a signer.** Provenance attached to the subject without
  changing it, and a policy that names the identity it will accept.
- **Fourteen characters renamed the stack.** The inventory is the identity, so
  a component cannot be altered and re-checksummed into looking unchanged.
- **An answer reached with the network refused**, which is the condition the
  rack is actually in.

What this does not do is verify firmware. The packages are signed by the people
who built them, and that is the right place for it. This verifies the claim
about which packages belong together — the part that was, until now, a page.

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
