# Examples

Walkthroughs you can run. Each one lives in its own directory with its own
`README.md`, and each is self-contained — no example depends on having read
another.

| Example | Shows | Needs |
| --- | --- | --- |
| [tamper-and-trust](tamper-and-trust/) | Why a digest is a name you can rely on: identical builds, what `verify` does and does not claim, a policy that writes nothing when it fails, and what happens when someone changes the stored bytes. | `devproof` ≥ `v0.2.0`, `python3` |
| [firmware-catalog](firmware-catalog/) | The same ideas against a real inventory: a rack firmware stack from public NVIDIA release notes, diffed across two hardware generations, signed, pinned by digest, and verified with the network refused. It is also explicit about what a passing result does not prove. | `devproof` ≥ `v0.2.0`, `python3`, `openssl` |
| [publish-once-reproduce-anywhere](publish-once-reproduce-anywhere/) | The multi-party case: one publisher signs an artifact into a registry keyless, and unrelated consumers regenerate it from pinned inputs on their own operating systems and confirm by digest rather than by trusting the channel. Also the air-gapped transfer, trusted root included. | `devproof` ≥ `v0.5.0`, network, `cosign` |

Start with **tamper-and-trust**; it is the shortest and the other two assume
what it establishes. The first two run entirely on your machine. The third is
the only one that needs a network, because being about distribution is the
point of it.

## How these are kept true

Every example that can be executed is executed, by a Go test in its own
directory that extracts the commands from the `README.md` and runs them.

That is not ceremony. One of these walkthroughs demonstrates that tampering
with an artifact is caught, and the release before it was written reported
`integrity: pass` for exactly that case — so the document would have described
a guarantee the binary did not provide, convincingly, in a file people copy
from. A demonstration nobody runs is a description.

The tests assert outcomes rather than output. Human-readable text is
explicitly not a contract ([compatibility](../docs/compatibility.md)), so
asserting on wording would break for reasons a reader would never care about;
what has to stay true is that the commands succeed or fail as the document
says they do.

## Adding one

1. Make a directory named for what it demonstrates.
2. Write `README.md`: a short statement of what it shows, numbered steps with
   the reason each one matters, and a short summary at the end.
3. Transcribe every output block from a real run. Do not write output that
   looks plausible.
4. Add a test in the same directory that runs the document and checks what it
   claims.
5. Add a row to the table above.

Keep each example runnable with nothing but a local directory where possible.
An example that needs a registry, a signing identity, or a network is worth
having, but it is worth saying so in the table rather than discovering it at
step four.
