package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/thingzio/devproof/internal/fault"
)

const digestOp = "bundle.digest"

// DigestSize is the length of a SHA-256 digest in bytes. Format v1 accepts no
// other algorithm anywhere the format requires one, so there is no algorithm
// negotiation to get wrong.
const DigestSize = sha256.Size

// Digest is a raw SHA-256 digest.
//
// It is a fixed-size array rather than a string for two reasons: the tree
// record encoding embeds the raw 32 bytes, and a fixed size makes an unset
// digest impossible to confuse with a valid one of the wrong length.
type Digest [DigestSize]byte

// String renders the digest in OCI form: "sha256:" followed by lowercase hex.
func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }

// Hex renders the digest as lowercase hex with no algorithm prefix.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether d is the zero value, which is never a digest any
// content produced.
func (d Digest) IsZero() bool { return d == Digest{} }

// DigestOf returns the SHA-256 of b.
func DigestOf(b []byte) Digest { return sha256.Sum256(b) }

// ParseDigest accepts the OCI "sha256:<64 lowercase hex>" form.
//
// The encoding is validated, not merely decoded. Uppercase hex, a missing
// algorithm, and a wrong length all decode to something under a lax parser,
// and two spellings of one digest that compare unequal would defeat content
// addressing entirely.
func ParseDigest(s string) (Digest, error) {
	var d Digest

	algorithm, encoded, ok := strings.Cut(s, ":")
	if !ok {
		return d, fault.New(fault.CodeInvalidInput, digestOp,
			fmt.Sprintf("digest %q has no algorithm prefix", s))
	}
	if algorithm != "sha256" {
		return d, fault.New(fault.CodeUnsupportedVersion, digestOp,
			fmt.Sprintf("digest algorithm %q is not supported; format v1 requires sha256", algorithm))
	}
	if len(encoded) != hex.EncodedLen(DigestSize) {
		return d, fault.New(fault.CodeInvalidInput, digestOp,
			fmt.Sprintf("digest is %d hex characters, want %d", len(encoded), hex.EncodedLen(DigestSize)))
	}
	if strings.ToLower(encoded) != encoded {
		return d, fault.New(fault.CodeInvalidInput, digestOp, "digest must be lowercase hexadecimal")
	}
	if _, err := hex.Decode(d[:], []byte(encoded)); err != nil {
		return d, fault.Wrap(fault.CodeInvalidInput, digestOp, "digest is not valid hexadecimal", err)
	}
	return d, nil
}
