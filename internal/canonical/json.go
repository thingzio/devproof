// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/thingzio/devproof/internal/fault"
)

const jsonOp = "canonical.json"

// MarshalJSON encodes v as RFC 8785 canonical JSON.
//
// Canonical JSON is what lets a lock, a config, or a policy be identified by
// digest: two encoders that agree on the value must agree on the bytes, so
// key order, whitespace, and escaping cannot carry information.
//
// Numbers are restricted to integers. RFC 8785 specifies ECMAScript double
// formatting for the general case, which is a large and subtle surface, and
// no DevProof document contains a non-integer number. A float here is
// therefore a bug in a caller's types rather than input to accommodate, and
// is reported as one. Admitting floats later is a format decision.
func MarshalJSON(v any) ([]byte, error) {
	// Round-tripping through encoding/json rather than reflecting over v
	// directly means json struct tags, omitempty, and custom marshalers all
	// behave exactly as they do everywhere else, and only the serialization
	// is replaced.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, jsonOp, "encoding value as JSON", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON rewrites already-valid JSON into its RFC 8785 form.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Without UseNumber every integer becomes a float64, which silently
	// loses precision above 2^53 and would reformat sizes and counts.
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, jsonOp, "parsing JSON", err)
	}
	if decoder.More() {
		return nil, fault.New(fault.CodeInvalidInput, jsonOp,
			"input contains more than one JSON value")
	}

	var out bytes.Buffer
	out.Grow(len(raw))
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
		return nil
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(b, v)
	case json.Number:
		return writeCanonicalNumber(b, v)
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case map[string]any:
		return writeCanonicalObject(b, v)
	default:
		return fault.New(fault.CodeInternal, jsonOp,
			fmt.Sprintf("unsupported JSON value of type %T", value))
	}
}

func writeCanonicalObject(b *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareUTF16)

	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeCanonicalString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := writeCanonical(b, obj[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// compareUTF16 orders keys by UTF-16 code unit, as RFC 8785 requires.
//
// This is not the same as ordering by UTF-8 bytes. A supplementary character
// such as U+1F600 encodes in UTF-16 as a surrogate pair beginning 0xD83D,
// which sorts *below* a BMP character like U+FFFD, while in UTF-8 it sorts
// above. Comparing bytes would be right for almost every real key and wrong
// for exactly the ones an adversary would choose.
func compareUTF16(a, b string) int {
	// Fast path: keys that are pure ASCII, which is every key DevProof emits,
	// compare identically under both orderings.
	if isASCII(a) && isASCII(b) {
		return strings.Compare(a, b)
	}
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

func writeCanonicalNumber(b *bytes.Buffer, n json.Number) error {
	literal := n.String()

	if strings.ContainsAny(literal, ".eE") {
		return fault.New(fault.CodeInvalidInput, jsonOp,
			fmt.Sprintf("number %s is not an integer; canonical JSON in DevProof "+
				"documents admits integers only", literal))
	}

	// Re-emit from the parsed value rather than passing the literal through,
	// so that "-0" and "007" cannot reach the output as themselves.
	if i, err := strconv.ParseInt(literal, 10, 64); err == nil {
		b.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	if u, err := strconv.ParseUint(literal, 10, 64); err == nil {
		b.WriteString(strconv.FormatUint(u, 10))
		return nil
	}
	return fault.New(fault.CodeInvalidInput, jsonOp,
		fmt.Sprintf("number %s does not fit a 64-bit integer", literal))
}

// escapeTable maps the control characters that RFC 8785 gives a short escape.
// Everything else below U+0020 uses the \u00xx form; everything at or above
// it is written literally, including characters that encoding/json would
// escape for HTML safety.
var escapeTable = map[byte]string{
	'"':  `\"`,
	'\\': `\\`,
	'\b': `\b`,
	'\f': `\f`,
	'\n': `\n`,
	'\r': `\r`,
	'\t': `\t`,
}

func writeCanonicalString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fault.New(fault.CodeInvalidInput, jsonOp, "string is not valid UTF-8")
	}

	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= utf8.RuneSelf:
			// Multi-byte UTF-8 passes through untouched; writing the byte is
			// correct because the sequence was validated above.
			b.WriteByte(c)
		case escapeTable[c] != "":
			b.WriteString(escapeTable[c])
		case c < 0x20:
			b.WriteString(`\u00`)
			const hexDigits = "0123456789abcdef"
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return nil
}

// JSONDigest returns the SHA-256 of v's canonical JSON encoding, along with
// those bytes. Callers that persist a document need both: the digest
// identifies it and the bytes are what must be written, and recomputing
// either separately invites the two to disagree.
func JSONDigest(v any) (Digest, []byte, error) {
	encoded, err := MarshalJSON(v)
	if err != nil {
		return Digest{}, nil, err
	}
	return DigestOf(encoded), encoded, nil
}
