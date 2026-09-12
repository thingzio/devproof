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
	stderrors "errors"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

func TestCanonicalizeJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"null", `null`, `null`},
		{"true", `true`, `true`},
		{"false", `false`, `false`},
		{"integer", `42`, `42`},
		{"negative", `-42`, `-42`},
		{"zero", `0`, `0`},
		{"string", `"hello"`, `"hello"`},
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},

		{"whitespace is removed", "{\n  \"a\" : 1 ,\n  \"b\" : 2\n}", `{"a":1,"b":2}`},
		{"keys are sorted", `{"c":3,"a":1,"b":2}`, `{"a":1,"b":2,"c":3}`},
		{"nested keys are sorted", `{"z":{"y":1,"x":2}}`, `{"z":{"x":2,"y":1}}`},

		// Array order is data, not presentation, so it is preserved.
		{"array order is preserved", `[3,1,2]`, `[3,1,2]`},

		{"uppercase keys sort before lowercase", `{"a":1,"B":2}`, `{"B":2,"a":1}`},
		{"digits sort before letters", `{"a":1,"1":2}`, `{"1":2,"a":1}`},

		// Leading zeros and negative zero are spellings, not values.
		{"negative zero normalizes", `{"a":-0}`, `{"a":0}`},

		{"large integer keeps precision", `9007199254740993`, `9007199254740993`},
		{"max int64", `9223372036854775807`, `9223372036854775807`},
		{"beyond int64 but within uint64", `18446744073709551615`, `18446744073709551615`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("CanonicalizeJSON(%s) = %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("CanonicalizeJSON(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// Escaping is part of the canonical byte sequence. encoding/json escapes
// <, >, and & for HTML safety by default, which RFC 8785 does not; leaving
// that on would make DevProof's canonical JSON disagree with every other
// conforming implementation.
func TestCanonicalizeJSONStringEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"quote", `"a\"b"`, `"a\"b"`},
		{"backslash", `"a\\b"`, `"a\\b"`},
		{"backspace", `"a\bb"`, `"a\bb"`},
		{"form feed", `"a\fb"`, `"a\fb"`},
		{"newline", `"a\nb"`, `"a\nb"`},
		{"carriage return", `"a\rb"`, `"a\rb"`},
		{"tab", `"a\tb"`, `"a\tb"`},
		{"other control uses lowercase \\u00xx", `"a\u0001b"`, `"a\u0001b"`},
		{"control 0x1f", `"\u001f"`, `"\u001f"`},

		// Not escaped by RFC 8785.
		{"html characters stay literal", `"<a>&b"`, `"<a>&b"`},
		{"forward slash stays literal", `"a/b"`, `"a/b"`},
		{"del is not a control escape", "\"\u007f\"", "\"\u007f\""},

		// Non-ASCII is emitted as UTF-8, never as \u escapes.
		{"multibyte passes through", `"caf\u00e9"`, "\"caf\u00e9\""},
		{"cjk passes through", `"\u8a2d\u5b9a"`, "\"\u8a2d\u5b9a\""},
		{"supplementary plane passes through", `"\ud83d\ude00"`, "\"\U0001F600\""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("CanonicalizeJSON(%s) = %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("= %q, want %q", got, tc.want)
			}
		})
	}
}

// RFC 8785 orders keys by UTF-16 code unit, which differs from UTF-8 byte
// order exactly where surrogate pairs are involved. Getting this wrong
// produces bytes that almost always match a conforming implementation, and
// disagree on precisely the input someone would pick to make them disagree.
func TestCanonicalizeJSONSortsByUTF16CodeUnits(t *testing.T) {
	t.Parallel()

	// U+1F600 encodes in UTF-16 as D83D DE00, so it sorts below U+FFFD.
	// In UTF-8 it is F0 9F 98 80 against EF BF BD, so it would sort above.
	const in = "{\"\U0001F600\":1,\"\uFFFD\":2}"
	const want = "{\"\U0001F600\":1,\"\uFFFD\":2}"

	got, err := CanonicalizeJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	if string(got) != want {
		t.Errorf("= %q, want %q (UTF-16 order, not UTF-8 byte order)", got, want)
	}
}

func TestCanonicalizeJSONSortsMixedAsciiAndNonAscii(t *testing.T) {
	t.Parallel()

	got, err := CanonicalizeJSON([]byte("{\"\u00e9\":1,\"z\":2,\"a\":3}"))
	if err != nil {
		t.Fatalf("CanonicalizeJSON: %v", err)
	}
	if want := "{\"a\":3,\"z\":2,\"\u00e9\":1}"; string(got) != want {
		t.Errorf("= %q, want %q", got, want)
	}
}

func TestCanonicalizeJSONRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		code fault.Code
	}{
		{"malformed", `{`, fault.CodeInvalidInput},
		{"trailing content", `{} {}`, fault.CodeInvalidInput},
		{"empty input", ``, fault.CodeInvalidInput},

		// Integers only, by decision: RFC 8785's general number rules
		// require ECMAScript double formatting, and no DevProof document
		// contains a non-integer number.
		{"float", `1.5`, fault.CodeInvalidInput},
		{"exponent", `1e3`, fault.CodeInvalidInput},
		{"float in object", `{"a":0.1}`, fault.CodeInvalidInput},
		{"integer-valued float is still a float", `1.0`, fault.CodeInvalidInput},
		{"beyond uint64", `99999999999999999999999`, fault.CodeInvalidInput},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := CanonicalizeJSON([]byte(tc.in))
			if !stderrors.Is(err, tc.code) {
				t.Errorf("CanonicalizeJSON(%s) code = %q, want %q", tc.in, fault.CodeOf(err), tc.code)
			}
		})
	}
}

// Canonicalization must be a fixed point: running it again changes nothing.
// If it were not, a document's digest would depend on how many times it had
// been processed.
func TestCanonicalizeJSONIsIdempotent(t *testing.T) {
	t.Parallel()

	inputs := []string{
		`{"c":3,"a":1,"b":{"z":[1,2,{"y":null}]}}`,
		`[{"b":1,"a":2},{"d":3,"c":4}]`,
		"{\"\U0001F600\":\"caf\u00e9\",\"a\":\"\\u0001\"}",
	}

	for _, in := range inputs {
		once, err := CanonicalizeJSON([]byte(in))
		if err != nil {
			t.Fatalf("first pass on %s: %v", in, err)
		}
		twice, err := CanonicalizeJSON(once)
		if err != nil {
			t.Fatalf("second pass on %s: %v", once, err)
		}
		if string(once) != string(twice) {
			t.Errorf("not idempotent for %s: %s then %s", in, once, twice)
		}
	}
}

// Two spellings of one value must produce one byte sequence. This is the
// entire point of canonicalization.
func TestCanonicalizeJSONCollapsesSpellings(t *testing.T) {
	t.Parallel()

	spellings := []string{
		`{"a":1,"b":2}`,
		`{"b":2,"a":1}`,
		"{ \"a\" : 1 , \"b\" : 2 }",
		"{\n\t\"b\": 2,\n\t\"a\": 1\n}",
	}

	var first string
	for i, s := range spellings {
		got, err := CanonicalizeJSON([]byte(s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if i == 0 {
			first = string(got)
			continue
		}
		if string(got) != first {
			t.Errorf("%s canonicalized to %s, want %s", s, got, first)
		}
	}
}

func TestMarshalJSONUsesStructTags(t *testing.T) {
	t.Parallel()

	type doc struct {
		Zeta    string `json:"zeta"`
		Alpha   int    `json:"alpha"`
		Omitted string `json:"omitted,omitempty"`
		Hidden  string `json:"-"`
	}

	got, err := MarshalJSON(doc{Zeta: "z", Alpha: 1, Hidden: "secret"})
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if want := `{"alpha":1,"zeta":"z"}`; string(got) != want {
		t.Errorf("= %s, want %s", got, want)
	}
	if strings.Contains(string(got), "secret") {
		t.Error("a json:\"-\" field reached the output")
	}
}

func TestMarshalJSONRejectsFloats(t *testing.T) {
	t.Parallel()

	type doc struct {
		Ratio float64 `json:"ratio"`
	}

	if _, err := MarshalJSON(doc{Ratio: 1.5}); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestJSONDigestAgreesWithItsBytes(t *testing.T) {
	t.Parallel()

	type doc struct {
		A int `json:"a"`
	}

	d, encoded, err := JSONDigest(doc{A: 1})
	if err != nil {
		t.Fatalf("JSONDigest: %v", err)
	}
	if string(encoded) != `{"a":1}` {
		t.Errorf("encoded = %s", encoded)
	}
	if d != DigestOf(encoded) {
		t.Error("the returned digest is not the digest of the returned bytes")
	}
}

// Canonical output must always be re-parseable, and canonicalizing it again
// must be a no-op, for any JSON the decoder accepts.
func FuzzCanonicalizeJSONIsIdempotent(f *testing.F) {
	seeds := []string{
		`{"a":1}`, `[1,2,3]`, `null`, `"s"`, `{}`, `{"b":{"a":[true,false,null]}}`,
		`{"\u0001":"\u001f"}`, `{"a":-0}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		once, err := CanonicalizeJSON(raw)
		if err != nil {
			t.Skip()
		}
		twice, err := CanonicalizeJSON(once)
		if err != nil {
			t.Fatalf("canonical output was rejected on re-canonicalization: %v\ninput: %q\noutput: %q",
				err, raw, once)
		}
		if string(once) != string(twice) {
			t.Fatalf("not idempotent\ninput: %q\nfirst: %q\nsecond: %q", raw, once, twice)
		}
	})
}
