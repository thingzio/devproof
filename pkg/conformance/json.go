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

package conformance

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CheckCanonicalJSON verifies that bytes are RFC 8785 canonical JSON.
//
// The config and the manifest are the two documents whose digests are the
// artifact's identity, so "the same document" has to mean "the same bytes".
// Two writers that agree on every value and disagree on key order produce two
// different subject digests for one payload, and the disagreement is invisible
// to anything that compares decoded values.
//
// This used to be a json.Compact round trip, which only catches insignificant
// whitespace. Reordered keys, a non-minimal string escape, and a number spelled
// with a leading plus or an exponent all survived it.
//
// The scan is over the raw bytes rather than over a decoded value, because a
// decoder has already thrown away the spelling that is the thing in question.
func CheckCanonicalJSON(data []byte) error {
	scanner := &jsonScanner{data: data}
	if err := scanner.value(); err != nil {
		return err
	}
	if scanner.pos != len(data) {
		return fmt.Errorf("trailing bytes after the JSON value at offset %d", scanner.pos)
	}
	return nil
}

type jsonScanner struct {
	data []byte
	pos  int
}

// errUnexpectedEnd is returned wherever the document stops mid-value.
var errUnexpectedEnd = errors.New("the JSON document ends unexpectedly")

func (s *jsonScanner) value() error {
	if s.pos >= len(s.data) {
		return errUnexpectedEnd
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return s.object()
	case c == '[':
		return s.array()
	case c == '"':
		_, err := s.str()
		return err
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		return fmt.Errorf("insignificant whitespace at offset %d", s.pos)
	default:
		return fmt.Errorf("unexpected byte %q at offset %d", c, s.pos)
	}
}

// object scans a member list, requiring keys in UTF-16 code-unit order.
//
// That ordering is RFC 8785's, and it is not the same as byte order: a
// character above the basic plane sorts below one in U+E000..U+FFFF once both
// are encoded as UTF-16. Comparing the encoded units rather than the strings
// is the difference between implementing the rule and implementing something
// that agrees with it for ASCII.
func (s *jsonScanner) object() error {
	s.pos++ // '{'
	if s.peek() == '}' {
		s.pos++
		return nil
	}

	var previous []uint16
	for {
		if s.peek() != '"' {
			return s.unexpected("a member name must be a string")
		}
		key, err := s.str()
		if err != nil {
			return err
		}
		units := utf16.Encode([]rune(key))
		if previous != nil && slices.Compare(previous, units) >= 0 {
			return fmt.Errorf("member %q does not follow the previous name in UTF-16 order", key)
		}
		previous = units

		if s.peek() != ':' {
			return s.unexpected("a member name is not followed by a colon")
		}
		s.pos++
		if err := s.value(); err != nil {
			return err
		}

		switch s.peek() {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return s.unexpected("unexpected byte in an object")
		}
	}
}

func (s *jsonScanner) array() error {
	s.pos++ // '['
	if s.peek() == ']' {
		s.pos++
		return nil
	}
	for {
		if err := s.value(); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return s.unexpected("unexpected byte in an array")
		}
	}
}

// str scans a string literal and returns its decoded value.
//
// Only the escapes RFC 8785 emits are accepted. A canonicalizer escapes the
// quote, the reverse solidus, and the control characters below U+0020 — the
// short forms where they exist and \u00xx otherwise — and nothing else. An
// escaped solidus, an escaped non-control character, or an uppercase hex digit
// is a different spelling of the same string, which is exactly the class of
// difference that changes a digest without changing a meaning.
func (s *jsonScanner) str() (string, error) {
	s.pos++ // '"'
	var out strings.Builder

	for {
		if s.pos >= len(s.data) {
			return "", errUnexpectedEnd
		}
		c := s.data[s.pos]

		switch {
		case c == '"':
			s.pos++
			if !utf8.ValidString(out.String()) {
				return "", errors.New("a string contains invalid UTF-8")
			}
			return out.String(), nil

		case c < 0x20:
			return "", fmt.Errorf("an unescaped control character U+%04X at offset %d", c, s.pos)

		case c == '\\':
			decoded, err := s.escape()
			if err != nil {
				return "", err
			}
			out.WriteRune(decoded)

		default:
			out.WriteByte(c)
			s.pos++
		}
	}
}

// shortEscapes are the two-character forms a canonicalizer emits, keyed by the
// letter that follows the reverse solidus.
var shortEscapes = map[byte]rune{
	'"': '"', '\\': '\\', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
}

// hasShortForm is the same set keyed by the character escaped, which is the
// direction a \u escape has to be checked against.
var hasShortForm = map[rune]bool{
	'"': true, '\\': true, '\b': true, '\f': true, '\n': true, '\r': true, '\t': true,
}

func (s *jsonScanner) escape() (rune, error) {
	if s.pos+1 >= len(s.data) {
		return 0, errUnexpectedEnd
	}
	kind := s.data[s.pos+1]

	if decoded, ok := shortEscapes[kind]; ok {
		s.pos += 2
		return decoded, nil
	}
	if kind != 'u' {
		return 0, fmt.Errorf("the escape \\%c at offset %d is not one a canonicalizer emits",
			kind, s.pos)
	}
	if s.pos+6 > len(s.data) {
		return 0, errUnexpectedEnd
	}

	digits := string(s.data[s.pos+2 : s.pos+6])
	if digits != strings.ToLower(digits) {
		return 0, fmt.Errorf("the escape \\u%s uses uppercase hex digits", digits)
	}
	value, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("the escape \\u%s is not hexadecimal", digits)
	}
	// Everything at or above U+0020 is written literally, and every control
	// character with a short form uses it.
	if value >= 0x20 {
		return 0, fmt.Errorf("U+%04X is escaped as \\u%s but is written literally", value, digits)
	}
	if hasShortForm[rune(value)] {
		return 0, fmt.Errorf("U+%04X is escaped as \\u%s and has a short form", value, digits)
	}
	s.pos += 6
	return rune(value), nil
}

// number scans a numeric literal.
//
// Format v1 documents hold integers only — counts, sizes, modes, a schema
// version — so the canonical spelling is the shortest decimal integer. A
// fraction or an exponent is not merely a different spelling here; it is a
// value the format does not carry.
func (s *jsonScanner) number() error {
	start := s.pos
	if s.pos < len(s.data) && s.data[s.pos] == '-' {
		s.pos++
	}
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
	}

	if s.pos < len(s.data) {
		if c := s.data[s.pos]; c == '.' || c == 'e' || c == 'E' {
			return fmt.Errorf("the number at offset %d is not an integer; v1 documents carry none",
				start)
		}
	}

	text := string(s.data[start:s.pos])
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("the number %q at offset %d is not a 64-bit integer", text, start)
	}
	if spelled := strconv.FormatInt(value, 10); spelled != text {
		return fmt.Errorf("the number %q is spelled %q in canonical form", text, spelled)
	}
	return nil
}

func (s *jsonScanner) literal(want string) error {
	if !strings.HasPrefix(string(s.data[s.pos:]), want) {
		return fmt.Errorf("expected %s at offset %d", want, s.pos)
	}
	s.pos += len(want)
	return nil
}

// unexpected reports a byte that cannot appear where the scan is.
//
// Whitespace is named for what it is rather than reported as an unexpected
// byte. It is the most common way a document is non-canonical and the least
// obvious to read out of an offset.
func (s *jsonScanner) unexpected(context string) error {
	switch s.peek() {
	case ' ', '\t', '\n', '\r':
		return fmt.Errorf("insignificant whitespace at offset %d", s.pos)
	case 0:
		return errUnexpectedEnd
	default:
		return fmt.Errorf("%s at offset %d", context, s.pos)
	}
}

// peek returns the next byte, or zero at the end of the document.
//
// It never skips whitespace: canonical JSON has none, so a space here is a
// finding rather than something to step over.
func (s *jsonScanner) peek() byte {
	if s.pos >= len(s.data) {
		return 0
	}
	return s.data[s.pos]
}
