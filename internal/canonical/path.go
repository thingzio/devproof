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

// Package canonical produces the exact bytes a DevProof subject commits to:
// path normalization, tree records, JSON, tar, and gzip.
//
// Everything here is a compatibility surface. These functions may not consult
// a clock, the environment, the working directory, randomness, or filesystem
// enumeration order (DP-012); .golangci.yaml enforces that with a depguard
// rule rather than trusting the convention.
package canonical

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/thingzio/devproof/pkg/fault"
)

const op = "canonical.path"

// Separator is the only path separator a canonical path may contain. Native
// separators are the source adapter's problem: it splits on them and rejoins
// with this, so that a literal backslash in a POSIX filename never silently
// becomes a directory boundary.
const Separator = "/"

// PathLimits bounds a canonical path.
//
// It is a local struct rather than bundle.Limits so that bundle can depend on
// canonical for its inventory types without a cycle. Callers project the
// three relevant fields across.
type PathLimits struct {
	// MaxBytes bounds the whole path's UTF-8 length.
	MaxBytes int
	// MaxSegmentBytes bounds one segment's UTF-8 length.
	MaxSegmentBytes int
	// MaxDepth bounds the number of segments.
	MaxDepth int
}

// Path is a validated, normalized, relative bundle path. Its zero value is
// not a valid path; obtain one from [NormalizePath].
type Path string

func (p Path) String() string { return string(p) }

// reservedNames are the Windows device names. A file called CON cannot be
// created on Windows under any extension, so a bundle containing one could be
// built on Linux and never expanded on Windows. The portable profile rejects
// it everywhere rather than producing artifacts that expand on some platforms.
var reservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// forbiddenRunes are illegal in a segment on at least one supported platform.
// Backslash is here because it is a separator on Windows: allowing it would
// mean a single canonical path denoting two different trees depending on
// where it was expanded.
const forbiddenRunes = `<>:"\|?*`

// NormalizePath validates p and returns its canonical form.
//
// Normalization is NFC only. No segment is ever removed or resolved: a "."
// or ".." is rejected rather than collapsed, because collapsing would let a
// source describe one path and a consumer materialize another.
func NormalizePath(p string, lim PathLimits) (Path, error) {
	if p == "" {
		return "", fault.New(fault.CodeUnsafePath, op, "path must not be empty")
	}
	// Validity is checked before normalization: norm silently replaces
	// invalid sequences with U+FFFD, which would turn malformed input into a
	// well-formed path that no longer denotes the source file.
	if !utf8.ValidString(p) {
		return "", fault.New(fault.CodeUnsafePath, op, "path is not valid UTF-8").WithPath(safeQuote(p))
	}

	normalized := norm.NFC.String(p)

	if strings.HasPrefix(normalized, Separator) {
		return "", fault.New(fault.CodeUnsafePath, op, "path must be relative").WithPath(normalized)
	}
	// A canonical path names a file, and a file path never ends in a
	// separator. Catching it here keeps the empty-segment check from having
	// to report a confusing "empty segment" for a trailing slash.
	if strings.HasSuffix(normalized, Separator) {
		return "", fault.New(fault.CodeUnsafePath, op, "path must not end with a separator").WithPath(normalized)
	}

	if lim.MaxBytes > 0 && len(normalized) > lim.MaxBytes {
		return "", fault.New(fault.CodeLimitExceeded, op,
			fmt.Sprintf("path is %d bytes, limit is %d", len(normalized), lim.MaxBytes)).
			WithPath(normalized)
	}

	segments := strings.Split(normalized, Separator)
	if lim.MaxDepth > 0 && len(segments) > lim.MaxDepth {
		return "", fault.New(fault.CodeLimitExceeded, op,
			fmt.Sprintf("path has %d segments, limit is %d", len(segments), lim.MaxDepth)).
			WithPath(normalized)
	}

	for _, seg := range segments {
		if err := validateSegment(seg, normalized, lim); err != nil {
			return "", err
		}
	}

	return Path(normalized), nil
}

func validateSegment(seg, full string, lim PathLimits) error {
	reject := func(msg string) error {
		return fault.New(fault.CodeUnsafePath, op, msg).WithPath(full)
	}

	switch seg {
	case "":
		return reject("path contains an empty segment or repeated separator")
	case ".", "..":
		return reject("path contains a " + seg + " segment")
	}

	if lim.MaxSegmentBytes > 0 && len(seg) > lim.MaxSegmentBytes {
		return fault.New(fault.CodeLimitExceeded, op,
			fmt.Sprintf("path segment %q is %d bytes, limit is %d",
				seg, len(seg), lim.MaxSegmentBytes)).WithPath(full)
	}

	for _, r := range seg {
		switch {
		case r == 0:
			return reject("path contains a NUL byte")
		case unicode.IsControl(r):
			return reject(fmt.Sprintf("path contains control character U+%04X", r))
		case strings.ContainsRune(forbiddenRunes, r):
			return reject(fmt.Sprintf("path contains the character %q, which is not portable", r))
		}
	}

	// Windows silently strips these, so a bundle containing "config." would
	// expand to "config" there and stop matching its own inventory.
	if last := seg[len(seg)-1]; last == ' ' || last == '.' {
		return reject(fmt.Sprintf("path segment %q ends with a space or period", seg))
	}

	stem, _, _ := strings.Cut(seg, ".")
	if reservedNames[strings.ToLower(stem)] {
		return reject(fmt.Sprintf("path segment %q is a reserved device name", seg))
	}

	return nil
}

// Parents returns p's required parent directories, shallowest first. A path
// with no separator has none.
func (p Path) Parents() []string {
	s := string(p)
	var out []string
	for i, r := range s {
		if r == '/' {
			out = append(out, s[:i])
		}
	}
	return out
}

// FoldKey returns p's case-insensitive collision key.
//
// Simple folding, matching what APFS, HFS+, and NTFS actually merge. Full
// folding would additionally collapse "ß" onto "ss", which no filesystem
// does, and would reject bundles that expand cleanly everywhere (DP-017).
func (p Path) FoldKey() string { return foldString(string(p)) }

func foldString(s string) string {
	if isASCII(s) {
		return foldASCII(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// foldASCII is the ASCII case of foldRune, avoiding rune decoding for the
// paths that make up nearly every bundle.
//
// It must agree with foldRune exactly. It does, and not by coincidence: for
// every ASCII letter the folding orbit's lowest code point is the uppercase
// one, including the orbits that reach outside ASCII — 'k' folds with U+212A
// KELVIN SIGN and 's' with U+017F LONG S, and in both the ASCII uppercase
// letter is still lowest. TestFoldFastPathMatchesRuneLoop holds the two
// implementations to that.
func foldASCII(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// foldRune maps r to the lowest rune in its simple-folding orbit, giving a
// canonical representative. Using a key rather than pairwise EqualFold makes
// collision detection a map lookup, which is what keeps the result
// independent of the order paths were visited.
func foldRune(r rune) rune {
	lowest := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < lowest {
			lowest = f
		}
	}
	return lowest
}

// safeQuote renders an invalid-UTF-8 path for a diagnostic without emitting
// raw bytes into a log.
func safeQuote(s string) string {
	const limit = 128
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.ToValidUTF8(s, "�")
}
