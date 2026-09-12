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
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/thingzio/devproof/internal/fault"
)

// testLimits are generous enough that only the rule under test can fail.
var testLimits = PathLimits{MaxBytes: 1024, MaxSegmentBytes: 255, MaxDepth: 64}

// The Unicode tables are a format constant (DP-017). Two independent data
// sets feed path canonicalization — x/text for NFC and the standard library
// for simple folding — and they can drift apart on separate upgrade
// schedules. If either moves, every path containing an affected character may
// canonicalize differently, which silently reissues subject digests.
//
// This test failing is not a bug to be fixed by editing the expectation. It
// means a dependency or toolchain upgrade has changed the format.
func TestUnicodeVersionIsPinned(t *testing.T) {
	t.Parallel()

	pinned := pinnedUnicodeVersion(t)

	if norm.Version != pinned {
		t.Errorf("golang.org/x/text normalization tables are Unicode %s, "+
			".versions.yaml pins %s.\nThis changes canonical path bytes; treat it as a "+
			"format-version decision, not a dependency bump (DP-017).",
			norm.Version, pinned)
	}
	if unicode.Version != pinned {
		t.Errorf("standard library case-folding tables are Unicode %s, "+
			".versions.yaml pins %s.\nThis changes case-collision detection; treat it as a "+
			"format-version decision, not a toolchain bump (DP-017).",
			unicode.Version, pinned)
	}
}

func pinnedUnicodeVersion(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("../../.versions.yaml")
	if err != nil {
		t.Fatalf("reading .versions.yaml: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*unicode:\s*'([^']+)'`).FindSubmatch(data)
	if m == nil {
		t.Fatal("no specs.unicode pin found in .versions.yaml")
	}
	return string(m[1])
}

func TestNormalizePathAccepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple file", "config.yaml", "config.yaml"},
		{"nested", "app/config/service.yaml", "app/config/service.yaml"},
		{"deep", "a/b/c/d/e/f.txt", "a/b/c/d/e/f.txt"},
		{"leading dot is a hidden file, not a segment", ".gitignore", ".gitignore"},
		{"dots inside a name", "v1.2.3.json", "v1.2.3.json"},
		{"multibyte", "café/naïve.txt", "café/naïve.txt"},
		{"cjk", "設定/ファイル.yaml", "設定/ファイル.yaml"},
		{"emoji", "🔐/key.pem", "🔐/key.pem"},
		{"reserved name as a substring is fine", "console/prnt.txt", "console/prnt.txt"},
		{"reserved name after a separator-free prefix", "mycon.txt", "mycon.txt"},
		{"space inside a segment", "my config/a b.txt", "my config/a b.txt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizePath(tc.in, testLimits)
			if err != nil {
				t.Fatalf("NormalizePath(%q) = %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Decomposed input must arrive at the same canonical path as composed input,
// or a macOS-authored bundle and a Linux-authored one would have different
// subject digests for identical content.
func TestNormalizePathComposesToNFC(t *testing.T) {
	t.Parallel()

	// Written as escapes rather than literals: the distinction under test is
	// a difference in bytes, and an editor or a copy-paste can silently
	// normalize a source file out from under it.
	const (
		composed   = "caf\u00e9.txt"  // e-acute as one rune
		decomposed = "cafe\u0301.txt" // e + U+0301 COMBINING ACUTE
		nested     = "d\u0131r/e\u0301.txt"
	)

	a, err := NormalizePath(composed, testLimits)
	if err != nil {
		t.Fatalf("composed: %v", err)
	}
	b, err := NormalizePath(decomposed, testLimits)
	if err != nil {
		t.Fatalf("decomposed: %v", err)
	}
	if a != b {
		t.Errorf("composed %q and decomposed %q produced different canonical paths", a, b)
	}
	if string(a) != composed {
		t.Errorf("canonical form is %q, want the NFC form %q", a, composed)
	}

	got, err := NormalizePath(nested, testLimits)
	if err != nil {
		t.Fatalf("nested: %v", err)
	}
	if !norm.NFC.IsNormalString(string(got)) {
		t.Errorf("result %q is not NFC", got)
	}
}

func TestNormalizePathRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		code fault.Code
	}{
		{"empty", "", fault.CodeUnsafePath},
		{"absolute", "/etc/passwd", fault.CodeUnsafePath},
		{"trailing separator", "app/", fault.CodeUnsafePath},
		{"dot segment", "app/./config.yaml", fault.CodeUnsafePath},
		{"parent segment", "app/../../etc/passwd", fault.CodeUnsafePath},
		{"bare parent", "..", fault.CodeUnsafePath},
		{"bare dot", ".", fault.CodeUnsafePath},
		{"repeated separator", "app//config.yaml", fault.CodeUnsafePath},
		{"NUL", "app/config\x00.yaml", fault.CodeUnsafePath},
		{"control character", "app/config\x1f.yaml", fault.CodeUnsafePath},
		{"DEL", "app/config\x7f.yaml", fault.CodeUnsafePath},
		{"backslash is never a separator", `app\config.yaml`, fault.CodeUnsafePath},
		{"colon", "app/c:config.yaml", fault.CodeUnsafePath},
		{"asterisk", "app/*.yaml", fault.CodeUnsafePath},
		{"question mark", "app/what?.yaml", fault.CodeUnsafePath},
		{"angle brackets", "app/<in>.yaml", fault.CodeUnsafePath},
		{"quote", `app/"q".yaml`, fault.CodeUnsafePath},
		{"pipe", "app/a|b.yaml", fault.CodeUnsafePath},
		{"final segment ends in space", "app/config.yaml ", fault.CodeUnsafePath},
		{"final segment ends in period", "app/config.yaml.", fault.CodeUnsafePath},
		{"intermediate segment ends in period", "app/config./x", fault.CodeUnsafePath},
		{"intermediate segment ends in space", "app/config /x", fault.CodeUnsafePath},
		{"invalid UTF-8", "app/\xff\xfe.yaml", fault.CodeUnsafePath},

		// Windows device names, with and without extensions.
		{"CON", "CON", fault.CodeUnsafePath},
		{"con lowercase", "con", fault.CodeUnsafePath},
		{"CoN mixed", "CoN", fault.CodeUnsafePath},
		{"CON with extension", "CON.txt", fault.CodeUnsafePath},
		{"CON with two extensions", "CON.txt.bak", fault.CodeUnsafePath},
		{"NUL device", "app/nul", fault.CodeUnsafePath},
		{"COM1", "app/com1.cfg", fault.CodeUnsafePath},
		{"COM9", "com9", fault.CodeUnsafePath},
		{"LPT1", "lpt1", fault.CodeUnsafePath},
		{"AUX", "aux/file.txt", fault.CodeUnsafePath},
		{"PRN", "prn", fault.CodeUnsafePath},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizePath(tc.in, testLimits)
			if err == nil {
				t.Fatalf("NormalizePath(%q) = %q, want a rejection", tc.in, got)
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("NormalizePath(%q) code = %q, want %q", tc.in, fault.CodeOf(err), tc.code)
			}
		})
	}
}

// COM0 and LPT0 are not reserved on Windows; over-rejecting would refuse
// legitimate content.
func TestNormalizePathAllowsNonReservedDeviceLikeNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"com0", "lpt0", "com10", "conn", "auxiliary", "nula"} {
		if _, err := NormalizePath(name, testLimits); err != nil {
			t.Errorf("NormalizePath(%q) rejected a non-reserved name: %v", name, err)
		}
	}
}

func TestNormalizePathLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		lim  PathLimits
	}{
		{
			"path too long",
			strings.Repeat("a", 40),
			PathLimits{MaxBytes: 10, MaxSegmentBytes: 255, MaxDepth: 64},
		},
		{
			"segment too long",
			strings.Repeat("a", 40),
			PathLimits{MaxBytes: 1024, MaxSegmentBytes: 10, MaxDepth: 64},
		},
		{
			"too deep",
			"a/b/c/d/e",
			PathLimits{MaxBytes: 1024, MaxSegmentBytes: 255, MaxDepth: 3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NormalizePath(tc.in, tc.lim)
			if !stderrors.Is(err, fault.CodeLimitExceeded) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
			}
		})
	}
}

// Limits are measured in bytes, not runes: a filesystem's 255 limit is a byte
// limit, so a path of 200 multibyte runes must be rejected against a 255-byte
// segment bound.
func TestNormalizePathLimitsAreMeasuredInBytes(t *testing.T) {
	t.Parallel()

	// 100 three-byte runes = 300 bytes.
	seg := strings.Repeat("設", 100)

	_, err := NormalizePath(seg, PathLimits{MaxBytes: 1024, MaxSegmentBytes: 255, MaxDepth: 64})
	if !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("a 300-byte segment passed a 255-byte limit: %v", err)
	}
}

// Zero means "no bound" here, because PathLimits is an internal projection
// whose caller has already resolved real values; it is not user-facing
// configuration.
func TestNormalizePathZeroLimitsAreUnbounded(t *testing.T) {
	t.Parallel()

	deep := strings.TrimSuffix(strings.Repeat("a/", 500), "/")
	if _, err := NormalizePath(deep, PathLimits{}); err != nil {
		t.Errorf("zero PathLimits enforced a bound: %v", err)
	}
}

func TestParents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   Path
		want []string
	}{
		{"file.txt", nil},
		{"a/file.txt", []string{"a"}},
		{"a/b/c/file.txt", []string{"a", "a/b", "a/b/c"}},
		{"設定/ファイル.yaml", []string{"設定"}},
	}

	for _, tc := range tests {
		t.Run(string(tc.in), func(t *testing.T) {
			t.Parallel()
			got := tc.in.Parents()
			if len(got) != len(tc.want) {
				t.Fatalf("Parents(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Parents(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestFoldKey(t *testing.T) {
	t.Parallel()

	// Escapes, not literals: several of these characters are visually
	// indistinguishable from their ASCII counterparts, which is exactly why
	// they are a collision hazard.
	equal := [][2]string{
		{"README.md", "readme.md"},
		{"App/Config.yaml", "app/config.yaml"},
		{"\u212A", "k"},      // KELVIN SIGN folds onto ASCII k
		{"\u017F", "s"},      // LATIN SMALL LETTER LONG S folds onto s
		{"\u00DF", "\u1E9E"}, // sharp s and capital sharp s are a case pair
		{"\u03A3", "\u03C3"}, // SIGMA and sigma
		{"\u03C2", "\u03C3"}, // final sigma and sigma
	}
	for _, pair := range equal {
		if a, b := foldString(pair[0]), foldString(pair[1]); a != b {
			t.Errorf("fold(%q)=%q and fold(%q)=%q differ, want equal",
				pair[0], a, pair[1], b)
		}
	}

	// Simple folding, not full. No shipping filesystem merges these, so
	// rejecting a bundle that contains both would be a false positive
	// (DP-017).
	distinct := [][2]string{
		{"\u00DF", "ss"}, // sharp s vs ss
		{"\uFB01", "fi"}, // fi ligature vs f + i
	}
	for _, pair := range distinct {
		if a, b := foldString(pair[0]), foldString(pair[1]); a == b {
			t.Errorf("fold(%q) and fold(%q) both = %q; full folding was applied "+
				"where simple folding was specified", pair[0], pair[1], a)
		}
	}
}

// foldASCII exists only as an optimization, so it must be indistinguishable
// from the rune loop it shortcuts. A divergence here is what let an earlier
// version of this package report "README.md" and "readme.md" as different
// paths.
func TestFoldFastPathMatchesRuneLoop(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	for r := rune(0); r < utf8.RuneSelf; r++ {
		b.WriteRune(r)
	}
	allASCII := b.String()

	for _, s := range []string{allASCII, "README.md", "a", "A", "kK", "sS", "", "0123", "-_./"} {
		fast := foldASCII(s)

		var slow strings.Builder
		for _, r := range s {
			slow.WriteRune(foldRune(r))
		}

		if fast != slow.String() {
			t.Errorf("foldASCII(%q) = %q, rune loop gives %q", s, fast, slow.String())
		}
	}
}

func TestFoldKeyIsStableAndIdempotent(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"README.md", "K\u00DF\u03A3", "app/Config.YAML", "設定", "\u212A"} {
		once := foldString(s)
		if twice := foldString(once); twice != once {
			t.Errorf("fold is not idempotent for %q: %q then %q", s, once, twice)
		}
	}
}

// Folding is what makes collision detection independent of visit order, so
// it must never depend on anything but the input.
func FuzzFoldStringIsDeterministic(f *testing.F) {
	for _, seed := range []string{"README.md", "\u212A", "\u00DF", "設定/a.txt", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			t.Skip()
		}
		first := foldString(s)
		if second := foldString(s); first != second {
			t.Fatalf("fold(%q) returned %q then %q", s, first, second)
		}
		if third := foldString(first); third != first {
			t.Fatalf("fold is not idempotent for %q: %q then %q", s, first, third)
		}
	})
}
