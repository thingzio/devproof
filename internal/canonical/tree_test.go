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
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"slices"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/golden"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

func mustDigest(t *testing.T, content string) Digest {
	t.Helper()
	return sha256.Sum256([]byte(content))
}

// The record stream is the normative encoding, so the expectation is spelled
// out byte by byte rather than produced by calling the encoder a second way.
// A test that re-derives the layout from the implementation cannot catch the
// implementation changing the layout.
func TestWriteTreeRecordsExactBytes(t *testing.T) {
	t.Parallel()

	records := []FileRecord{{
		Path:   "a.txt",
		Mode:   bundle.ModeFile,
		Size:   5,
		Digest: mustDigest(t, "hello"),
	}}

	var want []byte
	want = append(want, "devproof-tree-v1\x00"...)                     // domain prefix
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 1)                        // uint64be record count
	want = append(want, 0, 0, 0, 5)                                    // uint32be path length
	want = append(want, "a.txt"...)                                    // path bytes
	want = append(want, 0, 0, 0x01, 0xa4)                              // uint32be mode 0644 == 420
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 5)                        // uint64be size
	want = append(want, mustHex(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e"+ // raw sha256("hello")
		"1b161e5c1fa7425e73043362938b9824")...)

	var got bytes.Buffer
	if err := WriteTreeRecords(&got, records); err != nil {
		t.Fatalf("WriteTreeRecords: %v", err)
	}

	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("record stream mismatch\n got: %s\nwant: %s",
			hex.EncodeToString(got.Bytes()), hex.EncodeToString(want))
	}
	if got.Len() != 17+8+4+5+4+8+32 {
		t.Errorf("record stream is %d bytes, want %d", got.Len(), 17+8+4+5+4+8+32)
	}
}

// An empty tree cannot be built, but the encoder must still be total: a
// header with a zero count, and nothing else. Leaving this undefined would
// mean the one degenerate case has no specified digest.
func TestWriteTreeRecordsEmpty(t *testing.T) {
	t.Parallel()

	var got bytes.Buffer
	if err := WriteTreeRecords(&got, nil); err != nil {
		t.Fatalf("WriteTreeRecords: %v", err)
	}

	want := append([]byte("devproof-tree-v1\x00"), 0, 0, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("= %s, want %s", hex.EncodeToString(got.Bytes()), hex.EncodeToString(want))
	}
}

// The executable bit is one of exactly two values a mode may take, and it
// changes the digest. A build that lost it would silently produce a bundle
// whose scripts expand non-executable.
func TestTreeDigestDistinguishesExecutableBit(t *testing.T) {
	t.Parallel()

	base := FileRecord{Path: "run.sh", Size: 3, Digest: mustDigest(t, "abc")}

	plain := base
	plain.Mode = bundle.ModeFile
	exec := base
	exec.Mode = bundle.ModeExecutable

	a, err := TreeDigest([]FileRecord{plain})
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	b, err := TreeDigest([]FileRecord{exec})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if a == b {
		t.Error("the executable bit does not affect the tree digest")
	}
}

// Path and content are both committed to, so neither can be substituted for
// the other without changing identity.
func TestTreeDigestIsSensitiveToPathAndContent(t *testing.T) {
	t.Parallel()

	base := []FileRecord{{
		Path: "a.txt", Mode: bundle.ModeFile, Size: 5, Digest: mustDigest(t, "hello"),
	}}
	baseDigest, err := TreeDigest(base)
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	renamed := slices.Clone(base)
	renamed[0].Path = "b.txt"
	if d, _ := TreeDigest(renamed); d == baseDigest {
		t.Error("renaming a file did not change the tree digest")
	}

	edited := slices.Clone(base)
	edited[0].Digest = mustDigest(t, "world")
	if d, _ := TreeDigest(edited); d == baseDigest {
		t.Error("changing content did not change the tree digest")
	}

	resized := slices.Clone(base)
	resized[0].Size = 6
	if d, _ := TreeDigest(resized); d == baseDigest {
		t.Error("changing the declared size did not change the tree digest")
	}
}

func TestTreeDigestIsDeterministic(t *testing.T) {
	t.Parallel()

	records := []FileRecord{
		{Path: "a.txt", Mode: bundle.ModeFile, Size: 1, Digest: mustDigest(t, "a")},
		{Path: "b/c.txt", Mode: bundle.ModeExecutable, Size: 2, Digest: mustDigest(t, "bc")},
		{Path: "z.txt", Mode: bundle.ModeFile, Size: 0, Digest: mustDigest(t, "")},
	}

	first, err := TreeDigest(records)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for range 16 {
		next, err := TreeDigest(records)
		if err != nil {
			t.Fatalf("repeat: %v", err)
		}
		if next != first {
			t.Fatalf("TreeDigest is not deterministic: %s then %s", first, next)
		}
	}
}

// The encoder is the last gate before identity. A malformed record set must
// fail rather than mint a digest no independent verifier can reproduce.
func TestWriteTreeRecordsRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	good := FileRecord{Path: "a.txt", Mode: bundle.ModeFile, Size: 1, Digest: mustDigest(t, "a")}

	tests := []struct {
		name    string
		records []FileRecord
		code    fault.Code
	}{
		{
			"unsorted",
			[]FileRecord{
				{Path: "b.txt", Mode: bundle.ModeFile, Size: 1, Digest: mustDigest(t, "b")},
				good,
			},
			fault.CodeInternal,
		},
		{
			"duplicate path",
			[]FileRecord{good, good},
			fault.CodeInternal,
		},
		{
			"empty path",
			[]FileRecord{{Path: "", Mode: bundle.ModeFile}},
			fault.CodeInternal,
		},
		{
			"unnormalized mode",
			[]FileRecord{{Path: "a.txt", Mode: 0o777, Size: 1}},
			fault.CodeInternal,
		},
		{
			"mode with setuid",
			[]FileRecord{{Path: "a.txt", Mode: 0o4755, Size: 1}},
			fault.CodeInternal,
		},
		{
			"negative size",
			[]FileRecord{{Path: "a.txt", Mode: bundle.ModeFile, Size: -1}},
			fault.CodeInternal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := WriteTreeRecords(&bytes.Buffer{}, tc.records)
			if err == nil {
				t.Fatal("malformed records were encoded")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), tc.code)
			}
		})
	}
}

// Sorting is by raw UTF-8 bytes, not by locale or by rune. A locale-aware
// collation would make the digest depend on the builder's environment.
func TestWriteTreeRecordsRequiresByteOrderSorting(t *testing.T) {
	t.Parallel()

	// "Z" (0x5A) sorts before "a" (0x61) by bytes, the reverse of most
	// locale collations.
	byteOrder := []FileRecord{
		{Path: "Z.txt", Mode: bundle.ModeFile, Size: 1, Digest: mustDigest(t, "z")},
		{Path: "a.txt", Mode: bundle.ModeFile, Size: 1, Digest: mustDigest(t, "a")},
	}
	if err := WriteTreeRecords(&bytes.Buffer{}, byteOrder); err != nil {
		t.Errorf("byte-order sorted records were rejected: %v", err)
	}

	localeOrder := []FileRecord{byteOrder[1], byteOrder[0]}
	if err := WriteTreeRecords(&bytes.Buffer{}, localeOrder); err == nil {
		t.Error("locale-order sorted records were accepted")
	}
}

func TestDigestString(t *testing.T) {
	t.Parallel()

	d := mustDigest(t, "hello")
	const want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	if got := d.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got := d.Hex(); got != strings.TrimPrefix(want, "sha256:") {
		t.Errorf("Hex() = %q", got)
	}
	if got := DigestOf([]byte("hello")); got != d {
		t.Error("DigestOf disagrees with sha256.Sum256")
	}
}

func TestParseDigestRoundTrip(t *testing.T) {
	t.Parallel()

	want := mustDigest(t, "round trip")

	got, err := ParseDigest(want.String())
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if got != want {
		t.Errorf("round trip changed the digest")
	}
}

// Lax digest parsing is an algorithm-confusion foothold: two spellings of one
// digest that compare unequal defeat content addressing.
func TestParseDigestRejects(t *testing.T) {
	t.Parallel()

	valid := mustDigest(t, "x").Hex()

	tests := []struct {
		name string
		in   string
		code fault.Code
	}{
		{"empty", "", fault.CodeInvalidInput},
		{"no algorithm prefix", valid, fault.CodeInvalidInput},
		{"unsupported algorithm", "sha512:" + valid, fault.CodeUnsupportedVersion},
		{"empty algorithm", ":" + valid, fault.CodeUnsupportedVersion},
		{"too short", "sha256:" + valid[:62], fault.CodeInvalidInput},
		{"too long", "sha256:" + valid + "ab", fault.CodeInvalidInput},
		{"uppercase hex", "sha256:" + strings.ToUpper(valid), fault.CodeInvalidInput},
		{"not hex", "sha256:" + strings.Repeat("g", 64), fault.CodeInvalidInput},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDigest(tc.in); !stderrors.Is(err, tc.code) {
				t.Errorf("ParseDigest(%q) code = %q, want %q", tc.in, fault.CodeOf(err), tc.code)
			}
		})
	}
}

// TestGoldenTreeRecords freezes the record stream for a fixture that exercises
// every field: an empty file, binary content, nesting, both modes, a multibyte
// path, and byte-order sorting across cases.
func TestGoldenTreeRecords(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteTreeRecords(&buf, goldenRecords(t)); err != nil {
		t.Fatalf("WriteTreeRecords: %v", err)
	}
	golden.Assert(t, "testdata/format/v1/tree-records.bin", buf.Bytes())
}

func TestGoldenTreeDigest(t *testing.T) {
	t.Parallel()

	d, err := TreeDigest(goldenRecords(t))
	if err != nil {
		t.Fatalf("TreeDigest: %v", err)
	}
	golden.AssertString(t, "testdata/format/v1/tree-digest.txt", d.String()+"\n")
}

func goldenRecords(t *testing.T) []FileRecord {
	t.Helper()

	records := []FileRecord{
		{Path: "README.md", Mode: bundle.ModeFile, Size: 12, Digest: mustDigest(t, "hello world\n")},
		{Path: "app/config/service.yaml", Mode: bundle.ModeFile, Size: 5, Digest: mustDigest(t, "a: 1\n")},
		{Path: "app/scripts/run.sh", Mode: bundle.ModeExecutable, Size: 12, Digest: mustDigest(t, "#!/bin/sh\ns\n")},
		{Path: "empty", Mode: bundle.ModeFile, Size: 0, Digest: mustDigest(t, "")},
		{Path: "binary.dat", Mode: bundle.ModeFile, Size: 4, Digest: mustDigest(t, "\x00\x01\xfe\xff")},
		{Path: "café/naïve.txt", Mode: bundle.ModeFile, Size: 3, Digest: mustDigest(t, "utf")},
	}
	slices.SortFunc(records, func(a, b FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})
	return records
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return b
}
