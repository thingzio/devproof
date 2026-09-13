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

package conformance_test

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/conformance"
)

// This file holds negative vectors: archives that are structurally plausible
// and not conforming.
//
// The corruption tests elsewhere take a real artifact and damage it, which
// proves the reader notices bytes that changed. These go the other way. Each
// one is a complete, internally consistent archive of the kind a second
// implementation would produce if it read the specification slightly
// differently -- a GNU header, a PAX size record, an access time, a path that
// is valid on Linux and unopenable on Windows. Every one of them used to be
// accepted, because the reader was built on archive/tar, whose entire job is
// to paper over exactly these differences.

// block is a raw 512-byte tar header under construction.
type block [512]byte

// setString writes a NUL-padded string field.
func (b *block) setString(offset int, width int, value string) {
	copy(b[offset:offset+width], value)
}

// setOctal writes a NUL-terminated octal numeric field, the spelling USTAR
// defines for every numeric value.
func (b *block) setOctal(offset int, width int, value int64) {
	text := strconv.FormatInt(value, 8)
	for len(text) < width-1 {
		text = "0" + text
	}
	copy(b[offset:offset+width], text)
	b[offset+width-1] = 0
}

// seal computes and writes the header checksum, which must be last.
func (b *block) seal() {
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var sum int64
	for _, v := range b {
		sum += int64(v)
	}
	text := fmt.Sprintf("%06o", sum)
	copy(b[148:156], text)
	b[154] = 0
	b[155] = ' '
}

// headerFor builds a conforming USTAR header for one entry.
func headerFor(name string, mode int64, size int64, typeflag byte) block {
	var b block
	b.setString(0, 100, name)
	b.setOctal(100, 8, mode)
	b.setOctal(108, 8, 0) // uid
	b.setOctal(116, 8, 0) // gid
	b.setOctal(124, 12, size)
	b.setOctal(136, 12, 0) // mtime
	b[156] = typeflag
	b.setString(257, 6, "ustar")
	b.setString(263, 2, "00")
	b.setOctal(329, 8, 0) // devmajor
	b.setOctal(337, 8, 0) // devminor
	b.seal()
	return b
}

// paxRecord formats one extended-header record.
//
// The declared length counts itself, so it is solved for rather than computed
// -- adding a digit to the length can change the length.
func paxRecord(key, value string) string {
	body := " " + key + "=" + value + "\n"
	for n := len(body) + 1; ; n++ {
		if len(strconv.Itoa(n))+len(body) == n {
			return strconv.Itoa(n) + body
		}
	}
}

// entry is one member of a synthetic archive.
type entry struct {
	name     string
	mode     int64
	typeflag byte
	content  string
	// pax, when set, is emitted as an extended header before this entry.
	pax string
	// mutate edits the sealed header block, which is how a vector expresses a
	// deviation the builder above would never produce.
	mutate func(*block)
}

// archive assembles entries into an uncompressed tar stream.
func archive(entries []entry) []byte {
	var out bytes.Buffer
	for _, e := range entries {
		if e.pax != "" {
			header := headerFor("PaxHeaders/0", 0o644, int64(len(e.pax)), 'x')
			out.Write(header[:])
			writePadded(&out, e.pax)
		}
		header := headerFor(e.name, e.mode, int64(len(e.content)), e.typeflag)
		if e.mutate != nil {
			e.mutate(&header)
		}
		out.Write(header[:])
		writePadded(&out, e.content)
	}
	out.Write(make([]byte, 1024))
	return out.Bytes()
}

// writePadded writes content padded out to a whole number of blocks.
func writePadded(out *bytes.Buffer, content string) {
	out.WriteString(content)
	if remainder := len(content) % 512; remainder != 0 {
		out.Write(make([]byte, 512-remainder))
	}
}

// compress wraps a tar stream in the frozen v1 gzip container.
//
// compress/gzip is not used: it writes its own header, and these vectors need
// to control every byte of it.
func compress(t *testing.T, plain []byte) []byte {
	t.Helper()

	var out bytes.Buffer
	out.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff})

	writer, err := flate.NewWriter(&out, flate.BestCompression)
	if err != nil {
		t.Fatalf("creating the DEFLATE writer: %v", err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatalf("compressing: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing the DEFLATE writer: %v", err)
	}

	var trailer [8]byte
	putUint32(trailer[0:4], crc32.ChecksumIEEE(plain))
	putUint32(trailer[4:8], uint32(len(plain)))
	out.Write(trailer[:])
	return out.Bytes()
}

func putUint32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

// configFor builds the config blob that describes a synthetic archive.
//
// The tree digest is recomputed here from the specification rather than taken
// from the package under test, so a conforming vector verifies end to end and
// the control means "every rule passed" rather than "the read got far enough".
func configFor(entries []entry) string {
	type record struct {
		path   string
		mode   uint32
		size   int64
		digest [32]byte
	}

	var records []record
	for _, e := range entries {
		if e.typeflag != '0' {
			continue
		}
		records = append(records, record{
			path: e.name, mode: uint32(e.mode), size: int64(len(e.content)),
			digest: sha256.Sum256([]byte(e.content)),
		})
	}
	slices.SortFunc(records, func(a, b record) int { return strings.Compare(a.path, b.path) })

	h := sha256.New()
	h.Write([]byte("devproof-tree-v1\x00"))
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], uint64(len(records)))
	h.Write(scratch[:])

	var files []string
	var total int64
	for _, r := range records {
		binary.BigEndian.PutUint32(scratch[:4], uint32(len(r.path)))
		h.Write(scratch[:4])
		h.Write([]byte(r.path))
		binary.BigEndian.PutUint32(scratch[:4], r.mode)
		h.Write(scratch[:4])
		binary.BigEndian.PutUint64(scratch[:], uint64(r.size))
		h.Write(scratch[:])
		h.Write(r.digest[:])

		total += r.size
		files = append(files, fmt.Sprintf(
			`{"digest":"sha256:%x","mode":%d,"path":%s,"size":%d}`,
			r.digest, r.mode, jsonString(r.path), r.size))
	}

	return fmt.Sprintf(
		`{"fileCount":%d,"files":[%s],"format":"devproof-bundle-v1",`+
			`"schemaVersion":1,"totalSize":%d,"treeDigest":"sha256:%x"}`,
		len(records), strings.Join(files, ","), total, h.Sum(nil))
}

// jsonString encodes a path as a JSON string without HTML escaping.
//
// fmt's %q is Go syntax, not JSON: it spells a bell with an escape no JSON
// parser accepts. encoding/json escapes the angle brackets and the ampersand
// by default, which is valid JSON and not what a canonicalizer emits.
func jsonString(value string) string {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return strings.TrimRight(out.String(), "\n")
}

// manifestFor wires a config and a layer into a canonical manifest.
func manifestFor(config string, layer []byte) string {
	return fmt.Sprintf(`{`+
		`"artifactType":"application/vnd.thingz.devproof.bundle.v1",`+
		`"config":{"digest":"%s",`+
		`"mediaType":"application/vnd.thingz.devproof.config.v1+json","size":%d},`+
		`"layers":[{"digest":"%s",`+
		`"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":%d}],`+
		`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"schemaVersion":2}`,
		digestOf([]byte(config)), len(config), digestOf(layer), len(layer))
}

// verifyEntries runs a synthetic archive through the public entry point.
func verifyEntries(t *testing.T, entries []entry, level conformance.Level) (*conformance.Report, error) {
	t.Helper()

	return verifyLayerBytes(t, entries, compress(t, archive(entries)), level)
}

// verifyLayerBytes is the same with the compressed layer supplied, which is how
// a vector expresses damage to the container or the framing rather than to an
// entry.
func verifyLayerBytes(
	t *testing.T,
	entries []entry,
	layer []byte,
	level conformance.Level,
) (*conformance.Report, error) {

	t.Helper()

	config := configFor(entries)
	manifest := manifestFor(config, layer)

	return conformance.VerifyManifest([]byte(manifest), func(digest string) ([]byte, error) {
		switch digest {
		case digestOf([]byte(config)):
			return []byte(config), nil
		case digestOf(layer):
			return layer, nil
		}
		return nil, fmt.Errorf("no blob %s", digest)
	}, level)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// conformingEntries is the archive every vector starts from.
func conformingEntries() []entry {
	return []entry{
		{name: "a/", mode: 0o755, typeflag: '5'},
		{name: "a/b.txt", mode: 0o644, typeflag: '0', content: "hello\n"},
	}
}

// TestConformingSyntheticArchiveReachesTheInventory is the control.
//
// Without it, a vector that failed for an unrelated reason would look like a
// rule working.
func TestConformingSyntheticArchiveReachesTheInventory(t *testing.T) {
	t.Parallel()

	report, err := verifyEntries(t, conformingEntries(), conformance.LevelCanonical)
	if err != nil {
		t.Fatalf("a conforming synthetic archive was rejected: %v", err)
	}
	if len(report.Deviations) != 0 {
		t.Errorf("a conforming archive reported deviations: %v", report.Deviations)
	}
}

// TestNonConformingArchivesAreRejected is the negative vector suite.
func TestNonConformingArchivesAreRejected(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		entries func() []entry
		want    string
	}{
		{
			// DP-019 omits access and change times rather than writing them as
			// the epoch, and the format document used to permit either.
			name: "an access time in an extended header",
			entries: func() []entry {
				e := conformingEntries()
				e[1].pax = paxRecord("atime", "1700000000")
				return e
			},
			want: "v1 emits only path",
		},
		{
			name: "a size record in an extended header",
			entries: func() []entry {
				e := conformingEntries()
				e[1].pax = paxRecord("size", "6")
				return e
			},
			want: "v1 emits only path",
		},
		{
			name: "the USTAR prefix field",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "b.txt"
				e[1].mutate = func(b *block) {
					b.setString(345, 155, "a")
					b.seal()
				}
				return e
			},
			want: "prefix field",
		},
		{
			name: "a GNU header",
			entries: func() []entry {
				e := conformingEntries()
				e[1].mutate = func(b *block) {
					b.setString(257, 8, "ustar  ")
					b.seal()
				}
				return e
			},
			want: "POSIX USTAR",
		},
		{
			name: "a non-zero owner",
			entries: func() []entry {
				e := conformingEntries()
				e[1].mutate = func(b *block) {
					b.setOctal(108, 8, 1000)
					b.seal()
				}
				return e
			},
			want: "uid",
		},
		{
			name: "a user name",
			entries: func() []entry {
				e := conformingEntries()
				e[1].mutate = func(b *block) {
					b.setString(265, 32, "builder")
					b.seal()
				}
				return e
			},
			want: "uname",
		},
		{
			name: "a modification time",
			entries: func() []entry {
				e := conformingEntries()
				e[1].mutate = func(b *block) {
					b.setOctal(136, 12, 1700000000)
					b.seal()
				}
				return e
			},
			want: "mtime",
		},
		{
			name: "a base-256 size",
			entries: func() []entry {
				e := conformingEntries()
				e[1].mutate = func(b *block) {
					b[124] = 0x80
					b.seal()
				}
				return e
			},
			want: "base-256",
		},
		{
			name: "a symbolic link",
			entries: func() []entry {
				e := conformingEntries()
				e[1].typeflag = '2'
				e[1].content = ""
				return e
			},
			want: "only regular files",
		},
		{
			name: "a decomposed Unicode path",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "a/café.txt"
				return e
			},
			want: "NFC",
		},
		{
			name: "a reserved device name",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "a/CON.txt"
				return e
			},
			want: "reserved device name",
		},
		{
			name: "a reserved character",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "a/b:c.txt"
				return e
			},
			want: "reserved character",
		},
		{
			name: "a segment ending in a space",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "a/b .txt"
				e[1].name = "a/b "
				return e
			},
			want: "space or period",
		},
		{
			name: "a control character",
			entries: func() []entry {
				e := conformingEntries()
				e[1].name = "a/b\x7f.txt"
				return e
			},
			want: "control character",
		},
		{
			name: "two paths differing only by case",
			entries: func() []entry {
				e := conformingEntries()
				return append(e, entry{
					name: "a/b.TXT", mode: 0o644, typeflag: '0', content: "hello\n",
				})
			},
			want: "differ only by case",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifyEntries(t, tc.entries(), conformance.LevelCanonical)
			if err == nil {
				t.Fatal("a non-conforming archive verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestArchiveFramingIsChecked covers the bytes around the entries.
//
// Framing is where a second payload hides behind a stream that otherwise
// reads correctly, and archive/tar stops at the first terminator without
// caring what follows.
func TestArchiveFramingIsChecked(t *testing.T) {
	t.Parallel()

	plain := archive(conformingEntries())

	for _, tc := range []struct {
		name  string
		build func() []byte
		want  string
	}{
		{"one terminating block", func() []byte {
			return plain[:len(plain)-512]
		}, "want exactly"},
		{"bytes after the terminator", func() []byte {
			return append(append([]byte{}, plain...), make([]byte, 512)...)
		}, "want exactly"},
		{"a partial block", func() []byte {
			return plain[:len(plain)-8]
		}, "whole number"},
		{"non-zero content padding", func() []byte {
			out := append([]byte{}, plain...)
			// The file entry's content block is the last one before the two
			// zero blocks; its tail is padding.
			out[len(out)-1024-1] = 0x01
			return out
		}, "padding after the content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verifyLayerBytes(t, conformingEntries(),
				compress(t, tc.build()), conformance.LevelCanonical)
			if err == nil {
				t.Fatal("a malformed archive verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestGzipHeaderIsFrozen covers the container.
//
// compress/gzip parses a name, a comment, and a timestamp without complaint,
// so a writer that recorded when and where it ran produced a layer that
// decompressed correctly and had a different digest on every build.
func TestGzipHeaderIsFrozen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		edit  func([]byte)
		index int
	}{
		{name: "a modification time", edit: func(b []byte) { b[4] = 0x01 }},
		{name: "a name flag", edit: func(b []byte) { b[3] = 0x08 }},
		{name: "a different operating system", edit: func(b []byte) { b[9] = 0x03 }},
		{name: "a different compression level", edit: func(b []byte) { b[8] = 0x04 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			layer := compress(t, archive(conformingEntries()))
			tc.edit(layer)

			_, err := verifyLayerBytes(t, conformingEntries(), layer, conformance.LevelCanonical)
			if err == nil {
				t.Fatal("a layer with a non-frozen gzip header verified")
			}
			if !strings.Contains(err.Error(), "frozen v1 header") {
				t.Errorf("error %q does not mention the frozen header", err)
			}
		})
	}
}

// TestNonCanonicalJSONIsRejected covers the two documents whose bytes are the
// artifact's identity.
//
// The check used to be a json.Compact round trip, which sees insignificant
// whitespace and nothing else. Reordered members, a non-minimal string escape,
// and a number spelled with a leading zero or an exponent all survived it --
// and every one of them gives two writers two different subject digests for
// the same payload.
func TestNonCanonicalJSONIsRejected(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{"reordered members", `{"b":1,"a":2}`, "UTF-16 order"},
		{"repeated member", `{"a":1,"a":2}`, "UTF-16 order"},
		{"a space after a colon", `{"a": 1}`, "whitespace"},
		{"an escaped solidus", `{"a":"\/"}`, "not one a canonicalizer emits"},
		{"an escaped newline", `{"a":"\u000a"}`, "short form"},
		{"an escaped letter", `{"a":"\u0041"}`, "written literally"},
		{"uppercase hex", `{"a":"\u001F"}`, "uppercase"},
		{"a leading zero", `{"a":01}`, "canonical form"},
		{"an exponent", `{"a":1e2}`, "not an integer"},
		{"a fraction", `{"a":1.0}`, "not an integer"},
		{"negative zero", `{"a":-0}`, "canonical form"},
		{"trailing bytes", `{"a":1} `, "trailing bytes"},
		{"indentation", "{\n  \"a\": 1\n}", "whitespace"},
		{"an unescaped control character", "{\"a\":\"\x01\"}", "control character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := conformance.CheckCanonicalJSON([]byte(tc.doc))
			if err == nil {
				t.Fatalf("non-canonical JSON %s was accepted", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestCanonicalJSONIsAccepted keeps the check from rejecting everything.
func TestCanonicalJSONIsAccepted(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{
		`{}`,
		`[]`,
		`{"a":1,"b":[1,2,3],"c":{"d":true,"e":null}}`,
		`{"mode":420,"path":"a/b.txt","size":0}`,
		`{"a":"café"}`,
		`{"a":-1,"b":9007199254740991}`,
		`{"A":1,"a":2}`,
	} {
		t.Run(doc, func(t *testing.T) {
			t.Parallel()

			if err := conformance.CheckCanonicalJSON([]byte(doc)); err != nil {
				t.Errorf("canonical JSON %s was rejected: %v", doc, err)
			}
		})
	}
}

// TestStructuralLevelToleratesAndRecords covers the level split.
//
// Conflating the levels is how an implementation claims more than it checked.
// A structural pass answers "is this intact and safe to expand"; a GNU header
// or a user name is not that question, and a reader that failed on one would
// be useless for reading somebody else's artifact. What it must not do is stay
// quiet about them.
func TestStructuralLevelToleratesAndRecords(t *testing.T) {
	t.Parallel()

	entries := conformingEntries()
	entries[1].mutate = func(b *block) {
		b.setString(265, 32, "builder")
		b.setOctal(108, 8, 1000)
		b.seal()
	}

	if _, err := verifyEntries(t, entries, conformance.LevelCanonical); err == nil {
		t.Error("the canonical level accepted a user name")
	} else if !strings.Contains(err.Error(), "uname") {
		t.Errorf("the canonical level failed for another reason: %v", err)
	}

	report, err := verifyEntries(t, entries, conformance.LevelStructure)
	if err != nil {
		t.Fatalf("the structural level refused a readable archive: %v", err)
	}
	if len(report.Deviations) != 2 {
		t.Errorf("deviations = %v, want the user name and the owner", report.Deviations)
	}
	if report.Level != conformance.LevelStructure {
		t.Errorf("report level = %s", report.Level)
	}
}

// TestStructuralLevelStillRefusesUnsafePaths draws the other half of the line.
//
// A path that escapes the destination is not a spelling difference. Expanding
// it is the harm, so it fails at every level.
func TestStructuralLevelStillRefusesUnsafePaths(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"../escape.txt", "/absolute.txt", "a//b.txt"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entries := conformingEntries()
			entries[1].name = name

			if _, err := verifyEntries(t, entries, conformance.LevelStructure); err == nil {
				t.Fatal("an unsafe path was accepted at the structural level")
			}
		})
	}
}

// TestUnknownLevelIsRefused keeps byte conformance from being claimed by a
// function that does not check it.
func TestUnknownLevelIsRefused(t *testing.T) {
	t.Parallel()

	for _, level := range []conformance.Level{0, conformance.LevelBytes, 99} {
		t.Run(level.String(), func(t *testing.T) {
			t.Parallel()

			if _, err := verifyEntries(t, conformingEntries(), level); err == nil {
				t.Error("an artifact was checked at a level nothing implements")
			}
		})
	}
}

// TestPublishedVectorsVerify closes the loop on the byte vectors.
//
// The vectors are what another implementation compares its output against, so
// a vector that does not itself conform would propagate the error rather than
// catch it. Reading them back through this package checks that the published
// manifest, config, and layer describe one artifact, that the published subject
// and tree digests are the ones that artifact hashes to, and that the
// uncompressed layer is what the compressed one holds.
func TestPublishedVectorsVerify(t *testing.T) {
	t.Parallel()

	report, err := conformance.VerifyVectors(os.DirFS("../../vectors/format/v1"))
	if err != nil {
		t.Fatalf("the published vectors do not verify: %v", err)
	}
	if report.Level != conformance.LevelBytes {
		t.Errorf("report level = %s, want %s", report.Level, conformance.LevelBytes)
	}
	if report.FileCount == 0 {
		t.Error("the vector artifact holds no files")
	}
}
