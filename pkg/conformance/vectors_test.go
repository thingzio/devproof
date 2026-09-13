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
	"encoding/hex"
	"fmt"
	"hash/crc32"
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

// verifyLayer runs a synthetic layer through the public entry point.
//
// The config it builds is deliberately not consistent with the layer: every
// layer rule is checked before the inventory is compared, so a conforming
// layer reaches the tree-digest comparison and fails there. That makes the
// base case a control -- "tree digest" means every header rule passed -- and
// each vector's own message the thing under test.
func verifyLayer(t *testing.T, layer []byte) error {
	t.Helper()

	config := `{"schemaVersion":1,"format":"devproof-bundle-v1",` +
		`"treeDigest":"sha256:` + strings.Repeat("0", 64) + `",` +
		`"fileCount":0,"totalSize":0,"files":[]}`

	manifest := fmt.Sprintf(`{"schemaVersion":2,`+
		`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"artifactType":"application/vnd.thingz.devproof.bundle.v1",`+
		`"config":{"mediaType":"application/vnd.thingz.devproof.config.v1+json",`+
		`"digest":"%s","size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip",`+
		`"digest":"%s","size":%d}]}`,
		digestOf([]byte(config)), len(config), digestOf(layer), len(layer))

	_, err := conformance.VerifyManifest([]byte(manifest), func(digest string) ([]byte, error) {
		switch digest {
		case digestOf([]byte(config)):
			return []byte(config), nil
		case digestOf(layer):
			return layer, nil
		}
		return nil, fmt.Errorf("no blob %s", digest)
	})
	return err
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

	err := verifyLayer(t, compress(t, archive(conformingEntries())))
	if err == nil {
		t.Fatal("a layer that does not match its config verified")
	}
	if !strings.Contains(err.Error(), "the config declares") {
		t.Fatalf("the synthetic archive failed a header rule rather than the inventory: %v", err)
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
				e[1].name = "a/b\x07.txt"
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

			err := verifyLayer(t, compress(t, archive(tc.entries())))
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

			err := verifyLayer(t, compress(t, tc.build()))
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

			err := verifyLayer(t, layer)
			if err == nil {
				t.Fatal("a layer with a non-frozen gzip header verified")
			}
			if !strings.Contains(err.Error(), "frozen v1 header") {
				t.Errorf("error %q does not mention the frozen header", err)
			}
		})
	}
}
