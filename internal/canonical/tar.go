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
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const tarOp = "canonical.tar"

// USTAR layout constants.
const (
	blockSize = 512

	nameSize     = 100
	linknameSize = 100
	// prefixSize is the USTAR prefix field. Format v1 never writes it: using
	// it would require choosing where to split a path, and two encoders that
	// split differently would produce different bytes for the same tree. A
	// path too long for the name field gets a PAX record instead, which has
	// exactly one spelling.
	prefixSize = 155

	typeRegular   = '0'
	typeDirectory = '5'
	typePAX       = 'x'
)

// headerFieldTotal is the USTAR field layout laid out in order: name, mode,
// uid, gid, size, mtime, chksum, typeflag, linkname, magic, version, uname,
// gname, devmajor, devminor, prefix, and the trailing pad.
const headerFieldTotal = nameSize + 8 + 8 + 8 + 12 + 12 + 8 + 1 +
	linknameSize + 6 + 2 + 32 + 32 + 8 + 8 + prefixSize + 12

// Compile-time assertion that the field layout exactly fills one block. The
// offsets in buildHeaderBlock are written as literals for readability, so
// this is what catches a typo in one of them.
var _ = [1]struct{}{}[blockSize-headerFieldTotal]

// Fixed header field values. Every one of these exists to keep build context
// out of artifact identity (DP-019).
const (
	tarUID   = 0
	tarGID   = 0
	tarMtime = 0
)

// MaxFileSize is the largest file format v1 can represent: eleven octal
// digits in the 12-byte USTAR size field, one byte short of 8 GiB.
//
// Files larger than this are rejected rather than described with a PAX size
// record. Two reasons. The rule for when PAX appears collapses to a single
// case — a path too long for the name field — so there is one thing to
// specify and one thing to verify. And a PAX size path could not be
// meaningfully tested without an 8 GiB fixture, which would leave an
// untested branch in the code that decides artifact identity.
//
// Raising this is a format-version decision.
const MaxFileSize = int64(1)<<33 - 1

// TarWriter emits the canonical v1 tar stream.
//
// It is written by hand rather than with archive/tar because DP-019 fixes
// every header byte, including PAX record naming, ordering, and numeric
// encoding. archive/tar makes several of those choices itself, and none of
// them are covered by its compatibility promise — the same coupling DP-016
// removed for the compressor.
//
// The writer does not sort. It emits what it is given, in the order given,
// and rejects anything that would produce a stream a consumer could
// materialize two ways.
type TarWriter struct {
	w      io.Writer
	index  int
	closed bool
	err    error
}

// NewTarWriter returns a writer emitting the canonical v1 tar stream to w.
func NewTarWriter(w io.Writer) *TarWriter { return &TarWriter{w: w} }

// WriteDirectory emits a directory entry.
//
// Directories are derived from file paths, never carried from a source, so
// this takes a path and nothing else: there is no mode or ownership to get
// wrong.
func (t *TarWriter) WriteDirectory(path string) error {
	if t.err != nil {
		return t.err
	}
	// The trailing separator is the tar convention for a directory, and is
	// what lets a reader distinguish one without relying on the typeflag.
	return t.writeHeader(path+"/", bundle.ModeDirectory, 0, typeDirectory)
}

// WriteFile emits a file entry and copies its content, hashing as it goes.
//
// The observed digest and size are checked against rec before the entry is
// considered written. Hashing here rather than trusting the inventory is what
// closes the time-of-check gap: content that changed between snapshot and
// packaging fails the build instead of producing a bundle whose layer
// disagrees with its own config.
func (t *TarWriter) WriteFile(rec FileRecord, content io.Reader) error {
	if t.err != nil {
		return t.err
	}
	if rec.Mode != bundle.ModeFile && rec.Mode != bundle.ModeExecutable {
		return t.fail(fault.New(fault.CodeInternal, tarOp,
			fmt.Sprintf("mode %#o is not normalized", rec.Mode)).WithPath(string(rec.Path)))
	}

	if err := t.writeHeader(string(rec.Path), rec.Mode, rec.Size, typeRegular); err != nil {
		return err
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(t.w, hasher), io.LimitReader(content, rec.Size))
	if err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "copying file content", err).
			WithPath(string(rec.Path)))
	}
	if written != rec.Size {
		return t.fail(fault.New(fault.CodeDigestMismatch, tarOp,
			fmt.Sprintf("file is %d bytes, inventory declares %d", written, rec.Size)).
			WithPath(string(rec.Path)))
	}
	// A reader that supplies more than Size would otherwise be silently
	// truncated by the LimitReader above, producing a valid-looking layer
	// built from content nobody verified.
	if extra, _ := io.CopyN(io.Discard, content, 1); extra != 0 {
		return t.fail(fault.New(fault.CodeDigestMismatch, tarOp,
			"file is longer than the inventory declares").WithPath(string(rec.Path)))
	}

	var observed Digest
	hasher.Sum(observed[:0])
	if observed != rec.Digest {
		return t.fail(fault.New(fault.CodeDigestMismatch, tarOp,
			fmt.Sprintf("content digest is %s, inventory declares %s", observed, rec.Digest)).
			WithPath(string(rec.Path)))
	}

	return t.writePadding(rec.Size)
}

// Close writes the two zero blocks that terminate the archive. Nothing may
// follow them.
func (t *TarWriter) Close() error {
	if t.closed {
		return t.err
	}
	t.closed = true
	if t.err != nil {
		return t.err
	}
	var terminator [2 * blockSize]byte
	if _, err := t.w.Write(terminator[:]); err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "writing archive terminator", err))
	}
	return nil
}

func (t *TarWriter) fail(err error) error {
	if t.err == nil {
		t.err = err
	}
	return t.err
}

func (t *TarWriter) writeHeader(name string, mode uint32, size int64, typeflag byte) error {
	if size < 0 {
		return t.fail(fault.New(fault.CodeInternal, tarOp, "negative size").WithPath(name))
	}

	if size > MaxFileSize {
		return t.fail(fault.New(fault.CodeLimitExceeded, tarOp,
			fmt.Sprintf("file is %d bytes; format v1 represents at most %d", size, MaxFileSize)).
			WithPath(name))
	}

	// A PAX extended header is emitted for exactly one reason: a path too
	// long for the USTAR name field (DP-019). Keeping it to one case means
	// there is one rule to specify, one branch to test, and no ordering
	// question between multiple records.
	headerName := name
	if len(name) > nameSize {
		if err := t.writePAXHeader(paxRecord{key: "path", value: name}); err != nil {
			return err
		}
		headerName = truncateAtRune(name, nameSize)
	}

	block, err := buildHeaderBlock(headerName, mode, size, typeflag)
	if err != nil {
		return t.fail(err)
	}
	if _, err := t.w.Write(block[:]); err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "writing header", err).WithPath(name))
	}
	t.index++
	return nil
}

type paxRecord struct{ key, value string }

func (t *TarWriter) writePAXHeader(records ...paxRecord) error {
	var body strings.Builder
	for _, rec := range records {
		body.WriteString(formatPAXRecord(rec.key, rec.value))
	}
	payload := body.String()

	// The extended header's own name is never interpreted; readers use it
	// only for display. It is derived from the entry ordinal rather than from
	// the path so it is always short, always unique, and never itself needs
	// a PAX record to describe.
	name := "PaxHeaders/" + strconv.Itoa(t.index)

	block, err := buildHeaderBlock(name, bundle.ModeFile, int64(len(payload)), typePAX)
	if err != nil {
		return t.fail(err)
	}
	if _, err := t.w.Write(block[:]); err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "writing PAX header", err))
	}
	if _, err := io.WriteString(t.w, payload); err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "writing PAX records", err))
	}
	t.index++
	return t.writePadding(int64(len(payload)))
}

// formatPAXRecord renders "<len> <key>=<value>\n", where len counts its own
// digits. The length is self-referential, so it is solved by iteration rather
// than guessed: adding a digit to the count can push the count to another
// digit.
func formatPAXRecord(key, value string) string {
	const overhead = len(" ") + len("=") + len("\n")
	size := overhead + len(key) + len(value)
	for digits := 1; ; digits++ {
		total := size + digits
		if len(strconv.Itoa(total)) == digits {
			return strconv.Itoa(total) + " " + key + "=" + value + "\n"
		}
	}
}

func (t *TarWriter) writePadding(size int64) error {
	remainder := size % blockSize
	if remainder == 0 {
		return nil
	}
	var pad [blockSize]byte
	if _, err := t.w.Write(pad[:blockSize-remainder]); err != nil {
		return t.fail(fault.Wrap(fault.CodeInternal, tarOp, "writing padding", err))
	}
	return nil
}

// buildHeaderBlock renders one 512-byte USTAR header.
//
// Field offsets are from POSIX.1-1988. Everything not derived from the entry
// is a constant, so the only inputs that can reach the bytes are the path,
// the normalized mode, the size, and the type.
func buildHeaderBlock(name string, mode uint32, size int64, typeflag byte) (*[blockSize]byte, error) {
	if len(name) > nameSize {
		return nil, fault.New(fault.CodeInternal, tarOp,
			fmt.Sprintf("header name is %d bytes, USTAR allows %d", len(name), nameSize)).
			WithPath(name)
	}

	var b [blockSize]byte
	var f octalFormatter

	copy(b[0:nameSize], name)
	f.put(b[100:108], int64(mode))
	f.put(b[108:116], tarUID)
	f.put(b[116:124], tarGID)
	f.put(b[124:136], size)
	f.put(b[136:148], tarMtime)
	// b[148:156] is the checksum, filled in last.
	b[156] = typeflag
	// b[157:257] linkname stays zero: v1 has no links.
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	// b[265:297] uname and b[297:329] gname stay empty. A real user name
	// would make the same tree hash differently per builder.
	f.put(b[329:337], 0) // devmajor
	f.put(b[337:345], 0) // devminor
	// b[345:500] prefix stays zero; see prefixSize.

	if f.err != nil {
		return nil, fault.Wrap(fault.CodeInternal, tarOp, "encoding header field", f.err).
			WithPath(name)
	}

	writeChecksum(&b, &f)
	if f.err != nil {
		return nil, fault.Wrap(fault.CodeInternal, tarOp, "encoding header checksum", f.err).
			WithPath(name)
	}
	return &b, nil
}

// octalFormatter writes right-aligned, zero-padded octal values, filling all
// but the last byte of a field and leaving that NUL. This is the encoding GNU
// tar and every reader in common use expects.
//
// It accumulates the first error rather than returning one per call: a value
// that does not fit is a broken invariant, not a condition to branch on at
// every field, and threading an error through twelve assignments would bury
// the layout the function exists to express.
type octalFormatter struct{ err error }

func (f *octalFormatter) put(field []byte, value int64) {
	width := len(field) - 1
	digits := strconv.FormatInt(value, 8)

	if value < 0 || len(digits) > width {
		if f.err == nil {
			f.err = fmt.Errorf("value %d needs %d octal digits, field holds %d",
				value, len(digits), width)
		}
		return
	}

	for i := range field {
		field[i] = 0
	}
	start := width - len(digits)
	for i := range start {
		field[i] = '0'
	}
	copy(field[start:width], digits)
}

// writeChecksum fills the header checksum, which is the unsigned sum of every
// byte with the checksum field itself treated as eight spaces.
func writeChecksum(b *[blockSize]byte, f *octalFormatter) {
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var sum int64
	for _, c := range b {
		sum += int64(c)
	}
	// Six octal digits, NUL, then a space: the historical layout, and the
	// one every reader accepts.
	f.put(b[148:155], sum)
	b[155] = ' '
}

// truncateAtRune returns the longest prefix of s that is at most n bytes and
// ends on a rune boundary.
//
// The USTAR name field of a PAX-described entry is never interpreted by a
// conforming reader, but it must still be deterministic and must not contain
// a split rune.
func truncateAtRune(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
