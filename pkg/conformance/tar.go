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
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The raw USTAR header layout, transcribed from POSIX.1-1988. Offsets and
// widths are written out rather than derived, because this reader's job is to
// disagree with the writer when the writer is wrong, and a shared layout table
// would be a shared bug.
const (
	blockSize = 512

	offName     = 0
	offMode     = 100
	offUID      = 108
	offGID      = 116
	offSize     = 124
	offMTime    = 136
	offChecksum = 148
	offTypeflag = 156
	offLinkname = 157
	offMagic    = 257
	offVersion  = 263
	offUname    = 265
	offGname    = 297
	offDevmajor = 329
	offDevminor = 337
	offPrefix   = 345
	offPadding  = 500

	sizeName     = 100
	sizeNumeric  = 8
	sizeLarge    = 12
	sizeLinkname = 100
	sizeMagic    = 6
	sizeVersion  = 2
	sizeOwner    = 32
	sizePrefix   = 155
	sizePadding  = 12
)

// The only three type flags format v1 emits.
const (
	typeRegular   = '0'
	typeDirectory = '5'
	typeExtended  = 'x'
)

// maxUSTARSize is the largest value the 11 octal digits of the size field can
// hold, one byte short of 8 GiB.
//
// Format v1 rejects a larger file rather than reaching for a base-256 or PAX
// encoding, so a size that does not fit is a non-conforming archive and not a
// large one.
const maxUSTARSize = 1<<33 - 1

// ustarMagic and ustarVersion identify the one header flavor v1 writes.
//
// The GNU flavor spells the magic "ustar  \x00" and stores access and change
// times in the area this layout leaves as padding. Requiring the POSIX spelling
// is therefore also what keeps those times out of the archive.
var (
	ustarMagic   = []byte("ustar\x00")
	ustarVersion = []byte("00")
)

// tarEntry is one archive member as the raw blocks describe it.
type tarEntry struct {
	name     string
	mode     uint32
	size     int64
	typeflag byte
	content  []byte
}

// readTar walks an uncompressed archive block by block.
//
// archive/tar is deliberately not used. It is lenient by design — it accepts
// GNU and base-256 encodings, transparently joins the USTAR prefix field onto
// the name, and hides how a value was spelled — and every one of those
// kindnesses conceals exactly the deviation this package exists to find.
func readTar(data []byte) ([]tarEntry, error) {
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("the archive is %d bytes, which is not a whole number of %d-byte blocks",
			len(data), blockSize)
	}

	var (
		entries  []tarEntry
		pending  string // a path supplied by the preceding extended header
		havePath bool
		offset   int
	)

	for offset < len(data) {
		block := data[offset : offset+blockSize]
		if isZeroBlock(block) {
			if err := checkTerminator(data[offset:]); err != nil {
				return nil, err
			}
			if havePath {
				return nil, errors.New("an extended header supplies a path for no following entry")
			}
			return entries, nil
		}
		offset += blockSize

		header, err := parseHeader(block)
		if err != nil {
			return nil, err
		}

		payload, consumed, err := readPayload(data, offset, header.size)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", header.name, err)
		}
		offset += consumed

		if header.typeflag == typeExtended {
			if havePath {
				return nil, errors.New("two extended headers precede one entry")
			}
			pending, err = extendedPath(payload)
			if err != nil {
				return nil, err
			}
			havePath = true
			continue
		}

		if havePath {
			// The described entry's name field carries the path truncated to a
			// rune boundary, so the extended record must extend it rather than
			// replace it with something unrelated.
			if !strings.HasPrefix(pending, header.name) {
				return nil, fmt.Errorf(
					"an extended header supplies path %q, which does not extend the header name %q",
					pending, header.name)
			}
			header.name = pending
			havePath = false
		} else if len(header.name) > sizeName {
			// Unreachable through the field itself; stated so the invariant is
			// checked rather than assumed by the caller.
			return nil, fmt.Errorf("entry %q exceeds the name field with no extended header", header.name)
		}

		header.content = payload
		entries = append(entries, header)
	}

	return nil, errors.New("the archive ends without the two zero blocks that terminate it")
}

// checkTerminator requires exactly two zero blocks and nothing after them.
//
// Trailing bytes are where a second archive, or a payload nobody accounted
// for, hides behind a stream that otherwise reads correctly.
func checkTerminator(tail []byte) error {
	if len(tail) != 2*blockSize {
		return fmt.Errorf("the archive has %d bytes after the first zero block, want exactly %d",
			len(tail), 2*blockSize)
	}
	if !isZeroBlock(tail[blockSize:]) {
		return errors.New("the second terminating block is not zero")
	}
	return nil
}

// readPayload returns an entry's content and how many bytes it occupied.
func readPayload(data []byte, offset int, size int64) ([]byte, int, error) {
	blocks := (size + blockSize - 1) / blockSize
	consumed := int(blocks) * blockSize
	if offset+consumed > len(data) {
		return nil, 0, fmt.Errorf("declares %d bytes, which run past the end of the archive", size)
	}

	payload := data[offset : offset+int(size)]
	for _, b := range data[offset+int(size) : offset+consumed] {
		if b != 0 {
			return nil, 0, errors.New("the padding after the content is not zero")
		}
	}
	return payload, consumed, nil
}

// parseHeader reads and checks one 512-byte header block.
func parseHeader(block []byte) (tarEntry, error) {
	var entry tarEntry

	if err := verifyChecksum(block); err != nil {
		return entry, err
	}
	if got := block[offMagic : offMagic+sizeMagic]; !bytes.Equal(got, ustarMagic) {
		return entry, fmt.Errorf("header magic is %q, want the POSIX USTAR %q", got, ustarMagic)
	}
	if got := block[offVersion : offVersion+sizeVersion]; !bytes.Equal(got, ustarVersion) {
		return entry, fmt.Errorf("header version is %q, want %q", got, ustarVersion)
	}

	name := trimField(block[offName : offName+sizeName])
	entry.name = name

	// The prefix field is never written: using it means choosing where to split
	// a path, and two encoders that split differently produce different bytes
	// for the same tree.
	if err := requireEmpty(block[offPrefix:offPrefix+sizePrefix], "prefix", name); err != nil {
		return entry, err
	}
	if err := requireEmpty(block[offLinkname:offLinkname+sizeLinkname], "linkname", name); err != nil {
		return entry, err
	}
	if err := requireEmpty(block[offUname:offUname+sizeOwner], "uname", name); err != nil {
		return entry, err
	}
	if err := requireEmpty(block[offGname:offGname+sizeOwner], "gname", name); err != nil {
		return entry, err
	}
	for _, b := range block[offPadding : offPadding+sizePadding] {
		if b != 0 {
			return entry, fmt.Errorf("entry %q has a non-zero header padding byte", name)
		}
	}

	for _, field := range []struct {
		label  string
		offset int
		width  int
	}{
		{"uid", offUID, sizeNumeric},
		{"gid", offGID, sizeNumeric},
		{"mtime", offMTime, sizeLarge},
		{"devmajor", offDevmajor, sizeNumeric},
		{"devminor", offDevminor, sizeNumeric},
	} {
		value, err := parseOctal(block[field.offset:field.offset+field.width], field.label, name)
		if err != nil {
			return entry, err
		}
		if value != 0 {
			return entry, fmt.Errorf("entry %q has %s %d, want 0", name, field.label, value)
		}
	}

	mode, err := parseOctal(block[offMode:offMode+sizeNumeric], "mode", name)
	if err != nil {
		return entry, err
	}
	if mode < 0 || mode > 0o7777 {
		return entry, fmt.Errorf("entry %q has mode %o, which is not a permission value", name, mode)
	}
	entry.mode = uint32(mode) //nolint:gosec // bounded to 0o7777 directly above

	size, err := parseOctal(block[offSize:offSize+sizeLarge], "size", name)
	if err != nil {
		return entry, err
	}
	if size > maxUSTARSize {
		return entry, fmt.Errorf("entry %q declares %d bytes, above the USTAR ceiling %d",
			name, size, int64(maxUSTARSize))
	}
	entry.size = size

	entry.typeflag = block[offTypeflag]
	switch entry.typeflag {
	case typeRegular, typeDirectory, typeExtended:
	default:
		return entry, fmt.Errorf("entry %q has type %q; v1 emits only regular files, "+
			"directories, and path extended headers", name, string(entry.typeflag))
	}
	if entry.typeflag == typeDirectory && entry.size != 0 {
		return entry, fmt.Errorf("directory %q declares %d content bytes", name, entry.size)
	}
	return entry, nil
}

// verifyChecksum recomputes the header checksum.
//
// The stored field is treated as eight spaces during the sum, which is the
// convention the format defines.
func verifyChecksum(block []byte) error {
	stored, err := parseOctal(block[offChecksum:offChecksum+sizeNumeric], "checksum", "")
	if err != nil {
		return err
	}

	var sum int64
	for i, b := range block {
		if i >= offChecksum && i < offChecksum+sizeNumeric {
			sum += ' '
			continue
		}
		sum += int64(b)
	}
	if sum != stored {
		return fmt.Errorf("header checksum is %d, and the block sums to %d", stored, sum)
	}
	return nil
}

// parseOctal reads a NUL- or space-terminated octal field.
//
// A base-256 encoding — the high bit of the first byte — is refused rather than
// decoded. It is how other writers escape the USTAR field widths, and v1
// rejects the values that would need it.
func parseOctal(field []byte, label, name string) (int64, error) {
	where := label
	if name != "" {
		where = fmt.Sprintf("%s of entry %q", label, name)
	}

	if len(field) > 0 && field[0]&0x80 != 0 {
		return 0, fmt.Errorf("the %s uses a base-256 encoding, which v1 does not emit", where)
	}

	trimmed := strings.Trim(string(field), "\x00 ")
	if trimmed == "" {
		// An all-NUL numeric field is how some writers spell zero. It carries
		// the same value and no ambiguity, so it is read rather than refused.
		return 0, nil
	}
	value, err := strconv.ParseInt(trimmed, 8, 64)
	if err != nil {
		return 0, fmt.Errorf("the %s is %q, which is not octal", where, trimmed)
	}
	return value, nil
}

// extendedPath reads an extended header's records.
//
// Exactly one record, named path, is legal. Anything else — a size record, a
// timestamp, a vendor key, or a second copy of path — is a record that changes
// what the archive means and that a v1 reader has no rule for.
func extendedPath(payload []byte) (string, error) {
	rest := payload
	var found string

	for len(rest) > 0 {
		space := bytes.IndexByte(rest, ' ')
		if space <= 0 {
			return "", errors.New("an extended header record has no length prefix")
		}
		length, err := strconv.Atoi(string(rest[:space]))
		if err != nil || length <= space+1 || length > len(rest) {
			return "", fmt.Errorf("an extended header record declares length %q", rest[:space])
		}
		record := rest[space+1 : length]
		if record[len(record)-1] != '\n' {
			return "", errors.New("an extended header record does not end with a newline")
		}

		key, value, ok := strings.Cut(string(record[:len(record)-1]), "=")
		if !ok {
			return "", errors.New("an extended header record has no key")
		}
		if key != "path" {
			return "", fmt.Errorf("an extended header carries the record %q; v1 emits only path", key)
		}
		if found != "" {
			return "", errors.New("an extended header carries two path records")
		}
		if value == "" {
			return "", errors.New("an extended header carries an empty path")
		}
		found = value
		rest = rest[length:]
	}

	if found == "" {
		return "", errors.New("an extended header carries no path record")
	}
	return found, nil
}

// requireEmpty checks that a fixed field holds nothing.
func requireEmpty(field []byte, label, name string) error {
	if trimField(field) != "" {
		return fmt.Errorf("entry %q carries a %s field", name, label)
	}
	return nil
}

// trimField reads a NUL-padded string field.
func trimField(field []byte) string {
	if i := bytes.IndexByte(field, 0); i >= 0 {
		field = field[:i]
	}
	return string(field)
}

// isZeroBlock reports whether a block is entirely zero.
func isZeroBlock(block []byte) bool {
	for _, b := range block {
		if b != 0 {
			return false
		}
	}
	return true
}
