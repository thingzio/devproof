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
	"encoding/binary"
	"hash/crc32"
	"io"

	"github.com/thingzio/devproof/internal/canonical/deflate"
	"github.com/thingzio/devproof/internal/fault"
)

const gzipOp = "canonical.gzip"

// GzipCompressionLevel is the DEFLATE level format v1 compresses at.
const GzipCompressionLevel = 9

// gzipHeaderV1 is the complete, fixed 10-byte gzip header for format v1
// (RFC 1952). Every field is a constant, so there is no code path that can
// make one build's header differ from another's.
//
//	1f 8b  magic
//	08     CM: deflate
//	00     FLG: no FTEXT, FHCRC, FEXTRA, FNAME, or FCOMMENT
//	00 x4  MTIME: zero. A build timestamp here would make identity depend on
//	       when the build ran, which DP-002 forbids outright.
//	02     XFL: maximum compression, matching the level above
//	ff     OS: unknown. The real host OS would leak the builder's platform
//	       into the subject digest and give Linux and macOS builds of the
//	       same tree different identities.
var gzipHeaderV1 = [10]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff}

// GzipWriter produces the canonical v1 gzip encoding of a stream.
//
// The container is written here rather than by compress/gzip because that
// package chooses some header bytes itself, and those choices are not part of
// its compatibility promise. The compressed stream comes from the frozen
// encoder in the deflate subpackage (DP-016). Between them, every byte of the
// layer is pinned.
type GzipWriter struct {
	w          io.Writer
	compressor *deflate.Writer
	crc        uint32
	size       uint32
	wroteHdr   bool
	closed     bool
	err        error
}

// GzipWriter is an io.Writer, which is why Write keeps the byte count in its
// signature even though callers in this package ignore it.
var _ io.WriteCloser = (*GzipWriter)(nil)

// NewGzipWriter returns a writer that emits the canonical v1 gzip encoding to
// w. The caller must call Close to flush the final block and the trailer.
func NewGzipWriter(w io.Writer) (*GzipWriter, error) {
	compressor, err := deflate.NewWriter(w, GzipCompressionLevel)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, gzipOp, "creating the frozen DEFLATE encoder", err)
	}
	return &GzipWriter{w: w, compressor: compressor}, nil
}

func (g *GzipWriter) Write(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	if g.closed {
		g.err = fault.New(fault.CodeInternal, gzipOp, "write after close")
		return 0, g.err
	}
	if !g.wroteHdr {
		if _, err := g.w.Write(gzipHeaderV1[:]); err != nil {
			g.err = fault.Wrap(fault.CodeInternal, gzipOp, "writing gzip header", err)
			return 0, g.err
		}
		g.wroteHdr = true
	}

	n, err := g.compressor.Write(p)
	// Account for exactly what was accepted, so a short write cannot leave
	// the trailer describing more data than the stream contains.
	g.crc = crc32.Update(g.crc, crc32.IEEETable, p[:n])
	g.size += uint32(n) //nolint:gosec // ISIZE is defined modulo 2^32 by RFC 1952
	if err != nil {
		g.err = fault.Wrap(fault.CodeInternal, gzipOp, "compressing", err)
		return n, g.err
	}
	return n, nil
}

// Close flushes the final DEFLATE block and writes the gzip trailer. It is
// idempotent, and reports the first error the writer saw.
func (g *GzipWriter) Close() error {
	if g.closed {
		return g.err
	}
	g.closed = true
	if g.err != nil {
		return g.err
	}

	// An empty stream still gets a header: a zero-byte gzip member is a valid
	// member, not an empty file.
	if !g.wroteHdr {
		if _, err := g.w.Write(gzipHeaderV1[:]); err != nil {
			g.err = fault.Wrap(fault.CodeInternal, gzipOp, "writing gzip header", err)
			return g.err
		}
		g.wroteHdr = true
	}

	if err := g.compressor.Close(); err != nil {
		g.err = fault.Wrap(fault.CodeInternal, gzipOp, "flushing the DEFLATE stream", err)
		return g.err
	}

	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[0:4], g.crc)
	binary.LittleEndian.PutUint32(trailer[4:8], g.size)
	if _, err := g.w.Write(trailer[:]); err != nil {
		g.err = fault.Wrap(fault.CodeInternal, gzipOp, "writing gzip trailer", err)
		return g.err
	}
	return nil
}
