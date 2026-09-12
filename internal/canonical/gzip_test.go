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
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/golden"
)

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := NewGzipWriter(&buf)
	if err != nil {
		t.Fatalf("NewGzipWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// The header is ten constant bytes. Two of them exist specifically to keep
// build context out of artifact identity: MTIME must be zero and OS must be
// "unknown", or the same tree built on two machines would differ.
func TestGzipHeaderIsFixed(t *testing.T) {
	t.Parallel()

	got := gzipBytes(t, []byte("payload"))

	want := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff}
	if !bytes.Equal(got[:10], want) {
		t.Errorf("header = %s, want %s", hex.EncodeToString(got[:10]), hex.EncodeToString(want))
	}

	if mtime := binary.LittleEndian.Uint32(got[4:8]); mtime != 0 {
		t.Errorf("MTIME = %d, want 0; a build timestamp must not reach the subject", mtime)
	}
	if os := got[9]; os != 0xff {
		t.Errorf("OS = %#x, want 0xff (unknown); the real OS would differ per builder", os)
	}
	if flg := got[3]; flg != 0 {
		t.Errorf("FLG = %#x, want 0; no name, comment, or extra field may be emitted", flg)
	}
}

// The whole point of the frozen encoder is that its output must remain a
// valid gzip member that anything can read.
func TestGzipIsReadableByStandardLibrary(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte(strings.Repeat("a", 100_000)),
		[]byte("\x00\x01\xfe\xff binary \x7f"),
		[]byte(strings.Repeat("the quick brown fox ", 5_000)),
	}

	for _, payload := range payloads {
		encoded := gzipBytes(t, payload)

		r, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("gzip.NewReader rejected our output: %v", err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("closing reader: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip changed %d bytes of payload", len(payload))
		}
	}
}

func TestGzipTrailerRecordsCRCAndSize(t *testing.T) {
	t.Parallel()

	payload := []byte("the quick brown fox")
	encoded := gzipBytes(t, payload)

	trailer := encoded[len(encoded)-8:]
	if got, want := binary.LittleEndian.Uint32(trailer[0:4]), crc32.ChecksumIEEE(payload); got != want {
		t.Errorf("CRC32 = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(trailer[4:8]), uint32(len(payload)); got != want {
		t.Errorf("ISIZE = %d, want %d", got, want)
	}
}

// A zero-byte payload is a valid gzip member, not an empty file. An empty
// bundle cannot be built, but the encoder must still be total.
func TestGzipEmptyPayloadStillProducesAMember(t *testing.T) {
	t.Parallel()

	encoded := gzipBytes(t, nil)

	if len(encoded) < 18 {
		t.Fatalf("empty payload produced %d bytes, want at least a header and trailer", len(encoded))
	}
	r, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("read %d bytes from an empty member", len(got))
	}
}

// Determinism across writes: the same payload delivered in one Write and in
// many must produce identical bytes. A compressor that flushed on write
// boundaries would break this, and the tar writer does many small writes.
func TestGzipOutputIsIndependentOfWriteChunking(t *testing.T) {
	t.Parallel()

	payload := []byte(strings.Repeat("chunk me up somewhat repetitively ", 2_000))

	whole := gzipBytes(t, payload)

	var buf bytes.Buffer
	w, err := NewGzipWriter(&buf)
	if err != nil {
		t.Fatalf("NewGzipWriter: %v", err)
	}
	for chunk := range slidingChunks(payload, 7) {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(whole, buf.Bytes()) {
		t.Errorf("chunked write produced %d bytes, single write produced %d; "+
			"output depends on write boundaries", buf.Len(), len(whole))
	}
}

func slidingChunks(b []byte, size int) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for i := 0; i < len(b); i += size {
			end := min(i+size, len(b))
			if !yield(b[i:end]) {
				return
			}
		}
	}
}

func TestGzipIsDeterministic(t *testing.T) {
	t.Parallel()

	payload := []byte(strings.Repeat("determinism matters ", 1_000))

	first := gzipBytes(t, payload)
	for range 8 {
		if next := gzipBytes(t, payload); !bytes.Equal(first, next) {
			t.Fatal("two encodings of the same payload differ")
		}
	}
}

func TestGzipCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	w, err := NewGzipWriter(&buf)
	if err != nil {
		t.Fatalf("NewGzipWriter: %v", err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	before := buf.Len()
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if buf.Len() != before {
		t.Error("a second Close wrote more bytes")
	}
}

func TestGzipWriteAfterCloseFails(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	w, err := NewGzipWriter(&buf)
	if err != nil {
		t.Fatalf("NewGzipWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("late")); err == nil {
		t.Error("a write after close was accepted")
	}
}

// TestGoldenGzip freezes the compressed bytes. This is the fixture that
// catches an accidental encoder upgrade: if compress/flate is ever reached
// for instead of the frozen copy, this is where it surfaces.
func TestGoldenGzip(t *testing.T) {
	t.Parallel()

	// Deliberately compressible, with enough structure that a different
	// match-finding strategy would produce different bytes.
	payload := []byte(strings.Repeat("devproof canonical layer bytes; ", 64) +
		strings.Repeat("\x00", 512) +
		"tail")

	golden.Assert(t, "testdata/format/v1/gzip-sample.gz", gzipBytes(t, payload))
}
