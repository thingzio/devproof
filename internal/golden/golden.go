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

// Package golden compares produced bytes against frozen fixtures.
//
// DevProof's format bytes are a compatibility surface (DP-015): canonical tree
// records, config JSON, tar headers, gzip output, and OCI manifest JSON must
// not change for a released format version, whatever a refactor or a
// dependency upgrade does. This package is the mechanism that makes such a
// change fail a test instead of silently reissuing every subject digest under
// a new identity.
//
// Fixtures live under vectors/format/<version>/ at the repository root rather
// than under a testdata directory, because they are published: an
// implementation in another language compares its output against them, and a
// testdata path is a Go convention that says "ignore this". Regenerating them
// is correct only when introducing a new format version, never when an
// existing one "looks wrong". See vectors/README.md.
package golden

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TB is the slice of *testing.T this package needs.
//
// It is a local interface rather than testing.TB because testing.TB cannot be
// implemented outside the testing package, which would leave this package's
// own failure reporting untestable — and a golden-byte checker that reports
// "match" when it should report "mismatch" is worse than no checker.
type TB interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// updateEnv, when set to "1", rewrites fixtures instead of asserting against
// them. Guarded by ciEnv below: a regeneration that runs in CI would make the
// whole mechanism decorative, because the build would rewrite the very bytes
// it is supposed to be defending.
const (
	updateEnv = "UPDATE_GOLDEN"
	ciEnv     = "CI"
)

// Assert compares got against the fixture at path, failing the test on any
// difference.
//
// path is interpreted relative to the calling package's directory, so a test
// in internal/canonical passes "../../vectors/format/v1/tree-records.bin".
func Assert(t TB, path string, got []byte) {
	t.Helper()

	if updating(t) {
		write(t, path, got)
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // test-controlled fixture path
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("golden fixture %s does not exist.\n"+
				"If this is a new fixture for a new format version, create it with:\n"+
				"    make regen-golden\n"+
				"produced %d bytes:\n%s", path, len(got), preview(got))
		}
		t.Fatalf("reading golden fixture %s: %v", path, err)
	}

	if bytes.Equal(got, want) {
		return
	}

	t.Fatalf("golden fixture %s does not match.\n\n"+
		"These bytes are a released compatibility surface. A difference here\n"+
		"means the artifact this code produces no longer has the identity it\n"+
		"used to, which is a new format version, not a fix.\n\n"+
		"%s", path, diff(want, got))
}

// AssertString is Assert for text fixtures, reporting a line-oriented
// difference rather than a hex dump.
func AssertString(t TB, path, got string) {
	t.Helper()
	Assert(t, path, []byte(got))
}

func updating(t TB) bool {
	t.Helper()

	if os.Getenv(updateEnv) != "1" {
		return false
	}
	if os.Getenv(ciEnv) != "" {
		t.Fatalf("%s is set in CI. Regenerating fixtures in CI would defeat "+
			"the compatibility check they exist to provide.", updateEnv)
	}
	return true
}

func write(t TB, path string, got []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating fixture directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // fixtures are world-readable by design
		t.Fatalf("writing golden fixture %s: %v", path, err)
	}
	t.Logf("regenerated golden fixture %s (%d bytes)", path, len(got))
}

// diff renders the first divergence. For format debugging the useful answer is
// "byte 41 changed from 0x00 to 0x20", not a page of context, because a
// canonical encoder that drifts usually drifts at exactly one field.
func diff(want, got []byte) string {
	var b strings.Builder

	fmt.Fprintf(&b, "length: want %d, got %d\n", len(want), len(got))

	at := firstDifference(want, got)
	if at < 0 {
		fmt.Fprintf(&b, "one is a prefix of the other; divergence begins at byte %d\n", min(len(want), len(got)))
		at = min(len(want), len(got))
	} else {
		fmt.Fprintf(&b, "first difference at byte %d: want %s, got %s\n",
			at, byteAt(want, at), byteAt(got, at))
	}

	const window = 32
	lo := max(0, at-window/2)
	fmt.Fprintf(&b, "\nwant [%d:]\n%s\n", lo, hex.Dump(slice(want, lo, lo+window*2)))
	fmt.Fprintf(&b, "got  [%d:]\n%s", lo, hex.Dump(slice(got, lo, lo+window*2)))

	return b.String()
}

func firstDifference(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

func byteAt(b []byte, i int) string {
	if i >= len(b) {
		return "end-of-input"
	}
	return fmt.Sprintf("0x%02x", b[i])
}

func slice(b []byte, lo, hi int) []byte {
	lo = min(max(lo, 0), len(b))
	hi = min(max(hi, lo), len(b))
	return b[lo:hi]
}

func preview(b []byte) string {
	const limit = 512
	if len(b) <= limit {
		return hex.Dump(b)
	}
	return hex.Dump(b[:limit]) + fmt.Sprintf("... (%d more bytes)\n", len(b)-limit)
}
