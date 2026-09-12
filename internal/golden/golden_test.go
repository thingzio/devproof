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

package golden

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fatalSentinel emulates testing.T.Fatalf's control flow: the real one calls
// runtime.Goexit, so code after it never runs. A fake that merely recorded
// the message would let assertions run on state the real helper would have
// abandoned.
type fatalSentinel struct{ msg string }

type fakeTB struct {
	fatal string
	logs  []string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Logf(format string, args ...any) {
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func (f *fakeTB) Fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	f.fatal = msg
	panic(fatalSentinel{msg})
}

// run invokes fn and reports the Fatalf message it produced, if any.
func run(fn func(tb TB)) (tb *fakeTB, failed bool) {
	tb = &fakeTB{}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fatalSentinel); ok {
				failed = true
				return
			}
			panic(r)
		}
	}()
	fn(tb)
	return tb, false
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	return path
}

func TestAssertMatchingBytesPass(t *testing.T) {
	path := writeFixture(t, "match.bin", []byte("canonical bytes"))

	tb, failed := run(func(tb TB) { Assert(tb, path, []byte("canonical bytes")) })
	if failed {
		t.Errorf("identical bytes were reported as a mismatch: %s", tb.fatal)
	}
}

// The single most important behavior in this package: a drift must fail.
func TestAssertDifferingBytesFail(t *testing.T) {
	path := writeFixture(t, "drift.bin", []byte("canonical bytes"))

	tb, failed := run(func(tb TB) { Assert(tb, path, []byte("canonical bytee")) })
	if !failed {
		t.Fatal("differing bytes were accepted")
	}
	if !strings.Contains(tb.fatal, "compatibility surface") {
		t.Errorf("failure does not explain why this matters:\n%s", tb.fatal)
	}
	if !strings.Contains(tb.fatal, "first difference at byte 14") {
		t.Errorf("failure does not locate the divergence:\n%s", tb.fatal)
	}
}

// A trailing-byte change is the classic tar or gzip regression: same prefix,
// different length. It must not be mistaken for a match.
func TestAssertDetectsLengthChangeWithCommonPrefix(t *testing.T) {
	path := writeFixture(t, "truncated.bin", []byte("abcdef"))

	tb, failed := run(func(tb TB) { Assert(tb, path, []byte("abcdefgh")) })
	if !failed {
		t.Fatal("a longer output with a matching prefix was accepted")
	}
	if !strings.Contains(tb.fatal, "want 6, got 8") {
		t.Errorf("failure does not report the length change:\n%s", tb.fatal)
	}
	if !strings.Contains(tb.fatal, "prefix") {
		t.Errorf("failure does not identify the prefix case:\n%s", tb.fatal)
	}
}

func TestAssertEmptyFixture(t *testing.T) {
	path := writeFixture(t, "empty.bin", nil)

	if _, failed := run(func(tb TB) { Assert(tb, path, []byte{}) }); failed {
		t.Error("an empty fixture matching empty output was reported as a mismatch")
	}
	if _, failed := run(func(tb TB) { Assert(tb, path, []byte{0x00}) }); !failed {
		t.Error("a byte appearing where the fixture is empty was accepted")
	}
}

// A missing fixture must not pass by default; silence would let a new
// encoder ship with no frozen bytes at all.
func TestAssertMissingFixtureFailsWithInstructions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.bin")

	tb, failed := run(func(tb TB) { Assert(tb, path, []byte("new")) })
	if !failed {
		t.Fatal("a missing fixture was accepted")
	}
	if !strings.Contains(tb.fatal, "make regen-golden") {
		t.Errorf("failure does not say how to create the fixture:\n%s", tb.fatal)
	}
}

func TestAssertUpdatesFixtureWhenRequested(t *testing.T) {
	t.Setenv(updateEnv, "1")
	t.Setenv(ciEnv, "")

	path := filepath.Join(t.TempDir(), "nested", "regen.bin")

	if _, failed := run(func(tb TB) { Assert(tb, path, []byte("fresh")) }); failed {
		t.Fatal("regeneration failed")
	}

	got, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("fixture was not written: %v", err)
	}
	if string(got) != "fresh" {
		t.Errorf("fixture contains %q, want %q", got, "fresh")
	}
}

// Regenerating in CI would make the whole mechanism decorative: the build
// would rewrite the bytes it exists to defend.
func TestUpdateIsRefusedInCI(t *testing.T) {
	t.Setenv(updateEnv, "1")
	t.Setenv(ciEnv, "true")

	path := filepath.Join(t.TempDir(), "ci.bin")

	tb, failed := run(func(tb TB) { Assert(tb, path, []byte("fresh")) })
	if !failed {
		t.Fatal("regeneration was allowed in CI")
	}
	if !strings.Contains(tb.fatal, "defeat") {
		t.Errorf("failure does not explain the refusal:\n%s", tb.fatal)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a fixture was written despite the refusal")
	}
}

func TestAssertStringReportsMismatch(t *testing.T) {
	path := writeFixture(t, "text.json", []byte(`{"a":1}`))

	if _, failed := run(func(tb TB) { AssertString(tb, path, `{"a":1}`) }); failed {
		t.Error("identical text was reported as a mismatch")
	}
	if _, failed := run(func(tb TB) { AssertString(tb, path, `{"a": 1}`) }); !failed {
		t.Error("differing text was accepted")
	}
}
