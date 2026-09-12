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

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// newProgressPrinter returns a printer writing to buffers.
func newProgressPrinter(terminal bool) (*Printer, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return &Printer{
		Streams: Streams{Out: &out, Err: &errOut, IsTerminal: terminal},
		Format:  FormatText,
	}, &out, &errOut
}

// Progress is for a human watching a slow operation. Written to a pipe it is
// noise; written to stdout it is corruption.
func TestProgressIsSilentWhenNotATerminal(t *testing.T) {
	t.Parallel()

	printer, out, errOut := newProgressPrinter(false)
	printer.Progress().Step("resolving sources")
	printer.Progress().Done()

	if out.Len() != 0 {
		t.Errorf("progress reached stdout: %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("progress was written to a non-terminal stderr: %q", errOut.String())
	}
}

func TestProgressNeverReachesStdout(t *testing.T) {
	t.Parallel()

	printer, out, _ := newProgressPrinter(true)
	printer.Progress().Step("resolving sources")
	printer.Progress().Done()

	if out.Len() != 0 {
		t.Errorf("progress reached stdout: %q", out.String())
	}
}

func TestProgressWritesToATerminal(t *testing.T) {
	t.Parallel()

	printer, _, errOut := newProgressPrinter(true)
	printer.Progress().Step("resolving sources")

	if !strings.Contains(errOut.String(), "resolving sources") {
		t.Errorf("no progress was drawn: %q", errOut.String())
	}
}

// Quiet and JSON both promise a machine-readable stream. A spinner in either
// is the same corruption as a log line.
func TestProgressRespectsQuietAndJSON(t *testing.T) {
	t.Parallel()

	for name, configure := range map[string]func(*Printer){
		"quiet": func(p *Printer) { p.Quiet = true },
		"json":  func(p *Printer) { p.Format = FormatJSON },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			printer, out, errOut := newProgressPrinter(true)
			configure(printer)
			printer.Progress().Step("working")

			if out.Len() != 0 || errOut.Len() != 0 {
				t.Errorf("progress was drawn in %s mode: stdout=%q stderr=%q",
					name, out.String(), errOut.String())
			}
		})
	}
}

// Under --verbose the same steps become permanent lines: a CI log is exactly
// where knowing which step was running when something failed is worth the
// extra output.
func TestVerboseTurnsProgressIntoLines(t *testing.T) {
	t.Parallel()

	printer, out, errOut := newProgressPrinter(false)
	printer.Verbose = true
	printer.Progress().Step("resolving sources")

	if out.Len() != 0 {
		t.Errorf("verbose progress reached stdout: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "resolving sources") {
		t.Errorf("verbose did not record the step: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "\r") {
		t.Error("a permanent line was written with a carriage return")
	}
}

// A long step must not wrap: a wrapped line cannot be erased by returning to
// its start, so its tail stays on screen and accumulates.
func TestProgressTruncatesLongSteps(t *testing.T) {
	t.Parallel()

	printer, _, errOut := newProgressPrinter(true)
	printer.Progress().Step("%s", strings.Repeat("x", progressWidth*2))

	for _, line := range strings.Split(errOut.String(), "\r") {
		if len([]rune(stripANSI(line))) > progressWidth {
			t.Errorf("a progress line is %d runes, want at most %d",
				len([]rune(stripANSI(line))), progressWidth)
		}
	}
}

// A shorter step must fully erase a longer one, or the tail of the previous
// step stays on screen and reads as part of the new one.
func TestProgressErasesThepreviousStep(t *testing.T) {
	t.Parallel()

	printer, _, errOut := newProgressPrinter(true)
	printer.Progress().Step("a very long step description")
	before := errOut.Len()
	printer.Progress().Step("short")

	written := errOut.String()[before:]
	erased := strings.Repeat(" ", len("a very long step description")-len("short"))
	if !strings.HasSuffix(written, erased) {
		t.Errorf("the previous step was not erased: %q", written)
	}
}

// Real output must never be printed on top of a half-erased progress line.
func TestOutputClearsPendingProgress(t *testing.T) {
	t.Parallel()

	for name, emit := range map[string]func(*Printer){
		"warning": func(p *Printer) { p.Warn("careful") },
		"success": func(p *Printer) { p.Success("done") },
		"result": func(p *Printer) {
			_ = p.Result("Test", nil, "", func(w io.Writer) { _, _ = w.Write([]byte("value\n")) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			printer, _, errOut := newProgressPrinter(true)
			printer.Progress().Step("working on something")
			emit(printer)

			// The erase sequence is a carriage return, spaces, and another
			// carriage return, emitted before whatever came next.
			erase := "\r" + strings.Repeat(" ", len("working on something")) + "\r"
			if !strings.Contains(errOut.String(), erase) {
				t.Errorf("%s did not erase the progress line: %q", name, errOut.String())
			}
		})
	}
}

// Done on an inactive reporter must not emit a stray carriage return.
func TestProgressDoneIsIdempotent(t *testing.T) {
	t.Parallel()

	printer, _, errOut := newProgressPrinter(true)
	printer.Progress().Done()
	printer.Progress().Done()

	if errOut.Len() != 0 {
		t.Errorf("Done wrote something with no active line: %q", errOut.String())
	}
}

// stripANSI removes color escapes so a length assertion measures text.
func stripANSI(s string) string {
	for {
		start := strings.Index(s, "\033[")
		if start < 0 {
			return s
		}
		end := strings.IndexByte(s[start:], 'm')
		if end < 0 {
			return s
		}
		s = s[:start] + s[start+end+1:]
	}
}
