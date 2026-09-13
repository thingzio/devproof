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

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/fault"
)

// conformanceLayout builds an artifact and returns the layout holding it.
func conformanceLayout(t *testing.T) string {
	t.Helper()

	layout := filepath.Join(t.TempDir(), "layout")
	got := run(t, "build", sourceTree(t), "--to", "oci-layout://"+layout)
	if got.code != fault.ExitSuccess {
		t.Fatalf("building the fixture: exit %d: %s", got.code, got.stderr)
	}
	return layout
}

// TestConformanceAcceptsWhatTheBuilderProduces is the loop that matters.
//
// The reader shares no code with the writer, so this is the writer being
// checked against the specification rather than against itself.
func TestConformanceAcceptsWhatTheBuilderProduces(t *testing.T) {
	t.Parallel()

	layout := conformanceLayout(t)

	for _, level := range []string{"structure", "canonical"} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()

			got := run(t, "conformance", layout, "--level", level)
			if got.code != fault.ExitSuccess {
				t.Fatalf("exit = %d: %s%s", got.code, got.stdout, got.stderr)
			}
			if !strings.Contains(got.stdout, "deviations:") {
				t.Errorf("no deviation count reported: %q", got.stdout)
			}
			if strings.Contains(got.stdout, "deviations:      0") {
				return
			}
			t.Errorf("a freshly built artifact reported deviations: %q", got.stdout)
		})
	}
}

// TestConformanceChecksThePublishedVectors makes the byte level reachable from
// the command line, which is how somebody writing a second implementation uses
// it against their own output.
func TestConformanceChecksThePublishedVectors(t *testing.T) {
	t.Parallel()

	got := run(t, "conformance", "../../vectors/format/v1", "--level", "bytes")
	if got.code != fault.ExitSuccess {
		t.Fatalf("exit = %d: %s%s", got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stdout, "level:") || !strings.Contains(got.stdout, "bytes") {
		t.Errorf("the byte level was not reported: %q", got.stdout)
	}
}

// TestConformanceRejectsADamagedArtifact keeps the command from reporting
// success for anything it was handed.
func TestConformanceRejectsADamagedArtifact(t *testing.T) {
	t.Parallel()

	layout := conformanceLayout(t)

	var target string
	err := filepath.WalkDir(filepath.Join(layout, "blobs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		// The largest blob is the layer; damaging the manifest would fail at
		// the reference lookup instead of inside the reader.
		if target == "" || info.Size() > fileSize(t, target) {
			target = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the layout: %v", err)
	}

	data, err := os.ReadFile(target) //nolint:gosec // a test-controlled path
	if err != nil {
		t.Fatalf("reading the blob: %v", err)
	}
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("writing the blob: %v", err)
	}

	if got := run(t, "conformance", layout); got.code == fault.ExitSuccess {
		t.Errorf("a damaged artifact conformed: %s", got.stdout)
	}
}

// TestConformanceRejectsAnUnknownLevel keeps a typo from silently selecting
// the weakest check.
func TestConformanceRejectsAnUnknownLevel(t *testing.T) {
	t.Parallel()

	got := run(t, "conformance", t.TempDir(), "--level", "loose")
	if got.code != fault.ExitUsage {
		t.Errorf("exit = %d, want %d: %s", got.code, fault.ExitUsage, got.stderr)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
