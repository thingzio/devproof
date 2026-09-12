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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof"
	"github.com/thingzio/devproof/conformance"
)

// build produces a bundle with the main implementation and returns the layout
// directory and the build result.
//
// The main implementation is used only to *produce*; everything the test
// asserts is established by reading the bytes back independently.
func build(t *testing.T, files map[string]string) (string, *devproof.BuildResult) {
	t.Helper()

	source := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(source, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", full, err)
		}
	}

	client, err := devproof.New()
	if err != nil {
		t.Fatalf("creating a client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	layout := filepath.Join(t.TempDir(), "layout")
	result, err := client.Build(context.Background(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	return layout, result
}

// The central claim: an independent reader, sharing no code with the writer,
// recomputes the same tree digest from the layer bytes.
func TestIndependentReadAgreesOnDigests(t *testing.T) {
	t.Parallel()

	layout, built := build(t, map[string]string{
		"README.md":               "hello\n",
		"app/config/service.yaml": "replicas: 3\n",
		"app/bin/data.bin":        strings.Repeat("\x00\xff", 512),
		"deeply/nested/dir/x.txt": "x\n",
	})

	report, err := conformance.VerifyLayout(layout, "v1")
	if err != nil {
		t.Fatalf("independent verification failed: %v", err)
	}

	if report.ManifestDigest != built.SubjectDigest {
		t.Errorf("subject digest:\n  writer: %s\n  reader: %s",
			built.SubjectDigest, report.ManifestDigest)
	}
	if report.TreeDigest != built.TreeDigest {
		t.Errorf("tree digest recomputed from the layer disagrees with the writer:\n"+
			"  writer: %s\n  reader: %s", built.TreeDigest, report.TreeDigest)
	}
	if report.TreeDigest != report.ConfigTreeDigest {
		t.Errorf("recomputed tree digest %s does not match the config's %s",
			report.TreeDigest, report.ConfigTreeDigest)
	}
	if report.FileCount != built.FileCount {
		t.Errorf("file count: writer %d, reader %d", built.FileCount, report.FileCount)
	}
}

// Resolution by digest must reach the same artifact as resolution by tag.
func TestResolveByDigestAndTag(t *testing.T) {
	t.Parallel()

	layout, built := build(t, map[string]string{"a.txt": "a\n"})

	byTag, err := conformance.VerifyLayout(layout, "v1")
	if err != nil {
		t.Fatalf("by tag: %v", err)
	}
	byDigest, err := conformance.VerifyLayout(layout, built.SubjectDigest)
	if err != nil {
		t.Fatalf("by digest: %v", err)
	}
	if byTag.ManifestDigest != byDigest.ManifestDigest {
		t.Errorf("tag and digest resolved to different manifests: %s and %s",
			byTag.ManifestDigest, byDigest.ManifestDigest)
	}
}

// Unicode, executable bits, empty files, and nesting are all format features,
// so the independent reader must agree on every one of them.
func TestIndependentReadHandlesAwkwardTrees(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]string{
		"empty file":       {"empty.txt": ""},
		"unicode path":     {"café/日本語.txt": "unicode\n"},
		"deep nesting":     {"a/b/c/d/e/f/g/h.txt": "deep\n"},
		"many siblings":    manyFiles(64),
		"large-ish file":   {"big.bin": strings.Repeat("abcdefgh", 4096)},
		"shared prefixes":  {"a.txt": "1\n", "a/b.txt": "2\n", "ab.txt": "3\n"},
		"sorting boundary": {"a-b.txt": "1\n", "a.b.txt": "2\n", "a/b.txt": "3\n"},
	}

	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			layout, built := build(t, files)
			report, err := conformance.VerifyLayout(layout, "v1")
			if err != nil {
				t.Fatalf("independent verification failed: %v", err)
			}
			if report.TreeDigest != built.TreeDigest {
				t.Errorf("tree digest:\n  writer: %s\n  reader: %s",
					built.TreeDigest, report.TreeDigest)
			}
			if report.ManifestDigest != built.SubjectDigest {
				t.Errorf("subject digest:\n  writer: %s\n  reader: %s",
					built.SubjectDigest, report.ManifestDigest)
			}
		})
	}
}

func manyFiles(n int) map[string]string {
	files := make(map[string]string, n)
	for i := range n {
		files[string(rune('a'+i%26))+string(rune('0'+i/26))+".txt"] = "content\n"
	}
	return files
}

// A verifier that accepts a corrupted artifact is worse than none. Each
// mutation below breaks a different rule, and every one must be caught.
func TestCorruptionIsDetected(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(t *testing.T, layout string, built *devproof.BuildResult)
		want   string
	}{
		"flipped byte in the layer": {
			mutate: func(t *testing.T, layout string, built *devproof.BuildResult) {
				path := layerBlob(t, layout, built)
				data := readFile(t, path)
				data[len(data)/2] ^= 0x01
				writeFile(t, path, data)
			},
			want: "content hashes to",
		},
		"truncated layer": {
			mutate: func(t *testing.T, layout string, built *devproof.BuildResult) {
				path := layerBlob(t, layout, built)
				data := readFile(t, path)
				writeFile(t, path, data[:len(data)-8])
			},
			want: "declares",
		},
		"flipped byte in the config": {
			mutate: func(t *testing.T, layout string, built *devproof.BuildResult) {
				path := configBlob(t, layout, built)
				data := readFile(t, path)
				data[len(data)/2] ^= 0x01
				writeFile(t, path, data)
			},
			want: "content hashes to",
		},
		"manifest replaced by an empty object": {
			mutate: func(t *testing.T, layout string, built *devproof.BuildResult) {
				writeFile(t, blobPath(layout, built.SubjectDigest), []byte(`{}`))
			},
			want: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			layout, built := build(t, map[string]string{
				"README.md": "hello\n",
				"a/b.txt":   strings.Repeat("padding to make this the largest blob\n", 32),
			})
			if _, err := conformance.VerifyLayout(layout, "v1"); err != nil {
				t.Fatalf("the unmodified artifact did not verify: %v", err)
			}

			tc.mutate(t, layout, built)

			_, err := conformance.VerifyLayout(layout, "v1")
			if err == nil {
				t.Fatal("a corrupted artifact verified successfully")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func blobPath(layout, digest string) string {
	return filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// testManifest is the manifest subset a corruption test needs to find a
// specific blob.
type testManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// manifestOf decodes the subject manifest so a test can target a specific
// blob rather than guessing by size.
func manifestOf(t *testing.T, layout string, built *devproof.BuildResult) testManifest {
	t.Helper()

	var m testManifest
	if err := json.Unmarshal(readFile(t, blobPath(layout, built.SubjectDigest)), &m); err != nil {
		t.Fatalf("decoding the manifest: %v", err)
	}
	return m
}

func layerBlob(t *testing.T, layout string, built *devproof.BuildResult) string {
	t.Helper()

	m := manifestOf(t, layout, built)
	if len(m.Layers) != 1 {
		t.Fatalf("manifest has %d layers", len(m.Layers))
	}
	return blobPath(layout, m.Layers[0].Digest)
}

func configBlob(t *testing.T, layout string, built *devproof.BuildResult) string {
	t.Helper()

	return blobPath(layout, manifestOf(t, layout, built).Config.Digest)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
