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

package safefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	stderrors "errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

// hostileArchive builds a gzip-compressed tar directly, bypassing the
// canonical writer. The extractor's job is to survive archives DevProof would
// never produce, so the tests have to be able to produce them.
type hostileArchive struct {
	tw  *tar.Writer
	gz  *gzip.Writer
	buf *bytes.Buffer
}

func newHostileArchive() *hostileArchive {
	buf := &bytes.Buffer{}
	gz := gzip.NewWriter(buf)
	return &hostileArchive{tw: tar.NewWriter(gz), gz: gz, buf: buf}
}

func (a *hostileArchive) add(t *testing.T, hdr *tar.Header, body string) {
	t.Helper()
	hdr.Size = int64(len(body))
	if err := a.tw.WriteHeader(hdr); err != nil {
		t.Fatalf("writing header %q: %v", hdr.Name, err)
	}
	if _, err := io.WriteString(a.tw, body); err != nil {
		t.Fatalf("writing body for %q: %v", hdr.Name, err)
	}
}

func (a *hostileArchive) file(t *testing.T, name, body string) {
	t.Helper()
	a.add(t, &tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg}, body)
}

func (a *hostileArchive) bytes(t *testing.T) []byte {
	t.Helper()
	if err := a.tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := a.gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return a.buf.Bytes()
}

// configFor builds an inventory describing exactly the given files.
func configFor(files map[string]string) *bundle.Config {
	cfg := &bundle.Config{
		SchemaVersion: bundle.ConfigSchemaVersion,
		Format:        bundle.FormatV1,
		TreeDigest:    bundle.DigestOf([]byte("tree")).String(),
	}
	for _, name := range sortedKeys(files) {
		body := files[name]
		cfg.Files = append(cfg.Files, bundle.ConfigFile{
			Path:   name,
			Mode:   bundle.ModeFile,
			Size:   int64(len(body)),
			Digest: bundle.DigestOf([]byte(body)).String(),
		})
		cfg.TotalSize += int64(len(body))
	}
	cfg.FileCount = int64(len(cfg.Files))
	return cfg
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Simple insertion sort keeps the helper free of the sorting the code
	// under test relies on.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func extractInto(t *testing.T, layer []byte, cfg *bundle.Config, limits bundle.Limits) (string, error) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "out")
	_, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Destination: dest,
		Config:      cfg,
		Limits:      limits,
	})
	return dest, err
}

// Every one of these is an archive a consumer might be handed. None may
// produce a published destination.
func TestExtractRejectsHostileArchives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) ([]byte, *bundle.Config)
		code  fault.Code
	}{
		{
			"absolute path",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "/etc/passwd", "pwned")
				return a.bytes(t), configFor(map[string]string{"etc/passwd": "pwned"})
			},
			fault.CodeUnsafePath,
		},
		{
			"parent traversal",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "../escape.txt", "pwned")
				return a.bytes(t), configFor(map[string]string{"escape.txt": "pwned"})
			},
			fault.CodeUnsafePath,
		},
		{
			"embedded traversal",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "a/../../escape.txt", "pwned")
				return a.bytes(t), configFor(map[string]string{"escape.txt": "pwned"})
			},
			fault.CodeUnsafePath,
		},
		{
			"backslash is not a separator",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, `..\escape.txt`, "pwned")
				return a.bytes(t), configFor(map[string]string{"escape.txt": "pwned"})
			},
			fault.CodeUnsafePath,
		},
		{
			"entry not in the inventory",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "declared.txt", "ok")
				a.file(t, "smuggled.txt", "extra")
				return a.bytes(t), configFor(map[string]string{"declared.txt": "ok"})
			},
			fault.CodeInvalidArtifact,
		},
		{
			"inventory declares a file the layer omits",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "present.txt", "ok")
				return a.bytes(t), configFor(map[string]string{
					"present.txt": "ok", "absent.txt": "missing",
				})
			},
			fault.CodeInvalidArtifact,
		},
		{
			"duplicate entry",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "a.txt", "first")
				a.file(t, "a.txt", "second")
				return a.bytes(t), configFor(map[string]string{"a.txt": "first"})
			},
			fault.CodeInvalidArtifact,
		},
		{
			"content does not match the inventory digest",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "a.txt", "tampered")
				return a.bytes(t), configFor(map[string]string{"a.txt": "original"})
			},
			fault.CodeDigestMismatch,
		},
		{
			"symlink entry",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.add(t, &tar.Header{
					Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777,
				}, "")
				return a.bytes(t), configFor(map[string]string{"link": ""})
			},
			fault.CodeUnsupportedFile,
		},
		{
			"hard link entry",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "a.txt", "ok")
				a.add(t, &tar.Header{
					Name: "hard", Typeflag: tar.TypeLink, Linkname: "a.txt", Mode: 0o644,
				}, "")
				return a.bytes(t), configFor(map[string]string{"a.txt": "ok"})
			},
			fault.CodeUnsupportedFile,
		},
		{
			"character device entry",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.add(t, &tar.Header{
					Name: "dev", Typeflag: tar.TypeChar, Mode: 0o666, Devmajor: 1, Devminor: 3,
				}, "")
				return a.bytes(t), configFor(map[string]string{"dev": ""})
			},
			fault.CodeUnsupportedFile,
		},
		{
			"FIFO entry",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.add(t, &tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o644}, "")
				return a.bytes(t), configFor(map[string]string{"pipe": ""})
			},
			fault.CodeUnsupportedFile,
		},
		{
			"Windows reserved name",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "CON.txt", "x")
				return a.bytes(t), configFor(map[string]string{"CON.txt": "x"})
			},
			fault.CodeUnsafePath,
		},
		{
			"segment ending in a period",
			func(t *testing.T) ([]byte, *bundle.Config) {
				a := newHostileArchive()
				a.file(t, "name.", "x")
				return a.bytes(t), configFor(map[string]string{"name.": "x"})
			},
			fault.CodeUnsafePath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			layer, cfg := tc.build(t)

			dest, err := extractInto(t, layer, cfg, bundle.Limits{})
			if err == nil {
				t.Fatal("a hostile archive was extracted")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q (%v)", fault.CodeOf(err), tc.code, err)
			}
			// The invariant that matters most: nothing was published.
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Errorf("a destination was published despite the failure: %v", statErr)
			}
		})
	}
}

// A decompression bomb must be stopped by the streaming limit, not by
// whatever the archive declares about itself.
func TestExtractStopsDecompressionBomb(t *testing.T) {
	t.Parallel()

	bomb := strings.Repeat("\x00", 8<<20)

	a := newHostileArchive()
	a.file(t, "bomb.dat", bomb)
	layer := a.bytes(t)

	cfg := configFor(map[string]string{"bomb.dat": bomb})

	dest, err := extractInto(t, layer, cfg, bundle.Limits{MaxExpandedBytes: 1 << 20})
	if !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("a destination was published for a bomb")
	}
}

// Data appended after the gzip member is content the layer descriptor does
// not cover, so it must be refused rather than ignored.
func TestExtractRejectsTrailingGzipData(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", "ok")
	layer := a.bytes(t)

	var second bytes.Buffer
	gz := gzip.NewWriter(&second)
	if _, err := gz.Write([]byte("appended")); err != nil {
		t.Fatalf("writing second member: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing second member: %v", err)
	}

	concatenated := append(append([]byte{}, layer...), second.Bytes()...)
	cfg := configFor(map[string]string{"a.txt": "ok"})

	if _, err := extractInto(t, concatenated, cfg, bundle.Limits{}); !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
}

func TestExtractRejectsTruncatedLayer(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", strings.Repeat("x", 4096))
	layer := a.bytes(t)

	cfg := configFor(map[string]string{"a.txt": strings.Repeat("x", 4096)})

	if _, err := extractInto(t, layer[:len(layer)/2], cfg, bundle.Limits{}); err == nil {
		t.Error("a truncated layer was extracted")
	}
}

func TestExtractRejectsNonGzipLayer(t *testing.T) {
	t.Parallel()

	cfg := configFor(map[string]string{"a.txt": "ok"})

	_, err := extractInto(t, []byte("this is not gzip"), cfg, bundle.Limits{})
	if !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
}

// DP-008: the destination must not exist. v1 has no replacement semantics,
// so an existing destination is refused rather than merged into.
func TestExtractRefusesExistingDestination(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", "ok")
	layer := a.bytes(t)
	cfg := configFor(map[string]string{"a.txt": "ok"})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("creating destination: %v", err)
	}

	_, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Destination: dest,
		Config:      cfg,
	})
	if !stderrors.Is(err, fault.CodeDestinationExists) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDestinationExists)
	}
}

// Staging must leave nothing behind on failure. A leftover staging directory
// beside the destination is both clutter and a disclosure.
func TestExtractCleansStagingOnFailure(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", "tampered")
	layer := a.bytes(t)
	cfg := configFor(map[string]string{"a.txt": "original"})

	parent := t.TempDir()
	dest := filepath.Join(parent, "out")

	if _, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Destination: dest, Config: cfg,
	}); err == nil {
		t.Fatal("tampered content was extracted")
	}

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading parent: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("staging survived a failure: %v", names)
	}
}

func TestExtractHonorsCancellation(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", strings.Repeat("x", 1<<20))
	layer := a.bytes(t)
	cfg := configFor(map[string]string{"a.txt": strings.Repeat("x", 1<<20)})

	ctx, cancel := stdContext(t)
	cancel()

	parent := t.TempDir()
	dest := filepath.Join(parent, "out")

	_, err := Extract(ctx, bytes.NewReader(layer), ExtractOptions{Destination: dest, Config: cfg})
	if !stderrors.Is(err, fault.CodeCanceled) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeCanceled)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("a destination was published after cancellation")
	}
}

func TestExtractRequiresConfigAndDestination(t *testing.T) {
	t.Parallel()

	a := newHostileArchive()
	a.file(t, "a.txt", "ok")
	layer := a.bytes(t)

	if _, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Config: configFor(map[string]string{"a.txt": "ok"}),
	}); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("empty destination: code = %q", fault.CodeOf(err))
	}

	if _, err := Extract(t.Context(), bytes.NewReader(layer), ExtractOptions{
		Destination: filepath.Join(t.TempDir(), "out"),
	}); !stderrors.Is(err, fault.CodeInternal) {
		t.Errorf("nil config: code = %q", fault.CodeOf(err))
	}
}

// stdContext returns a cancelable context derived from the test's.
func stdContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithCancel(t.Context())
}
