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
	"context"
	stderrors "errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/golden"
	"github.com/thingzio/devproof/pkg/bundle"
)

// memorySource is a frozen snapshot held in memory.
type memorySource map[Path]string

func (m memorySource) Open(_ context.Context, path Path) (io.ReadCloser, error) {
	content, ok := m[path]
	if !ok {
		return nil, stderrors.New("no such path in snapshot: " + string(path))
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

// fixture returns the canonical test tree: an empty file, binary content,
// nesting, both modes, a multibyte path, and a path long enough to need PAX.
func fixture(t *testing.T) ([]FileRecord, memorySource) {
	t.Helper()

	files := map[string]struct {
		mode uint32
		data string
	}{
		"README.md":               {bundle.ModeFile, "hello world\n"},
		"app/config/service.yaml": {bundle.ModeFile, "a: 1\n"},
		"app/scripts/run.sh":      {bundle.ModeExecutable, "#!/bin/sh\ns\n"},
		"binary.dat":              {bundle.ModeFile, "\x00\x01\xfe\xff"},
		"café/naïve.txt":          {bundle.ModeFile, "utf"},
		strings.Repeat("directory/", 12) + "deep.txt": {bundle.ModeFile, "deep"},
		"empty": {bundle.ModeFile, ""},
	}

	src := memorySource{}
	records := make([]FileRecord, 0, len(files))
	for path, f := range files {
		src[Path(path)] = f.data
		records = append(records, FileRecord{
			Path:   Path(path),
			Mode:   f.mode,
			Size:   int64(len(f.data)),
			Digest: DigestOf([]byte(f.data)),
		})
	}
	slices.SortFunc(records, func(a, b FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})
	return records, src
}

func packageFixture(t *testing.T) (*Subject, []byte) {
	t.Helper()

	records, src := fixture(t)

	var layer bytes.Buffer
	subject, err := Package(t.Context(), records, src, &layer)
	if err != nil {
		t.Fatalf("Package: %v", err)
	}
	return subject, layer.Bytes()
}

// Every digest the subject reports must actually describe the bytes it
// reports. A subject whose parts disagree would pass its own verification and
// fail everyone else's.
func TestPackageSubjectIsSelfConsistent(t *testing.T) {
	t.Parallel()

	subject, layer := packageFixture(t)

	if got := DigestOf(subject.ManifestBytes); got != subject.ManifestDigest {
		t.Errorf("manifest digest %s does not describe the manifest bytes (%s)",
			subject.ManifestDigest, got)
	}
	if got := DigestOf(subject.ConfigBytes); got != subject.ConfigDigest {
		t.Errorf("config digest %s does not describe the config bytes (%s)",
			subject.ConfigDigest, got)
	}
	if got := DigestOf(layer); got != subject.LayerDigest {
		t.Errorf("layer digest %s does not describe the layer bytes (%s)",
			subject.LayerDigest, got)
	}
	if subject.LayerSize != int64(len(layer)) {
		t.Errorf("layer size %d, wrote %d bytes", subject.LayerSize, len(layer))
	}

	if err := subject.ConfigDescriptor().VerifyContent(subject.ConfigBytes); err != nil {
		t.Errorf("config descriptor does not verify its own blob: %v", err)
	}
	if err := subject.LayerDescriptor().VerifyContent(layer); err != nil {
		t.Errorf("layer descriptor does not verify its own blob: %v", err)
	}
	if err := subject.Descriptor().VerifyContent(subject.ManifestBytes); err != nil {
		t.Errorf("subject descriptor does not verify its own manifest: %v", err)
	}
}

// The manifest must reference exactly the blobs that were produced, not
// merely plausible ones.
func TestPackageManifestReferencesItsOwnBlobs(t *testing.T) {
	t.Parallel()

	subject, _ := packageFixture(t)

	if subject.Manifest.Config.Digest != subject.ConfigDigest.String() {
		t.Error("manifest config descriptor does not name the config that was built")
	}
	layer, err := subject.Manifest.Layer()
	if err != nil {
		t.Fatalf("Layer: %v", err)
	}
	if layer.Digest != subject.LayerDigest.String() {
		t.Error("manifest layer descriptor does not name the layer that was written")
	}
	if err := subject.Manifest.Validate(); err != nil {
		t.Errorf("the manifest we produced does not validate: %v", err)
	}
}

// DP-002: identity is a function of content and format version alone. The
// same tree packaged repeatedly must have the same digest every time.
func TestPackageIsDeterministic(t *testing.T) {
	t.Parallel()

	first, firstLayer := packageFixture(t)

	for range 8 {
		next, nextLayer := packageFixture(t)

		if next.ManifestDigest != first.ManifestDigest {
			t.Fatalf("subject digest differs between runs: %s then %s",
				first.ManifestDigest, next.ManifestDigest)
		}
		if next.TreeDigest != first.TreeDigest {
			t.Fatalf("tree digest differs between runs")
		}
		if !bytes.Equal(nextLayer, firstLayer) {
			t.Fatalf("layer bytes differ between runs")
		}
	}
}

// Source ordering is not an input to identity (DP-011). The composer sorts,
// but the packager must not depend on having been handed sorted input by
// accident — it must reject what it cannot encode deterministically.
func TestPackageRejectsUnsortedRecords(t *testing.T) {
	t.Parallel()

	records, src := fixture(t)
	slices.Reverse(records)

	_, err := Package(t.Context(), records, src, io.Discard)
	if err == nil {
		t.Fatal("unsorted records were packaged")
	}
	if !stderrors.Is(err, fault.CodeInternal) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInternal)
	}
}

func TestPackageRejectsCollidingPaths(t *testing.T) {
	t.Parallel()

	src := memorySource{"a": "x", "a/b": "y"}
	records := []FileRecord{
		{Path: "a", Mode: bundle.ModeFile, Size: 1, Digest: DigestOf([]byte("x"))},
		{Path: "a/b", Mode: bundle.ModeFile, Size: 1, Digest: DigestOf([]byte("y"))},
	}

	_, err := Package(t.Context(), records, src, io.Discard)
	if !stderrors.Is(err, fault.CodePathCollision) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodePathCollision)
	}
}

// Content that changed after it was inventoried must fail the build rather
// than produce a layer that disagrees with its own config.
func TestPackageRejectsContentThatChangedSinceInventory(t *testing.T) {
	t.Parallel()

	records := []FileRecord{
		{Path: "a.txt", Mode: bundle.ModeFile, Size: 5, Digest: DigestOf([]byte("hello"))},
	}
	src := memorySource{"a.txt": "world"}

	_, err := Package(t.Context(), records, src, io.Discard)
	if !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
	}
}

func TestPackageHonorsCancellation(t *testing.T) {
	t.Parallel()

	records, src := fixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := Package(ctx, records, src, io.Discard)
	if !stderrors.Is(err, fault.CodeCanceled) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeCanceled)
	}
}

// VerifySubject is the read side of Package. What Package produced must be
// exactly what VerifySubject accepts, and it must recover the same identity.
func TestVerifySubjectAcceptsWhatPackageProduced(t *testing.T) {
	t.Parallel()

	subject, layer := packageFixture(t)

	verified, err := VerifySubject(
		subject.ManifestBytes, subject.ConfigBytes, int64(len(layer)), DigestOf(layer))
	if err != nil {
		t.Fatalf("VerifySubject rejected our own output: %v", err)
	}

	if verified.ManifestDigest != subject.ManifestDigest {
		t.Error("verification recovered a different subject digest")
	}
	if verified.TreeDigest != subject.TreeDigest {
		t.Error("verification recovered a different tree digest")
	}
	if verified.Config.FileCount != subject.Config.FileCount {
		t.Error("verification recovered a different file count")
	}
}

func TestVerifySubjectRejectsTampering(t *testing.T) {
	t.Parallel()

	subject, layer := packageFixture(t)

	t.Run("altered config blob", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Replace(subject.ConfigBytes, []byte(`"fileCount":7`), []byte(`"fileCount":6`), 1)
		if bytes.Equal(tampered, subject.ConfigBytes) {
			t.Skip("fixture shape changed; the substitution did not apply")
		}
		_, err := VerifySubject(subject.ManifestBytes, tampered, int64(len(layer)), DigestOf(layer))
		if !stderrors.Is(err, fault.CodeDigestMismatch) {
			t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
		}
	})

	t.Run("substituted layer", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySubject(
			subject.ManifestBytes, subject.ConfigBytes, int64(len(layer)), DigestOf([]byte("other")))
		if !stderrors.Is(err, fault.CodeDigestMismatch) {
			t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
		}
	})

	t.Run("layer size disagrees", func(t *testing.T) {
		t.Parallel()
		_, err := VerifySubject(
			subject.ManifestBytes, subject.ConfigBytes, int64(len(layer))+1, DigestOf(layer))
		if !stderrors.Is(err, fault.CodeDigestMismatch) {
			t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
		}
	})

	t.Run("manifest with an unknown field", func(t *testing.T) {
		t.Parallel()
		tampered := bytes.Replace(subject.ManifestBytes,
			[]byte(`{"artifactType"`), []byte(`{"annotations":{"a":"b"},"artifactType"`), 1)
		if bytes.Equal(tampered, subject.ManifestBytes) {
			t.Skip("fixture shape changed; the substitution did not apply")
		}
		if _, err := VerifySubject(tampered, subject.ConfigBytes, int64(len(layer)), DigestOf(layer)); err == nil {
			t.Error("a manifest carrying annotations was accepted")
		}
	})
}

// A config whose stated tree digest does not match its own inventory is
// tampered with; the two are computed from the same data.
func TestVerifyConfigTreeDigestDetectsSubstitution(t *testing.T) {
	t.Parallel()

	records, _ := fixture(t)
	cfg, err := BuildConfig(records)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	cfg.TreeDigest = DigestOf([]byte("not the real tree")).String()

	if _, err := VerifyConfigTreeDigest(cfg); !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
	}
}

func TestBuildConfigRoundTripsThroughRecords(t *testing.T) {
	t.Parallel()

	records, _ := fixture(t)

	cfg, err := BuildConfig(records)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	back, err := ConfigRecords(cfg)
	if err != nil {
		t.Fatalf("ConfigRecords: %v", err)
	}

	if !slices.Equal(records, back) {
		t.Error("records did not survive a round trip through the config")
	}
}

func TestGoldenConfig(t *testing.T) {
	t.Parallel()

	subject, _ := packageFixture(t)
	golden.Assert(t, "testdata/format/v1/config.json", subject.ConfigBytes)
}

func TestGoldenManifest(t *testing.T) {
	t.Parallel()

	subject, _ := packageFixture(t)
	golden.Assert(t, "testdata/format/v1/manifest.json", subject.ManifestBytes)
}

// The subject digest is the bundle's identity. It gets its own fixture so a
// change to it is impossible to overlook in a diff.
func TestGoldenSubjectDigest(t *testing.T) {
	t.Parallel()

	subject, _ := packageFixture(t)
	golden.AssertString(t, "testdata/format/v1/subject-digest.txt", subject.ManifestDigest.String()+"\n")
}
