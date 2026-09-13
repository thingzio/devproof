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

package devproof_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/policy"
)

// layoutFixture builds a bundle into a fresh local layout.
func layoutFixture(t *testing.T, client *devproof.Client) (layout, reference string) {
	t.Helper()

	dir := writeSource(t, map[string]string{
		"config.yaml":     "key: value\n",
		"nested/data.txt": "payload bytes\n",
	})
	layout = filepath.Join(t.TempDir(), "layout")
	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  dir,
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	}); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	return layout, "oci-layout://" + layout + ":v1"
}

// layerBlob returns the path of the payload layer blob inside a layout.
func layerBlob(t *testing.T, layout string) string {
	t.Helper()

	read := func(rel string) []byte {
		data, err := os.ReadFile(filepath.Join(layout, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		return data
	}

	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(read("index.json"), &index); err != nil {
		t.Fatalf("decoding index: %v", err)
	}
	if len(index.Manifests) == 0 {
		t.Fatal("layout index names no manifests")
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	manifestPath := filepath.Join("blobs", "sha256",
		strings.TrimPrefix(index.Manifests[0].Digest, "sha256:"))
	if err := json.Unmarshal(read(manifestPath), &manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if len(manifest.Layers) != 1 {
		t.Fatalf("manifest has %d layers, want 1", len(manifest.Layers))
	}

	return filepath.Join(layout, "blobs", "sha256",
		strings.TrimPrefix(manifest.Layers[0].Digest, "sha256:"))
}

// TestVerifyRejectsAnAbsentLayer is the plainest statement of what integrity
// has to mean.
//
// The README says integrity answers "are these the bytes the artifact
// claims?" and needs nothing but the artifact. A subject whose entire payload
// is missing cannot satisfy that, and reporting pass for one makes every other
// pass meaningless.
func TestVerifyRejectsAnAbsentLayer(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layout, reference := layoutFixture(t, client)

	if err := os.Remove(layerBlob(t, layout)); err != nil {
		t.Fatalf("removing layer: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{Reference: reference})
	if err == nil {
		t.Fatalf("verifying a subject with no payload succeeded: integrity=%s",
			report.Integrity)
	}
	if report != nil && report.Integrity == policy.StatusPass {
		t.Errorf("integrity reported pass with no payload present")
	}
}

// TestVerifyRejectsACorruptedLayer covers the demo case: flip one byte in a
// registry blob and verification must notice.
func TestVerifyRejectsACorruptedLayer(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layout, reference := layoutFixture(t, client)

	blob := layerBlob(t, layout)
	data, err := os.ReadFile(blob)
	if err != nil {
		t.Fatalf("reading layer: %v", err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(blob, data, 0o644); err != nil {
		t.Fatalf("writing layer: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{Reference: reference})
	if err == nil {
		t.Fatalf("verifying a corrupted payload succeeded: integrity=%s", report.Integrity)
	}
	if code := codeOf(err); code != devproof.CodeDigestMismatch && code != devproof.CodeInvalidArtifact {
		t.Errorf("code = %q, want digest-mismatch or invalid-artifact", code)
	}
}

// reEncodeLayer rewrites a layer blob with the same logical files in a
// different encoding, leaving it stored under its original digest name.
//
// This is the case a content check alone cannot catch. Every file is present
// with the right bytes, so entry-by-entry validation against the inventory
// passes; only hashing the compressed stream against the layer descriptor
// reveals that these are not the bytes the subject names.
func reEncodeLayer(t *testing.T, blob string) {
	t.Helper()

	original, err := os.Open(blob)
	if err != nil {
		t.Fatalf("opening layer: %v", err)
	}
	defer func() { _ = original.Close() }()

	zr, err := gzip.NewReader(original)
	if err != nil {
		t.Fatalf("reading layer gzip: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompressing layer: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("closing gzip reader: %v", err)
	}

	// Same tar stream, different compression level, so the archive's contents
	// are untouched and only the compressed bytes differ.
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("creating gzip writer: %v", err)
	}
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("recompressing: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	if bytes.Equal(out.Bytes(), plain) {
		t.Fatal("re-encoding produced identical bytes; the fixture proves nothing")
	}
	if err := os.WriteFile(blob, out.Bytes(), 0o644); err != nil {
		t.Fatalf("writing re-encoded layer: %v", err)
	}

	// Confirm the replacement really is a readable archive holding the same
	// entries, so a failure below is about identity rather than corruption.
	tr := tar.NewReader(mustGunzip(t, out.Bytes()))
	for {
		if _, err := tr.Next(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("re-encoded layer is not a readable tar: %v", err)
		}
	}
}

func mustGunzip(t *testing.T, data []byte) io.Reader {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("re-encoded layer is not valid gzip: %v", err)
	}
	return zr
}

// TestVerifyRejectsAReEncodedLayer is the test that distinguishes hashing the
// layer from merely reading it successfully.
func TestVerifyRejectsAReEncodedLayer(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layout, reference := layoutFixture(t, client)
	reEncodeLayer(t, layerBlob(t, layout))

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{Reference: reference})
	if err == nil {
		t.Fatalf("verifying a re-encoded payload succeeded: integrity=%s", report.Integrity)
	}
}

// TestExpandRejectsAReEncodedLayer applies the same case to the write path.
//
// Expansion validates each decoded entry against the inventory, which a
// re-encoded layer satisfies. Without a check on the compressed bytes it
// therefore writes a payload that is not the one the subject names.
func TestExpandRejectsAReEncodedLayer(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layout, reference := layoutFixture(t, client)
	reEncodeLayer(t, layerBlob(t, layout))

	destination := filepath.Join(t.TempDir(), "out")
	if _, err := client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   reference,
		Destination: destination,
	}); err == nil {
		t.Fatal("expanding a re-encoded payload succeeded")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Error("a failed expansion left a destination behind")
	}
}

// TestVerifyAcceptsAnIntactLayer guards against the fix being a blanket
// rejection.
func TestVerifyAcceptsAnIntactLayer(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	_, reference := layoutFixture(t, client)

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{Reference: reference})
	if err != nil {
		t.Fatalf("verifying an intact subject failed: %v", err)
	}
	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %s, want pass", report.Integrity)
	}
}

// TestPolicyGatedExpandReportsWhatItEvaluated covers the other half of a
// gated expansion.
//
// Refusing to write when a policy fails and telling the truth about a policy
// that passed are separate obligations. The gate was closed correctly while
// the successful result reported trust as not-evaluated, having discarded the
// evaluation: a caller that logged or stored that result recorded that
// nothing had been checked, for an artifact that had just been checked.
func TestPolicyGatedExpandReportsWhatItEvaluated(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layout := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layout)

	doc := policyDoc("gate", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
	})

	destination := filepath.Join(t.TempDir(), "out")
	result, err := client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   built.Reference,
		Destination: destination,
		Policy:      doc,
	})
	if err != nil {
		t.Fatalf("gated expand: %v", err)
	}

	report := result.Verification
	if report == nil {
		t.Fatal("a gated expansion returned no verification report")
	}
	if report.Trust != policy.StatusPass {
		t.Errorf("trust = %s, want pass: the policy was evaluated and satisfied",
			report.Trust)
	}
	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %s, want pass", report.Integrity)
	}
	if report.PolicyDigest == "" {
		t.Error("the report does not identify the policy that was applied")
	}
	if len(report.AcceptedIdentities) == 0 {
		t.Error("the report names no accepted identity for a threshold that was met")
	}
	if report.SubjectDigest != built.SubjectDigest {
		t.Errorf("report names subject %s, expansion was of %s",
			report.SubjectDigest, built.SubjectDigest)
	}
}

// TestFailedPolicyStillWritesNothing guards the behavior that was already
// correct, so fixing the report above cannot regress the gate (DP-032).
func TestFailedPolicyStillWritesNothing(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)
	layout := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layout)

	doc := policyDoc("gate", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{
			{KeyID: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		}
	})

	destination := filepath.Join(t.TempDir(), "out")
	if _, err := client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   built.Reference,
		Destination: destination,
		Policy:      doc,
	}); err == nil {
		t.Fatal("expansion succeeded under a policy nothing could satisfy")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Error("a refused expansion left a destination behind")
	}
}
