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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/policy"
)

// TestPolicyLimitsBoundExpansion is DP-021 applied where it matters.
//
// A policy may tighten a bound and never relax one. That was true of evidence
// discovery and of nothing else: limits were resolved before the policy was
// loaded, so the expansion a policy was gating ran under the caller's own
// numbers. A policy could refuse an artifact on its signature and not bound
// how much of it reached the disk.
func TestPolicyLimitsBoundExpansion(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	source := writeSource(t, map[string]string{
		"big.yaml": strings.Repeat("a: 1\n", 200), // 1000 bytes
	})
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	doc := policyDoc("tight", func(d *policy.Document) {
		d.Spec.Limits.MaxExpandedBytes = 100 // an order of magnitude under
	})

	destination := filepath.Join(t.TempDir(), "out")
	_, err = client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   built.Reference,
		Destination: destination,
		Policy:      doc,
	})
	if err == nil {
		t.Fatal("a policy bound of 100 bytes did not stop a 1000-byte expansion")
	}
	if code := codeOf(err); code != devproof.CodeLimitExceeded {
		t.Errorf("code = %q, want limit-exceeded", code)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Error("a refused expansion left a destination behind")
	}
}

// TestPolicyLimitsBoundVerification applies the same rule to the read path.
func TestPolicyLimitsBoundVerification(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	source := writeSource(t, map[string]string{
		"big.yaml": strings.Repeat("a: 1\n", 200),
	})
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	doc := policyDoc("tight", func(d *policy.Document) {
		d.Spec.Limits.MaxExpandedBytes = 100
	})

	if _, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: built.Reference,
		Policy:    doc,
	}); err == nil {
		t.Error("a policy bound did not apply to verification")
	}
}

// TestReportRecordsEffectiveLimits covers the second half of DP-021: the
// result records which input supplied each effective value.
//
// It recorded none of them. "The policy asked for a bound" and "the bound the
// policy asked for is the one that applied" were indistinguishable in the
// output, which is the difference the origin exists to express.
func TestReportRecordsEffectiveLimits(t *testing.T) {
	t.Parallel()

	client := newClient(t, devproof.WithLimits(devproof.Limits{
		MaxFiles: 500, // tightened by the client
	}))
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	doc := policyDoc("recorded", func(d *policy.Document) {
		d.Spec.Limits.MaxPathDepth = 8 // tightened by the policy
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: built.Reference,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	byName := make(map[string]policy.Limit, len(report.Limits))
	for _, limit := range report.Limits {
		byName[limit.Name] = limit
	}
	if len(byName) != len(bundle.Resolved{}.Each()) {
		t.Errorf("report carries %d limits, the code defines %d",
			len(byName), len(bundle.Resolved{}.Each()))
	}

	for _, want := range []struct {
		name   string
		value  int64
		origin string
	}{
		{"maxFiles", 500, string(bundle.OriginClient)},
		{"maxPathDepth", 8, string(bundle.OriginPolicy)},
		// Untouched by anybody, so it must still be reported, as a default.
		{"maxReferrers", 256, string(bundle.OriginDefault)},
	} {
		got, ok := byName[want.name]
		if !ok {
			t.Errorf("%s is missing from the report", want.name)
			continue
		}
		if got.Value != want.value {
			t.Errorf("%s = %d, want %d", want.name, got.Value, want.value)
		}
		if got.Origin != want.origin {
			t.Errorf("%s came from %q, want %q", want.name, got.Origin, want.origin)
		}
	}
}

// TestManifestAndLockReadsAreBounded covers limits that were declared and
// never applied.
//
// maxSpecBytes and maxLockBytes appeared in the documented limit table, in the
// policy schema, and in the type, while both documents were read with an
// unbounded os.ReadFile. These are local files a caller chose, so this is a
// bound rather than a defense -- but a limit that is documented and absent is
// worse than one never offered, because somebody will rely on it.
func TestManifestAndLockReadsAreBounded(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	dir := t.TempDir()
	content := filepath.Join(dir, "content")
	if err := os.MkdirAll(content, 0o755); err != nil {
		t.Fatalf("creating source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(content, "a.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	manifest := filepath.Join(dir, "devproof.yaml")
	rendered, err := bundle.Template("./content")
	if err != nil {
		t.Fatalf("rendering a manifest: %v", err)
	}
	if err := os.WriteFile(manifest, rendered, 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	_, err = client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    manifest,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		SkipLock:    true,
		Limits:      devproof.Limits{MaxSpecBytes: 32},
	})
	if err == nil {
		t.Fatal("a manifest larger than maxSpecBytes was read anyway")
	}
	if code := codeOf(err); code != devproof.CodeLimitExceeded {
		t.Errorf("code = %q, want limit-exceeded", code)
	}
}
