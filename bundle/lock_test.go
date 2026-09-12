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

package bundle

import (
	"encoding/json"
	stderrors "errors"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

func validLock() *Lock {
	return NewLock(
		digestOf("manifest"),
		FormatV1,
		[]LockedSource{{
			Name:       "application",
			Type:       SourceTypePath,
			Resolver:   "devproof.thingz.io/path/v1",
			Requested:  map[string]any{"path": "./application"},
			Resolved:   map[string]any{"treeDigest": digestOf("app tree")},
			TreeDigest: digestOf("app tree"),
			MountPath:  "app",
		}},
		[]LockedFile{{
			Path:       "app/config.yaml",
			Source:     "application",
			SourcePath: "config.yaml",
			Mode:       ModeFile,
			Size:       5,
			Digest:     digestOf("a: 1\n"),
		}},
		digestOf("final tree"),
	)
}

func TestLockRoundTripsThroughJSON(t *testing.T) {
	t.Parallel()

	lock := validLock()
	if err := lock.Validate(); err != nil {
		t.Fatalf("a freshly built lock does not validate: %v", err)
	}

	encoded, err := marshalLock(lock)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	parsed, err := ParseLock(encoded)
	if err != nil {
		t.Fatalf("ParseLock: %v", err)
	}
	if parsed.TreeDigest != lock.TreeDigest || len(parsed.Files) != len(lock.Files) {
		t.Error("the lock did not survive a round trip")
	}
}

// NewLock canonicalizes, so the order sources finished resolving in — which
// is concurrency-dependent — cannot reach the lock digest (DP-012).
func TestNewLockCanonicalizesOrder(t *testing.T) {
	t.Parallel()

	sources := []LockedSource{
		{Name: "zebra", Type: SourceTypePath, Resolver: "r", TreeDigest: digestOf("z"),
			Include: []string{"b/**", "a/**"}},
		{Name: "alpha", Type: SourceTypePath, Resolver: "r", TreeDigest: digestOf("a")},
	}
	files := []LockedFile{
		{Path: "z.yaml", Source: "zebra", Mode: ModeFile, Digest: digestOf("z")},
		{Path: "a.yaml", Source: "alpha", Mode: ModeFile, Digest: digestOf("a")},
	}

	lock := NewLock(digestOf("m"), FormatV1, sources, files, digestOf("t"))

	if lock.Sources[0].Name != "alpha" {
		t.Error("sources were not sorted by name")
	}
	if lock.Files[0].Path != "a.yaml" {
		t.Error("files were not sorted by path")
	}
	include := lock.Sources[1].Include
	if len(include) != 2 || include[0] != "a/**" {
		t.Errorf("include = %v, want sorted", include)
	}
	if err := lock.Validate(); err != nil {
		t.Errorf("a canonicalized lock does not validate: %v", err)
	}
}

func TestLockValidateRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Lock)
		code   fault.Code
	}{
		{"unknown apiVersion", func(l *Lock) { l.APIVersion = "v2" }, fault.CodeUnsupportedVersion},
		{"wrong kind", func(l *Lock) { l.Kind = "Bundle" }, fault.CodeInvalidInput},
		{"unsupported format", func(l *Lock) { l.Format = "devproof-bundle-v2" }, fault.CodeUnsupportedVersion},
		{"invalid manifest digest", func(l *Lock) { l.ManifestDigest = "nope" }, fault.CodeInvalidInput},
		{"invalid tree digest", func(l *Lock) { l.TreeDigest = "nope" }, fault.CodeInvalidInput},
		{"no sources", func(l *Lock) { l.Sources = nil }, fault.CodeInvalidInput},
		{"source with no resolver", func(l *Lock) { l.Sources[0].Resolver = "" }, fault.CodeInvalidInput},
		{"invalid source name", func(l *Lock) { l.Sources[0].Name = "Bad Name" }, fault.CodeInvalidInput},
		{"invalid source tree digest", func(l *Lock) { l.Sources[0].TreeDigest = "nope" }, fault.CodeInvalidInput},
		{
			// A file assigned to a source the lock does not record has no
			// owner, which is the invariant DP-011 exists to keep.
			"file owned by an unknown source",
			func(l *Lock) { l.Files[0].Source = "ghost" },
			fault.CodeInvalidInput,
		},
		{"file with no path", func(l *Lock) { l.Files[0].Path = "" }, fault.CodeInvalidInput},
		{"unnormalized mode", func(l *Lock) { l.Files[0].Mode = 0o600 }, fault.CodeInvalidInput},
		{"negative size", func(l *Lock) { l.Files[0].Size = -1 }, fault.CodeInvalidInput},
		{"invalid file digest", func(l *Lock) { l.Files[0].Digest = "nope" }, fault.CodeInvalidInput},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lock := validLock()
			tc.mutate(lock)

			err := lock.Validate()
			if err == nil {
				t.Fatal("an invalid lock validated")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q (%v)", fault.CodeOf(err), tc.code, err)
			}
		})
	}
}

// A duplicate or unsorted file list would let two entries claim one
// destination, or let a reader that sorts disagree with one that does not.
func TestLockValidateRejectsDuplicateAndUnsortedFiles(t *testing.T) {
	t.Parallel()

	duplicate := validLock()
	duplicate.Files = append(duplicate.Files, duplicate.Files[0])
	if err := duplicate.Validate(); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("duplicate: code = %q", fault.CodeOf(err))
	}

	unsorted := validLock()
	unsorted.Files = []LockedFile{
		{Path: "z.yaml", Source: "application", Mode: ModeFile, Digest: digestOf("z")},
		{Path: "a.yaml", Source: "application", Mode: ModeFile, Digest: digestOf("a")},
	}
	if err := unsorted.Validate(); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("unsorted: code = %q", fault.CodeOf(err))
	}
}

func TestLockValidateRejectsDuplicateSources(t *testing.T) {
	t.Parallel()

	lock := validLock()
	lock.Sources = append(lock.Sources, lock.Sources[0])

	if err := lock.Validate(); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
	}
}

func TestParseLockRejects(t *testing.T) {
	t.Parallel()

	encoded, err := marshalLock(validLock())
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"malformed", []byte("{")},
		{"trailing data", append(append([]byte{}, encoded...), []byte(" {}")...)},
		{
			// A lock is generated; a field this build does not understand
			// means it was produced by something else.
			"unknown field",
			[]byte(`{"apiVersion":"devproof.thingz.io/v1alpha1","kind":"BundleLock","surprise":1}`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseLock(tc.data); !stderrors.Is(err, fault.CodeInvalidInput) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
			}
		})
	}
}

func TestLockSourceByName(t *testing.T) {
	t.Parallel()

	lock := validLock()
	if _, ok := lock.SourceByName("application"); !ok {
		t.Error("a recorded source was not found")
	}
	if _, ok := lock.SourceByName("absent"); ok {
		t.Error("an unrecorded source was found")
	}
}

// marshalLock encodes a lock with the standard library. The canonical
// encoder lives in internal/canonical, which cannot be imported here without
// a cycle; these tests exercise the document rules, not the byte format.
func marshalLock(lock *Lock) ([]byte, error) { return json.Marshal(lock) }
