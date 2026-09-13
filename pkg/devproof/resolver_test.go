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
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/source"
)

// stubResolver is a registered resolver whose snapshot can be told to
// misreport itself.
type stubResolver struct {
	sourceType string
	identity   source.Identity
	material   source.Material
}

func (r *stubResolver) Type() string              { return r.sourceType }
func (r *stubResolver) Identity() source.Identity { return r.identity }

func (r *stubResolver) Resolve(context.Context, source.ResolveRequest) (source.Snapshot, error) {
	content := []byte("value\n")
	records := []bundle.FileRecord{{
		Path:   bundle.Path("app.yaml"),
		Mode:   bundle.ModeFile,
		Size:   int64(len(content)),
		Digest: bundle.DigestOf(content),
	}}

	material := r.material
	material.Requested = map[string]any{"stub": true}
	material.Resolved = map[string]any{"stub": true}
	// An unset digest means "report the truth"; a test that wants to lie sets
	// one explicitly.
	if material.TreeDigest == (bundle.Digest{}) {
		digest, err := canonical.TreeDigest(records)
		if err != nil {
			return nil, err
		}
		material.TreeDigest = digest
	}
	return &stubSnapshot{content: content, records: records, material: material}, nil
}

type stubSnapshot struct {
	content  []byte
	records  []bundle.FileRecord
	material source.Material
}

func (s *stubSnapshot) Material() source.Material    { return s.material }
func (s *stubSnapshot) Records() []bundle.FileRecord { return s.records }
func (s *stubSnapshot) Close() error                 { return nil }

func (s *stubSnapshot) Open(context.Context, bundle.Path) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

// stubSpec builds a one-source manifest naming the stub resolver.
func stubSpec(sourceType string) *bundle.Spec {
	return &bundle.Spec{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindBundle,
		Metadata:   bundle.SpecMetadata{Name: "stub"},
		Spec: bundle.SpecBody{Sources: []bundle.SourceSpec{{
			Name: "content", Type: sourceType, Config: map[string]any{},
		}}},
	}
}

func buildWithStub(t *testing.T, stub *stubResolver) error {
	t.Helper()

	client := newClient(t, devproof.WithResolver(stub))
	_, err := client.Build(t.Context(), devproof.BuildRequest{
		Spec:        stubSpec(stub.sourceType),
		SpecDir:     t.TempDir(),
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		SkipLock:    true,
	})
	return err
}

// TestSnapshotCannotMisreportItsResolver closes a gap where the core took a
// snapshot's word for what produced it.
//
// The registry knows which resolver it invoked, because it looked one up by
// the manifest's source type. It then recorded the type and resolver name the
// returned snapshot claimed instead, and never called Identity() at all -- so
// a resolver could attribute its output to another one, in the lock and in
// signed provenance, and nothing compared the two.
func TestSnapshotCannotMisreportItsResolver(t *testing.T) {
	t.Parallel()

	const sourceType = "example.com/stub"
	identity := source.Identity{Name: "example.com/stub/v1", Version: "1"}

	for _, tc := range []struct {
		name     string
		material source.Material
	}{
		{"a different source type", source.Material{
			Type: "git", Resolver: identity,
		}},
		{"a different resolver name", source.Material{
			Type: sourceType, Resolver: source.Identity{Name: "devproof.thingz.io/git/v1", Version: "1"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := buildWithStub(t, &stubResolver{
				sourceType: sourceType, identity: identity, material: tc.material,
			})
			if err == nil {
				t.Error("a snapshot attributed its output to something else and was believed")
			}
		})
	}
}

// TestSnapshotCannotMisreportItsTreeDigest covers the other self-report.
//
// The contribution digest went straight into the lock and into provenance
// without being derived from the records the snapshot returned, so the one
// value that identifies what a source actually contributed was whatever the
// source said it was.
func TestSnapshotCannotMisreportItsTreeDigest(t *testing.T) {
	t.Parallel()

	const sourceType = "example.com/stub"
	identity := source.Identity{Name: "example.com/stub/v1", Version: "1"}

	err := buildWithStub(t, &stubResolver{
		sourceType: sourceType,
		identity:   identity,
		material: source.Material{
			Type: sourceType, Resolver: identity,
			// Not the digest of the records it returns.
			TreeDigest: bundle.DigestOf([]byte("something else")),
		},
	})
	if err == nil {
		t.Error("a snapshot reported a contribution digest that did not match its records")
	}
}

// TestConsistentResolverIsAccepted guards the ordinary path.
func TestConsistentResolverIsAccepted(t *testing.T) {
	t.Parallel()

	const sourceType = "example.com/stub"
	identity := source.Identity{Name: "example.com/stub/v1", Version: "1"}

	if err := buildWithStub(t, &stubResolver{
		sourceType: sourceType,
		identity:   identity,
		material:   source.Material{Type: sourceType, Resolver: identity},
	}); err != nil {
		t.Errorf("a consistent resolver was rejected: %v", err)
	}
}
