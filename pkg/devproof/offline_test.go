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
	"context"
	stderrors "errors"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/devproof"
)

// trapTransport fails the test if anything reaches it.
//
// Asserting on an error message would only prove that an error was produced.
// What offline has to mean is that nothing was attempted, so the assertion is
// that this transport was never consulted at all -- not resolved, not fetched,
// not even asked for its scheme beyond registration.
type trapTransport struct {
	scheme string
	calls  atomic.Int64
}

func (t *trapTransport) Scheme() string { return t.scheme }

func (t *trapTransport) Resolve(context.Context, artifact.Reference) (artifact.Descriptor, error) {
	t.calls.Add(1)
	return artifact.Descriptor{}, nil
}

// errTrapped is returned rather than a nil error with a nil reader, so a
// caller that ignored the call count still cannot proceed as though this
// transport had produced something.
var errTrapped = stderrors.New("trap transport was called")

func (t *trapTransport) Fetch(
	context.Context, artifact.Reference, artifact.Descriptor,
) (io.ReadCloser, error) {

	t.calls.Add(1)
	return nil, errTrapped
}

func (t *trapTransport) Push(
	context.Context, artifact.Reference, artifact.Descriptor, io.Reader,
) error {

	t.calls.Add(1)
	return errTrapped
}

func (t *trapTransport) Tag(
	context.Context, artifact.Reference, artifact.Descriptor, string,
) error {

	t.calls.Add(1)
	return errTrapped
}

func (t *trapTransport) Close() error { return nil }

// TestOfflineRefusesBeforeTouchingTheTransport is the assertion that makes
// --offline a boundary rather than a preference.
//
// The flag previously only required a trust root to be supplied, and was
// never passed into the SDK or any transport, so a remote reference fetched
// exactly as it would have without it. The situations where offline matters
// -- an air gap, an incident, a machine that must not phone home -- are the
// ones where nobody is watching for an unexpected connection.
func TestOfflineRefusesBeforeTouchingTheTransport(t *testing.T) {
	t.Parallel()

	trap := &trapTransport{scheme: artifact.SchemeRegistry}
	client := newClient(t,
		devproof.WithOffline(),
		devproof.WithTransport(trap),
	)

	// Not subtests: the assertion that matters runs after every operation,
	// and parallel subtests would let it read the counter first.
	operations := []struct {
		name string
		run  func() error
	}{
		{"verify", func() error {
			_, err := client.Verify(t.Context(), devproof.VerifyRequest{
				Reference: "oci://registry.example.com/team/config:v1",
			})
			return err
		}},
		{"expand", func() error {
			_, err := client.Expand(t.Context(), devproof.ExpandRequest{
				Reference:   "oci://registry.example.com/team/config:v1",
				Destination: filepath.Join(t.TempDir(), "out"),
			})
			return err
		}},
		{"inspect", func() error {
			_, err := client.Inspect(t.Context(), devproof.InspectRequest{
				Reference: "oci://registry.example.com/team/config:v1",
			})
			return err
		}},
		{"build", func() error {
			_, err := client.Build(t.Context(), devproof.BuildRequest{
				SourcePath:  defaultSource(t),
				Destination: "oci://registry.example.com/team/config",
			})
			return err
		}},
	}

	for _, operation := range operations {
		if err := operation.run(); err == nil {
			t.Errorf("%s used a network reference while offline", operation.name)
		}
	}

	if calls := trap.calls.Load(); calls != 0 {
		t.Errorf("the network transport was called %d times while offline; "+
			"the refusal happens too late to be a boundary", calls)
	}
}

// TestOfflineAllowsALocalLayout guards against the boundary being a blanket
// refusal.
//
// Offline has to leave the useful case working, or nobody will turn it on:
// verifying an artifact that is already on disk needs no network and must
// keep succeeding.
func TestOfflineAllowsALocalLayout(t *testing.T) {
	t.Parallel()

	// Built by an ordinary client; verified by an offline one, which is the
	// real shape of an air-gapped transfer.
	builder := newClient(t)
	layout := filepath.Join(t.TempDir(), "layout")
	if _, err := builder.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + layout,
		Tag:         "v1",
	}); err != nil {
		t.Fatalf("building: %v", err)
	}

	offline := newClient(t, devproof.WithOffline())
	report, err := offline.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + ":v1",
	})
	if err != nil {
		t.Fatalf("offline verification of a local layout failed: %v", err)
	}
	if !report.OK() {
		t.Errorf("offline verification did not pass: integrity=%s", report.Integrity)
	}

	destination := filepath.Join(t.TempDir(), "out")
	if _, err := offline.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   "oci-layout://" + layout + ":v1",
		Destination: destination,
	}); err != nil {
		t.Errorf("offline expansion of a local layout failed: %v", err)
	}
}

// TestUnknownTransportsAreAssumedToNeedTheNetwork pins the direction of the
// default.
//
// A transport this module did not write cannot be inspected for whether it
// dials, so the assumption has to be the refusing one. Declaring LocalOnly is
// an opt-in promise; silence is not consent.
func TestUnknownTransportsAreAssumedToNeedTheNetwork(t *testing.T) {
	t.Parallel()

	// A transport that does not implement artifact.LocalOnly, registered
	// under a scheme an offline client would otherwise be happy with.
	trap := &trapTransport{scheme: artifact.SchemeLayout}
	if artifact.IsLocalOnly(trap) {
		t.Fatal("a transport that does not implement LocalOnly was treated as local")
	}

	client := newClient(t, devproof.WithOffline(), devproof.WithTransport(trap))
	if _, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + t.TempDir() + ":v1",
	}); err == nil {
		t.Error("an offline client used a transport that never promised to stay local")
	}
	if calls := trap.calls.Load(); calls != 0 {
		t.Errorf("the undeclared transport was called %d times while offline", calls)
	}
}
