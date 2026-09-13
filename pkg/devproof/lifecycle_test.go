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
	"path/filepath"
	"sync"
	"testing"

	"github.com/thingzio/devproof/pkg/devproof"
)

// TestCloseIsIdempotent covers a method callers put in a defer.
//
// Close walked every registered transport and closed it, with nothing
// recording that it had already run, so the ordinary `defer client.Close()`
// beside an explicit one closed each transport twice.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	client, err := devproof.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestConcurrentUseDoesNotRace backs the claim on the Client type.
//
// The doc comment says a Client is safe for concurrent use after
// construction, and the closed flag was an ordinary bool written by Close and
// read by every operation. Under the race detector that is a data race, which
// makes the documented guarantee false for exactly the program that relies on
// it.
//
// Run with -race, which the suite does.
func TestConcurrentUseDoesNotRace(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	source := defaultSource(t)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			layout := filepath.Join(t.TempDir(), "layout")
			// Errors are not the point; concurrent access is. An operation
			// that loses a race with another is still a correct outcome.
			_, _ = client.Build(t.Context(), devproof.BuildRequest{
				SourcePath:  source,
				Destination: "oci-layout://" + layout,
				Tag:         "v1",
			})
			_, _ = client.Inspect(t.Context(), devproof.InspectRequest{
				Reference: "oci-layout://" + layout + ":v1",
			})
			_ = i
		}()
	}
	wg.Wait()
}

// TestCloseRacingAnOperationIsNotADataRace is the case the flag was exposed
// to.
//
// Whether an operation started before Close wins is the caller's problem and
// either outcome is correct. What must not happen is a data race on the
// client's own state, because the type documents itself as safe for
// concurrent use and a race makes that false for precisely the program that
// believed it.
func TestCloseRacingAnOperationIsNotADataRace(t *testing.T) {
	t.Parallel()

	client, err := devproof.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	source := defaultSource(t)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = client.Build(t.Context(), devproof.BuildRequest{
			SourcePath:  source,
			Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		})
	}()
	go func() {
		defer wg.Done()
		_ = client.Close()
	}()
	wg.Wait()
}
