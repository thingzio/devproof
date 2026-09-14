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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/evidence"
)

// TestASecondVerifierIsRefused covers a silent replacement.
//
// WithVerifier and WithSigstore each install one verifier, so applying both
// left whichever ran last and discarded the other. An application that
// configured a Sigstore trusted root and then registered a key verifier got
// the keys alone, and nothing reported that the trusted root was no longer in
// use. Replacing what a client will believe is not something to do quietly.
func TestASecondVerifierIsRefused(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	verifier, err := evidence.NewKeyVerifier(key.Public())
	if err != nil {
		t.Fatalf("NewKeyVerifier: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts []devproof.Option
	}{
		{"sigstore then key", []devproof.Option{
			devproof.WithSigstore(evidence.SigstoreOptions{}),
			devproof.WithVerifier(verifier),
		}},
		{"key then sigstore", []devproof.Option{
			devproof.WithVerifier(verifier),
			devproof.WithSigstore(evidence.SigstoreOptions{}),
		}},
		{"two key verifiers", []devproof.Option{
			devproof.WithVerifier(verifier),
			devproof.WithVerifier(verifier),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, err := devproof.New(tc.opts...)
			if err == nil {
				_ = client.Close()
				t.Fatal("a second verifier silently replaced the first")
			}
			if !strings.Contains(err.Error(), "verifier") {
				t.Errorf("the error does not name the conflict: %v", err)
			}
		})
	}
}

// TestOneVerifierIsAccepted keeps the guard from rejecting the ordinary case.
func TestOneVerifierIsAccepted(t *testing.T) {
	t.Parallel()

	client, err := devproof.New(devproof.WithSigstore(evidence.SigstoreOptions{}))
	if err != nil {
		t.Fatalf("a single verifier was rejected: %v", err)
	}
	_ = client.Close()
}
