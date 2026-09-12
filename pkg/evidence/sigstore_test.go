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

package evidence

import (
	"context"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/fault"
)

// These tests cover the part of keyless verification this project owns:
// deciding whether a stored blob is a Sigstore bundle at all, and classifying
// it when it is not.
//
// The cryptographic path — certificate chains, transparency-log inclusion,
// identity extraction — belongs to sigstore-go and needs a live Fulcio, a live
// Rekor, and an OIDC token. Reproducing it here would mean hand-assembling
// protobuf bundles that mirror sigstore-go's internals, which breaks whenever
// that shape changes and proves nothing about our code. It is covered by the
// post-merge keyless job instead, which does the real thing once.
//
// What is worth testing here is classification. A repository is an open
// attachment surface: anyone with write access can attach anything to a
// subject. Whether junk reads as "this evidence is invalid" or "DevProof has a
// bug" decides whether an operator investigates their supply chain or files an
// issue against us.

func TestSigstoreVerifyRequiresABundle(t *testing.T) {
	t.Parallel()

	verifier := NewSigstoreVerifier(SigstoreOptions{})
	_, err := verifier.Verify(context.Background(), VerifyRequest{
		Envelope: &Envelope{PayloadType: "application/vnd.in-toto+json"},
		Payload:  []byte("{}"),
	})

	if err == nil {
		t.Fatal("evidence with no bundle verified")
	}
	// Distinct from "failed verification": there was nothing to verify, and
	// the message has to say which.
	if !strings.Contains(err.Error(), "no Sigstore bundle") {
		t.Errorf("the error does not explain the absence: %v", err)
	}
	if code := fault.CodeOf(err); code != fault.CodeEvidenceInvalid {
		t.Errorf("code = %q, want %q", code, fault.CodeEvidenceInvalid)
	}
}

func TestSigstoreVerifyRequiresAnEnvelope(t *testing.T) {
	t.Parallel()

	verifier := NewSigstoreVerifier(SigstoreOptions{})
	_, err := verifier.Verify(context.Background(), VerifyRequest{
		BundleJSON: []byte(`{}`),
	})

	if err == nil {
		t.Fatal("a request with no envelope verified")
	}
	// No envelope is a programming error in the caller, not bad evidence
	// somebody attached, and the codes have to separate those.
	if code := fault.CodeOf(err); code != fault.CodeInternal {
		t.Errorf("code = %q, want %q", code, fault.CodeInternal)
	}
}

// Malformed evidence is the attacker-reachable case: anyone who can write to
// the repository can attach these bytes. Every one must be refused as invalid
// evidence rather than reported as an internal failure.
func TestSigstoreVerifyClassifiesMalformedBundles(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"not JSON at all":       "{{{",
		"truncated JSON":        `{"dsseEnvelope":`,
		"JSON null":             `null`,
		"array, not an object":  `[]`,
		"bare string":           `"bundle"`,
		"number":                `42`,
		"empty":                 ``,
		"unknown proto field":   `{"notARealField": 1}`,
		"wrong types inside":    `{"mediaType": 7}`,
		"deeply nested garbage": `{"a":{"b":{"c":{"d":[[[{}]]]}}}}`,
	}

	verifier := NewSigstoreVerifier(SigstoreOptions{})
	envelope := &Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "e30=",
		Signatures:  []Signature{{Sig: "AA=="}},
	}

	for name, bundleJSON := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := verifier.Verify(context.Background(), VerifyRequest{
				Envelope:   envelope,
				Payload:    []byte("{}"),
				BundleJSON: []byte(bundleJSON),
			})
			if err == nil {
				t.Fatal("malformed bundle verified")
			}
			if code := fault.CodeOf(err); code != fault.CodeEvidenceInvalid {
				t.Errorf("code = %q, want %q; malformed evidence is not our bug",
					code, fault.CodeEvidenceInvalid)
			}
		})
	}
}

// Verification must never report success with no identity. A caller that
// branches on the error alone would treat that as a verified artifact signed
// by nobody, which is the worst possible outcome.
func TestSigstoreVerifyNeverSucceedsWithoutIdentity(t *testing.T) {
	t.Parallel()

	verifier := NewSigstoreVerifier(SigstoreOptions{})
	result, err := verifier.Verify(context.Background(), VerifyRequest{
		Envelope:   &Envelope{PayloadType: "application/vnd.in-toto+json"},
		Payload:    []byte("{}"),
		BundleJSON: []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
	})

	if err == nil && (result == nil || len(result.Identities) == 0) {
		t.Fatal("verification reported success with no verified identity")
	}
}

func TestSigstoreAttesterAndVerifierAgreeOnName(t *testing.T) {
	t.Parallel()

	// A report names the scheme that accepted evidence. If the attester and
	// verifier disagreed, a policy written against one would silently never
	// match what the other produced.
	attester := NewSigstoreAttester(SigstoreOptions{})
	verifier := NewSigstoreVerifier(SigstoreOptions{})
	if attester.Name() != verifier.Name() {
		t.Errorf("attester %q and verifier %q disagree", attester.Name(), verifier.Name())
	}
}
