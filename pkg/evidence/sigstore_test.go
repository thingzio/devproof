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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// Ambient detection that only reads environment variables finds nothing on
// GitHub Actions, which is the one CI system where keyless signing is most
// expected to work without configuration. These cover the exchange without a
// live Actions runner.
func TestGitHubActionsTokenAbsentIsNotAnError(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	token, err := githubActionsToken(context.Background(), 0)
	if err != nil {
		t.Fatalf("absence reported as an error: %v", err)
	}
	if token != "" {
		t.Errorf("got a token with no request variables set: %q", token)
	}
}

func TestGitHubActionsTokenExchange(t *testing.T) {
	var gotAudience, gotAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience = r.URL.Query().Get("audience")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"the.id.token"}`))
	}))
	defer server.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	// The test server uses a self-signed certificate, so the exchange runs
	// through a client that trusts it.
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()

	token, err := githubActionsToken(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token != "the.id.token" {
		t.Errorf("token = %q", token)
	}
	// Fulcio rejects a token minted for a different audience, so requesting
	// the wrong one fails later and confusingly.
	if gotAudience != "sigstore" {
		t.Errorf("audience = %q, want sigstore", gotAudience)
	}
	if gotAuth != "Bearer request-token" {
		t.Errorf("request token was not presented as a bearer credential: %q", gotAuth)
	}
}

// A refusal must say what to do about it. Missing `id-token: write` is the
// overwhelmingly common cause and is invisible from the error otherwise.
func TestGitHubActionsTokenRefusalIsActionable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied"}`))
	}))
	defer server.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()

	_, err := githubActionsToken(context.Background(), 5*time.Second)
	if err == nil {
		t.Fatal("a refused exchange succeeded")
	}
	if !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("the error does not name the likely cause: %v", err)
	}
	if fault.CodeOf(err) != fault.CodeAuthentication {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeAuthentication)
	}
}

// The request token is a bearer credential scoped to one host. A plaintext URL
// from a modified environment must not put it on the wire.
func TestGitHubActionsTokenRequiresHTTPS(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://127.0.0.1:1/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	if _, err := githubActionsToken(context.Background(), time.Second); err == nil {
		t.Fatal("a plaintext identity-token URL was accepted")
	}
}
