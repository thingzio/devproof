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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/policy"
)

// Keyless signing is the default way to sign and the least testable thing in
// the project: it needs a live Fulcio, a live Rekor, and an OIDC token that
// only a real workload identity can mint. Everything else about evidence is
// covered in-process; this is the part that is only true if it is done for
// real.
//
// Gated on an environment variable rather than a build tag so the file is
// always compiled, vetted, and linted — a test excluded by a tag rots
// silently. It runs in one place: a post-merge job on main with
// `id-token: write`, never on a pull request, so a fork can never reach the
// identity.
//
// No secret is involved. That is the property being tested: the token is
// minted per-job by the OIDC provider, expires in minutes, is scoped to an
// audience, and nothing durable exists to leak. If this test needed a secret,
// keyless signing would not be working.
const keylessEnv = "DEVPROOF_KEYLESS_E2E"

func TestKeylessSignAndVerifyEndToEnd(t *testing.T) {
	if os.Getenv(keylessEnv) != "1" {
		t.Skipf("set %s=1 to run against a live Sigstore with an ambient OIDC identity", keylessEnv)
	}

	identity := os.Getenv("DEVPROOF_KEYLESS_IDENTITY")
	issuer := os.Getenv("DEVPROOF_KEYLESS_ISSUER")
	if identity == "" || issuer == "" {
		t.Fatal("DEVPROOF_KEYLESS_IDENTITY and DEVPROOF_KEYLESS_ISSUER must name the " +
			"workload identity this job expects to sign as; a test that accepted any " +
			"identity would pass even if it signed as something else")
	}

	// Generous: this reaches Fulcio, Rekor, and a TUF root over the network.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "payload.txt"), []byte("keyless\n"), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	layout := "oci-layout://" + filepath.Join(t.TempDir(), "layout")

	signer, err := devproof.New(devproof.WithSigstore(evidence.SigstoreOptions{}))
	if err != nil {
		t.Fatalf("creating a signing client: %v", err)
	}
	defer func() { _ = signer.Close() }()

	built, err := signer.Build(ctx, devproof.BuildRequest{
		SourcePath:  source,
		Destination: layout,
		Tag:         "keyless",
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("keyless build: %v", err)
	}
	if built.Evidence == nil {
		t.Fatal("a signed build produced no evidence")
	}
	t.Logf("signed as %s, evidence %s", built.Evidence.Attester, built.Evidence.Digest)

	// Verify with a policy that names the identity this job runs as. Without
	// the identity rule the test would pass for a signature from anyone, which
	// is the failure mode keyless signing exists to prevent.
	doc := &policy.Document{
		APIVersion: "devproof.thingz.io/v1alpha1",
		Kind:       "VerificationPolicy",
		Metadata:   policy.Metadata{Name: "keyless-e2e"},
		Spec: policy.Spec{
			Signatures: policy.SignatureRules{
				Threshold: 1,
				Identities: []policy.IdentityRule{
					{Issuer: issuer, Subject: identity},
				},
				RequireTransparencyLog: true,
			},
			Provenance: policy.ProvenanceRules{Required: true},
		},
	}

	verifier, err := devproof.New(devproof.WithSigstore(evidence.SigstoreOptions{}))
	if err != nil {
		t.Fatalf("creating a verifying client: %v", err)
	}
	defer func() { _ = verifier.Close() }()

	report, err := verifier.Verify(ctx, devproof.VerifyRequest{
		Reference: built.Reference,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("verifying the keyless signature: %v", err)
	}

	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %s, want pass", report.Integrity)
	}
	if report.Trust != policy.StatusPass {
		t.Errorf("trust = %s, want pass; findings: %v", report.Trust, report.Findings)
	}
	if !report.OK() {
		t.Fatalf("the policy was not satisfied: %v", report.Findings)
	}

	// The identity has to be the one the policy demanded, not merely some
	// identity that happened to verify.
	var matched bool
	for _, accepted := range report.AcceptedIdentities {
		if accepted != "" {
			matched = true
			t.Logf("accepted identity: %s", accepted)
		}
	}
	if !matched {
		t.Error("trust passed but no accepted identity was reported")
	}
}

// A rejecting policy must reject a real signature too. Without this, the test
// above could pass because verification accepts everything rather than because
// the signature is good.
func TestKeylessVerifyRejectsAnotherIdentity(t *testing.T) {
	if os.Getenv(keylessEnv) != "1" {
		t.Skipf("set %s=1 to run against a live Sigstore", keylessEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "payload.txt"), []byte("keyless\n"), 0o644); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	client, err := devproof.New(devproof.WithSigstore(evidence.SigstoreOptions{}))
	if err != nil {
		t.Fatalf("creating a client: %v", err)
	}
	defer func() { _ = client.Close() }()

	built, err := client.Build(ctx, devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("keyless build: %v", err)
	}

	report, err := client.Verify(ctx, devproof.VerifyRequest{
		Reference: built.Reference,
		Policy: &policy.Document{
			APIVersion: "devproof.thingz.io/v1alpha1",
			Kind:       "VerificationPolicy",
			Metadata:   policy.Metadata{Name: "wrong-identity"},
			Spec: policy.Spec{
				Signatures: policy.SignatureRules{
					Threshold: 1,
					Identities: []policy.IdentityRule{{
						Issuer:  "https://token.actions.githubusercontent.com",
						Subject: "https://github.com/someone/else/.github/workflows/nope.yaml@refs/heads/main",
					}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if report.OK() {
		t.Fatal("a policy naming a different identity accepted this signature")
	}
}
