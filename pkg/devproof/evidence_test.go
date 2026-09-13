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
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/policy"
)

// signingClient returns a client that signs with a fresh local key and
// verifies against its public half.
//
// Local keys rather than keyless here: a test that reached Fulcio and Rekor
// would need the network, an OIDC identity, and would write to a public
// transparency log on every run. The keyless path is the same code past the
// attester boundary.
func signingClient(t *testing.T) (*devproof.Client, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	attester, err := evidence.NewKeyAttester(key)
	if err != nil {
		t.Fatalf("NewKeyAttester: %v", err)
	}
	verifier, err := evidence.NewKeyVerifier(key.Public())
	if err != nil {
		t.Fatalf("NewKeyVerifier: %v", err)
	}

	return newClient(t,
		devproof.WithAttester(attester),
		devproof.WithVerifier(verifier),
	), key
}

func keyIDOf(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	id, err := evidence.KeyID(key.Public())
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	return id
}

func policyDoc(name string, mutate func(*policy.Document)) *policy.Document {
	doc := &policy.Document{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindVerificationPolicy,
		Metadata:   policy.Metadata{Name: name},
	}
	if mutate != nil {
		mutate(doc)
	}
	return doc
}

// buildSigned builds with provenance attached and returns the result.
func buildSigned(t *testing.T, client *devproof.Client, layoutPath string) *devproof.BuildResult {
	t.Helper()

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + layoutPath,
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("Build with attestation: %v", err)
	}
	return built
}

// DP-003: evidence is stored beside the subject, never inside it. Attaching
// it must not move the subject digest, or a signature would invalidate the
// thing it signed.
func TestAttachingEvidenceDoesNotChangeTheSubject(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)
	source := defaultSource(t)

	unsigned, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	signed, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "b"),
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("Build with attestation: %v", err)
	}

	if signed.SubjectDigest != unsigned.SubjectDigest {
		t.Errorf("attaching evidence changed the subject digest:\n  unsigned: %s\n  signed:   %s",
			unsigned.SubjectDigest, signed.SubjectDigest)
	}
	if signed.Evidence == nil {
		t.Fatal("no evidence was reported")
	}
	if signed.Evidence.SubjectDigest != signed.SubjectDigest {
		t.Error("the evidence is not bound to the subject that was built")
	}
	if signed.Evidence.PredicateType != evidence.PredicateTypeDevProof {
		t.Errorf("predicate type = %q", signed.Evidence.PredicateType)
	}
}

// Without a policy, trust reports not-evaluated even when evidence exists and
// verifies. Reporting pass would tell a consumer their trust configuration
// took effect when it never ran.
func TestTrustIsNotEvaluatedWithoutAPolicy(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layoutPath)

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusNotEvaluated {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusNotEvaluated)
	}
}

// The whole point: a policy that names the signing key accepts evidence
// signed by it.
func TestPolicyAcceptsMatchingIdentity(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layoutPath)

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
		d.Spec.Provenance.Required = true
		d.Spec.Provenance.RequireLockDigest = true
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusPass {
		t.Errorf("trust = %q, want %q; findings: %v", report.Trust, policy.StatusPass, report.Findings)
	}
	if !report.OK() {
		t.Error("a satisfied policy did not report OK")
	}
	if len(report.AcceptedIdentities) == 0 {
		t.Error("the report does not record who was believed")
	}
	if report.PolicyDigest == "" || report.PolicyName != "release" {
		t.Error("the report does not identify the policy that produced it")
	}
	if report.EvidenceStorage == "" {
		t.Error("the report does not say how evidence was found")
	}
}

// DP-014: a policy requiring evidence fails when there is none. Fail-closed
// is the whole behavior; a missing signature must never read as "fine".
func TestPolicyFailsClosedWithoutEvidence(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	// Built without attestation.
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + layoutPath,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
		d.Spec.Provenance.Required = true
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Integrity still passes: the artifact is intact. Trust does not.
	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %q, want %q", report.Integrity, policy.StatusPass)
	}
	if report.Trust != policy.StatusFail {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusFail)
	}
	if report.OK() {
		t.Error("a failed policy reported OK")
	}
}

// Evidence signed by a key the policy does not name must not satisfy it.
// This is the case that separates "signed" from "signed by someone you
// trust".
func TestPolicyRejectsUnknownSigner(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layoutPath)

	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	strangerID, err := evidence.KeyID(stranger.Public())
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: strangerID}}
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusFail {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusFail)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.Code == policy.FindingSignatureThreshold {
			found = true
		}
	}
	if !found {
		t.Errorf("no threshold finding was reported: %v", report.Findings)
	}
}

// A client with no verifier cannot establish who signed anything, so
// evidence is rejected rather than trusted on the strength of being present.
func TestEvidenceWithoutAVerifierIsNotTrusted(t *testing.T) {
	t.Parallel()

	signer, key := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, signer, layoutPath)

	// A consumer with no verifier configured at all.
	consumer := newClient(t)

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
	})

	report, err := consumer.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusFail {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusFail)
	}
	if len(report.RejectedEvidence) == 0 {
		t.Error("the report does not say the evidence could not be checked")
	}
}

func TestPolicyRequireDigestReference(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + layoutPath,
		Tag:         "v1",
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Subject.RequireDigestReference = true
	})

	// A tag is refused before anything is fetched.
	_, err = client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + ":v1",
		Policy:    doc,
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}

	// A digest is accepted.
	if _, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	}); err != nil {
		t.Errorf("a digest reference was refused: %v", err)
	}
}

// Provenance must describe what was actually resolved, not what was asked
// for, and must record the lock so a build's inputs stay auditable.
func TestProvenanceRecordsResolvedSources(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    manifest,
		Destination: "oci-layout://" + layoutPath,
		Attest:      true,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Provenance.Required = true
		d.Spec.Provenance.RequireLockDigest = true
		d.Spec.Provenance.Sources.AllowedTypes = []string{"path"}
		d.Spec.Provenance.Sources.RequireImmutableResolution = true
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusPass {
		t.Errorf("trust = %q; findings: %v", report.Trust, report.Findings)
	}
}

// A source type the policy does not allow is a trust failure even when every
// signature is valid: policy chooses which build history it accepts.
func TestPolicyRejectsDisallowedSourceType(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layoutPath)

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Provenance.Required = true
		// The build used a path source.
		d.Spec.Provenance.Sources.AllowedTypes = []string{"git"}
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusFail {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusFail)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.Code == policy.FindingSourceTypeNotAllowed {
			found = true
		}
	}
	if !found {
		t.Errorf("no source-type finding was reported: %v", report.Findings)
	}
}

// A policy may tighten a limit and never relax one, so a policy traveling
// with an artifact cannot widen what the embedding application allowed.
func TestPolicyLimitsOnlyTighten(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layoutPath)

	doc := policyDoc("release", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
		// The fixture has three files.
		d.Spec.Subject.MaxFiles = 1
	})

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + "@" + built.SubjectDigest,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Trust != policy.StatusFail {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusFail)
	}
}

func TestBuildRejectsAttestWithoutAnAttester(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		Attest:      true,
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

// A policy that could never be satisfied is a configuration mistake, and
// failing at load says so where it can be fixed rather than producing a
// verification that always fails.
func TestUnsatisfiablePolicyIsRejected(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)

	unsatisfiable := []struct {
		name   string
		mutate func(*policy.Document)
	}{
		{"threshold with no identities", func(d *policy.Document) {
			d.Spec.Signatures.Threshold = 1
		}},
		{"threshold above the identity count", func(d *policy.Document) {
			d.Spec.Signatures.Threshold = 3
			d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: "abc"}}
		}},
		{"identity naming neither a key nor an issuer", func(d *policy.Document) {
			d.Spec.Signatures.Threshold = 1
			d.Spec.Signatures.Identities = []policy.IdentityRule{{}}
		}},
		{"subject with no issuer", func(d *policy.Document) {
			d.Spec.Signatures.Threshold = 1
			d.Spec.Signatures.Identities = []policy.IdentityRule{{Subject: "someone"}}
		}},
	}

	for _, tc := range unsatisfiable {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := client.Verify(t.Context(), devproof.VerifyRequest{
				Reference: "oci-layout://" + t.TempDir(),
				Policy:    policyDoc("broken", tc.mutate),
			})
			if !stderrors.Is(err, devproof.CodeInvalidInput) {
				t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
			}
		})
	}
}

// A policy loaded from a file must reject a field this build does not
// understand: a rule it cannot enforce would silently turn a strict policy
// into a permissive one.
func TestPolicyFileRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	client, _ := signingClient(t)

	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release
spec:
  signatures:
    threshold: 1
    identities:
      - keyId: abc
  requireSomethingThisBuildDoesNotKnow: true
`
	if err := writeFile(path, body); err != nil {
		t.Fatalf("writing policy: %v", err)
	}

	_, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference:  "oci-layout://" + t.TempDir(),
		PolicyPath: path,
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
	if err != nil && !strings.Contains(err.Error(), "requireSomethingThisBuildDoesNotKnow") {
		t.Errorf("the error does not name the unknown field: %v", err)
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

// TestEvidenceSurvivesAGenericIndexRewrite covers a layout that has been
// through a tool that is not this one.
//
// A layout has no referrers API, so this one records the relationship in a
// "subject" member on each index entry. That member is not part of the OCI
// image-layout specification. The standard place for the relationship is the
// subject descriptor inside the referrer manifest, which is where every other
// implementation looks -- so a generic copy or rewrite that produced a
// perfectly valid index would silently drop the only thing making attached
// evidence findable.
func TestEvidenceSurvivesAGenericIndexRewrite(t *testing.T) {
	t.Parallel()

	client, key := signingClient(t)
	layout := filepath.Join(t.TempDir(), "layout")
	built := buildSigned(t, client, layout)

	// Rewrite index.json without the non-standard member, keeping everything
	// the specification does define.
	indexPath := filepath.Join(layout, "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("reading index: %v", err)
	}
	var index map[string]any
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("decoding index: %v", err)
	}
	manifests, _ := index["manifests"].([]any)
	var stripped int
	for _, entry := range manifests {
		item, _ := entry.(map[string]any)
		if _, had := item["subject"]; had {
			delete(item, "subject")
			stripped++
		}
	}
	if stripped == 0 {
		t.Fatal("no index entry carried the custom subject member; the fixture proves nothing")
	}
	rewritten, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("encoding index: %v", err)
	}
	if err := os.WriteFile(indexPath, rewritten, 0o644); err != nil {
		t.Fatalf("writing index: %v", err)
	}

	doc := policyDoc("signed", func(d *policy.Document) {
		d.Spec.Signatures.Threshold = 1
		d.Spec.Signatures.Identities = []policy.IdentityRule{{KeyID: keyIDOf(t, key)}}
	})
	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: built.Reference,
		Policy:    doc,
	})
	if err != nil {
		t.Fatalf("verifying after a generic index rewrite: %v", err)
	}
	if report.Trust != policy.StatusPass {
		t.Errorf("evidence became undiscoverable after a standards-valid index rewrite: %v",
			report.Findings)
	}
}
