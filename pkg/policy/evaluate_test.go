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

package policy_test

import (
	"slices"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/policy"
)

// TestAcceptedIdentitiesAreOnlyTheMatchedOnes pins what that field means.
//
// An evidence object can carry more than one verified signature. Every
// identity on an object that contributed was previously copied into the
// report, so a signer the policy had never heard of appeared under
// "acceptedIdentities" as long as somebody else on the same object matched.
//
// A report records who was believed. Listing a signer nobody decided to trust
// beside one who was trusted makes the field useless for the thing it exists
// for: answering, after the fact, whose signature this artifact rests on.
func TestAcceptedIdentitiesAreOnlyTheMatchedOnes(t *testing.T) {
	t.Parallel()

	const trusted = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const stranger = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	doc := &policy.Document{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindVerificationPolicy,
		Metadata:   policy.Metadata{Name: "one-signer"},
		Spec: policy.Spec{
			Signatures: policy.SignatureRules{
				Threshold:  1,
				Identities: []policy.IdentityRule{{KeyID: trusted}},
			},
		},
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the fixture policy is invalid: %v", err)
	}

	report := policy.Evaluate(doc, policy.Input{
		SubjectDigest: "sha256:" + trusted,
		Format:        bundle.FormatV1,
		Evidence: []policy.VerifiedEvidence{{
			Digest: "sha256:" + stranger,
			// Both signatures verified. Only one is a signer this policy
			// named.
			Identities: []evidence.Identity{
				{KeyID: trusted},
				{KeyID: stranger},
			},
		}},
	})

	if report.Trust != policy.StatusPass {
		t.Fatalf("trust = %s, want pass: a listed identity signed it", report.Trust)
	}

	want := evidence.Identity{KeyID: trusted}.String()
	unwanted := evidence.Identity{KeyID: stranger}.String()

	if !slices.Contains(report.AcceptedIdentities, want) {
		t.Errorf("the matched signer is missing from %v", report.AcceptedIdentities)
	}
	if slices.Contains(report.AcceptedIdentities, unwanted) {
		t.Errorf("a signer the policy never named was reported as accepted: %v",
			report.AcceptedIdentities)
	}
}

// TestAcceptedIdentitiesAreDeduplicated keeps a repeated signer from reading
// as several.
//
// The threshold already counts distinct matched rules rather than signatures,
// so one signer cannot satisfy a threshold of two. The report should not tell
// a different story from the count that gated the result.
func TestAcceptedIdentitiesAreDeduplicated(t *testing.T) {
	t.Parallel()

	const signer = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	doc := &policy.Document{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindVerificationPolicy,
		Metadata:   policy.Metadata{Name: "one-signer"},
		Spec: policy.Spec{
			Signatures: policy.SignatureRules{
				Threshold:  1,
				Identities: []policy.IdentityRule{{KeyID: signer}},
			},
		},
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the fixture policy is invalid: %v", err)
	}

	// The same signer on two separate evidence objects.
	item := policy.VerifiedEvidence{
		Digest:     "sha256:" + signer,
		Identities: []evidence.Identity{{KeyID: signer}},
	}
	report := policy.Evaluate(doc, policy.Input{
		SubjectDigest: "sha256:" + signer,
		Format:        bundle.FormatV1,
		Evidence:      []policy.VerifiedEvidence{item, item},
	})

	name := evidence.Identity{KeyID: signer}.String()
	var count int
	for _, got := range report.AcceptedIdentities {
		if got == name {
			count++
		}
	}
	if count != 1 {
		t.Errorf("one signer is reported %d times: %v", count, report.AcceptedIdentities)
	}
}

const (
	subjectHex = "1111111111111111111111111111111111111111111111111111111111111111"
	treeHex    = "2222222222222222222222222222222222222222222222222222222222222222"
	otherHex   = "3333333333333333333333333333333333333333333333333333333333333333"
	signerHex  = "4444444444444444444444444444444444444444444444444444444444444444"
)

// provenanceInput builds a verified-evidence input whose predicate the test
// can shape.
func provenanceInput(mutate func(*evidence.DevProofProvenance)) policy.Input {
	claims := evidence.DevProofProvenance{
		FormatVersion:  string(bundle.FormatV1),
		ManifestDigest: "sha256:" + otherHex,
		LockDigest:     "sha256:" + otherHex,
		TreeDigest:     "sha256:" + treeHex,
		Sources: []evidence.SourceProvenance{{
			Name: "content", Type: "path", Resolver: "devproof.thingz.io/path/v1",
			TreeDigest: "sha256:" + treeHex,
		}},
	}
	if mutate != nil {
		mutate(&claims)
	}

	statement := &evidence.Statement{
		Type:          evidence.StatementType,
		PredicateType: bundle.PredicateTypeProvenanceV1,
		Subject: []evidence.Subject{{
			Digest: map[string]string{"sha256": subjectHex},
		}},
		Predicate: evidence.Predicate{DevProof: claims},
	}

	return policy.Input{
		SubjectDigest: "sha256:" + subjectHex,
		TreeDigest:    "sha256:" + treeHex,
		Format:        bundle.FormatV1,
		Evidence: []policy.VerifiedEvidence{{
			Digest:     "sha256:" + signerHex,
			Statement:  statement,
			Identities: []evidence.Identity{{KeyID: signerHex}},
		}},
	}
}

func provenancePolicy(mutate func(*policy.ProvenanceRules)) *policy.Document {
	doc := &policy.Document{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindVerificationPolicy,
		Metadata:   policy.Metadata{Name: "provenance"},
		Spec: policy.Spec{
			Signatures: policy.SignatureRules{
				Threshold:  1,
				Identities: []policy.IdentityRule{{KeyID: signerHex}},
			},
			Provenance: policy.ProvenanceRules{Required: true},
		},
	}
	if mutate != nil {
		mutate(&doc.Spec.Provenance)
	}
	return doc
}

// TestProvenanceClaimsAreBoundToTheSubject is the heart of R07.
//
// A signature establishes who wrote a statement. It says nothing about
// whether the statement is true. The subject binding was checked, so evidence
// could not be lifted onto a different artifact -- but the predicate's own
// claims about that artifact were taken at face value.
//
// A trusted signer could therefore publish provenance correctly bound to this
// subject while claiming a different tree digest or a different bundle
// format, and policy would report it as verified. Malformed or internally
// contradictory assertions must never become verified facts.
func TestProvenanceClaimsAreBoundToTheSubject(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		mutate func(*evidence.DevProofProvenance)
	}{
		{"tree digest", func(p *evidence.DevProofProvenance) {
			p.TreeDigest = "sha256:" + otherHex
		}},
		{"format", func(p *evidence.DevProofProvenance) {
			p.FormatVersion = "devproof-bundle-v99"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			report := policy.Evaluate(provenancePolicy(nil), provenanceInput(tc.mutate))
			if report.Trust == policy.StatusPass {
				t.Errorf("provenance contradicting the subject's %s was accepted", tc.name)
			}
		})
	}
}

// TestConsistentProvenanceIsAccepted guards against the check rejecting
// everything.
func TestConsistentProvenanceIsAccepted(t *testing.T) {
	t.Parallel()

	report := policy.Evaluate(provenancePolicy(nil), provenanceInput(nil))
	if report.Trust != policy.StatusPass {
		t.Errorf("consistent provenance was rejected: %v", report.Findings)
	}
}

// TestRequireLockDigestWantsADigest covers a rule that accepted anything.
//
// requireLockDigest checked only that the field was non-empty, so the string
// "yes" satisfied a policy asking a build to record what it was locked
// against.
func TestRequireLockDigestWantsADigest(t *testing.T) {
	t.Parallel()

	doc := provenancePolicy(func(r *policy.ProvenanceRules) { r.RequireLockDigest = true })
	report := policy.Evaluate(doc, provenanceInput(func(p *evidence.DevProofProvenance) {
		p.LockDigest = "yes"
	}))
	if report.Trust == policy.StatusPass {
		t.Error("a lock digest of \"yes\" satisfied requireLockDigest")
	}
}

// TestSourceRulesDoNotPassVacuously covers rules with nothing to apply to.
//
// Source restrictions were evaluated by looping over the sources a predicate
// claimed. An empty list ran the loop zero times, so a policy restricting
// source types and hosts was satisfied by provenance asserting there were no
// sources at all -- the one claim that should never satisfy it.
func TestSourceRulesDoNotPassVacuously(t *testing.T) {
	t.Parallel()

	doc := provenancePolicy(func(r *policy.ProvenanceRules) {
		r.Sources.AllowedTypes = []string{"git"}
		r.Sources.AllowedHosts = []string{"github.com"}
	})
	report := policy.Evaluate(doc, provenanceInput(func(p *evidence.DevProofProvenance) {
		p.Sources = nil
	}))
	if report.Trust == policy.StatusPass {
		t.Error("source restrictions were satisfied by provenance claiming no sources")
	}
}
