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
