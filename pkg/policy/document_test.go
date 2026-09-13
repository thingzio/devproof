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
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/policy"
)

const policyHeader = `apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release-bundles
`

// TestLimitsUseDocumentedSpelling pins the spelling of every limit a policy
// can set.
//
// Without struct tags, yaml.v3 derives a key by lowercasing the whole field
// name, so MaxFiles becomes "maxfiles" and the camelCase spelling every
// document uses is rejected as an unknown field. A policy is fail-closed, so
// the failure was loud rather than silent -- but it made the documented
// example unusable, and the spelling that did work was one nobody had written
// down.
func TestLimitsUseDocumentedSpelling(t *testing.T) {
	t.Parallel()

	limits := []string{
		"maxFiles",
		"maxFileBytes",
		"maxExpandedBytes",
		"maxCompressedBytes",
		"maxCompressionRatio",
		"maxPathBytes",
		"maxPathSegmentBytes",
		"maxPathDepth",
		"maxConfigBytes",
		"maxManifestBytes",
		"maxSpecBytes",
		"maxLockBytes",
		"maxReferrers",
		"maxEvidenceBytes",
		"maxParallelSources",
	}

	for _, field := range limits {
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			doc := policyHeader + "spec:\n  limits:\n    " + field + ": 1\n"
			if _, err := policy.ParseDocument([]byte(doc)); err != nil {
				t.Fatalf("limit %q is documented but not accepted: %v", field, err)
			}
		})
	}
}

// TestLimitsRejectLowercaseSpelling is the other half: once the tags exist,
// the accidental all-lowercase spelling must stop working.
//
// Leaving both accepted would mean two ways to write one rule, and a policy
// that a reader and the decoder read differently is the failure this document
// type exists to prevent.
func TestLimitsRejectLowercaseSpelling(t *testing.T) {
	t.Parallel()

	doc := policyHeader + "spec:\n  limits:\n    maxfiles: 1\n"
	_, err := policy.ParseDocument([]byte(doc))
	if err == nil {
		t.Fatal("the undocumented all-lowercase spelling was accepted")
	}
	if !strings.Contains(err.Error(), "maxfiles") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// TestDocumentedPolicyExampleParses runs the example from docs/policy.md.
//
// Documentation examples are tested elsewhere in this project for the CLI;
// this is the same idea applied to the one document type whose examples had
// drifted out of step with the decoder.
func TestDocumentedPolicyExampleParses(t *testing.T) {
	t.Parallel()

	const example = `apiVersion: devproof.thingz.io/v1alpha1
kind: VerificationPolicy
metadata:
  name: release-bundles
spec:
  subject:
    requireDigestReference: true
    allowedFormats:
      - devproof-bundle-v1

  signatures:
    threshold: 1
    identities:
      - issuer: https://token.actions.githubusercontent.com
        subject: https://github.com/example/release/.github/workflows/build.yaml@refs/heads/main

  provenance:
    required: true
    predicateTypes:
      - https://slsa.dev/provenance/v1
    requireLockDigest: true
    sources:
      allowedTypes: [git]
      allowedHosts:
        - github.com
      requireImmutableResolution: true

  evidence:
    rejectInvalidMatchingEvidence: true

  limits:
    maxFiles: 10000
    maxExpandedBytes: 1073741824
`

	if _, err := policy.ParseDocument([]byte(example)); err != nil {
		t.Fatalf("the example in docs/policy.md does not parse: %v", err)
	}
}

// TestNegativeSubjectLimitsAreRejected closes a fail-open gap.
//
// Document.Validate checked spec.limits but not subject.maxFiles or
// subject.maxExpandedBytes, and the evaluator applies those only when they are
// greater than zero. A policy setting maxFiles: -1 therefore loaded cleanly
// and silently enforced nothing -- the one outcome a strict, fail-closed
// document type must not have, because it looks exactly like a policy that is
// working.
func TestNegativeSubjectLimitsAreRejected(t *testing.T) {
	t.Parallel()

	for _, field := range []string{"maxFiles", "maxExpandedBytes"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			doc := policyHeader + "spec:\n  subject:\n    " + field + ": -1\n"
			_, err := policy.ParseDocument([]byte(doc))
			if err == nil {
				t.Fatalf("a negative subject.%s was accepted", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("the error does not name the offending field: %v", err)
			}
		})
	}
}

// TestZeroSubjectLimitsStayUnset guards the boundary the fix must not move.
//
// Zero means "unset, inherit the effective limit" everywhere else in this
// project, and a policy that omits a bound is the ordinary case.
func TestZeroSubjectLimitsStayUnset(t *testing.T) {
	t.Parallel()

	doc := policyHeader + "spec:\n  subject:\n    maxFiles: 0\n"
	if _, err := policy.ParseDocument([]byte(doc)); err != nil {
		t.Errorf("an explicit zero was rejected: %v", err)
	}
}
