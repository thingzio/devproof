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

// Package policy defines DevProof's verification result model and, in later
// phases, the verification policy document and its evaluator.
//
// The central idea here is that verification answers three separate
// questions, and collapsing them into one boolean is what makes supply-chain
// tooling misleading. An artifact can be perfectly intact and signed by
// someone you have never heard of; it can be signed by exactly the right
// identity and contain nonsense. Each dimension is reported on its own terms.
package policy

import "fmt"

// Status is the outcome of one verification dimension.
type Status string

const (
	// StatusPass means the dimension was evaluated and satisfied.
	StatusPass Status = "pass"
	// StatusFail means the dimension was evaluated and not satisfied.
	StatusFail Status = "fail"
	// StatusNotEvaluated means the dimension was not assessed.
	//
	// It is deliberately not a synonym for pass. "No policy was supplied, so
	// nothing was checked" and "the policy was satisfied" are different
	// facts, and a consumer that cannot tell them apart has no way to notice
	// that its trust configuration never took effect (DP-010).
	StatusNotEvaluated Status = "not-evaluated"
)

func (s Status) String() string { return string(s) }

// Severity classifies a finding.
type Severity string

const (
	// SeverityError means the policy was not satisfied. One is enough to
	// fail a report.
	SeverityError Severity = "error"
	// SeverityWarning is worth reporting but does not fail verification, such
	// as evidence that was ignored because nothing required it.
	SeverityWarning Severity = "warning"
)

// Finding is one thing verification observed.
//
// Code is a stable machine identifier and Message is not. Callers branch on
// the code; the message is for the human deciding what to do.
type Finding struct {
	Code     string   `json:"code"`
	Rule     string   `json:"rule,omitempty"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject,omitempty"`
	Message  string   `json:"message"`
}

func (f Finding) String() string {
	if f.Subject == "" {
		return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Code, f.Message)
	}
	return fmt.Sprintf("[%s] %s: %s (%s)", f.Severity, f.Code, f.Message, f.Subject)
}

// Stable finding codes.
//
// Codes are a compatibility surface; messages are not. A caller branches on
// these, and a message may be reworded at any time.
const (
	FindingIntegrityFailed   = "integrity-failed"
	FindingDigestMismatch    = "digest-mismatch"
	FindingInvalidArtifact   = "invalid-artifact"
	FindingFormatNotAllowed  = "format-not-allowed"
	FindingResourceLimit     = "resource-limit-exceeded"
	FindingPolicyNotSupplied = "policy-not-supplied"

	FindingDigestReferenceRequired = "digest-reference-required"
	FindingSignatureThreshold      = "signature-threshold-not-met"
	FindingSignerNotAllowed        = "signer-identity-not-allowed"
	FindingTransparencyProof       = "transparency-proof-required"
	FindingProvenanceRequired      = "provenance-required"
	// FindingProvenanceInconsistent marks a signed statement whose claims
	// contradict what verification established. A signature proves authorship,
	// not truth.
	FindingProvenanceInconsistent = "provenance-inconsistent"
	FindingPredicateNotAllowed    = "predicate-not-allowed"
	FindingBuilderNotAllowed      = "builder-not-allowed"
	FindingLockDigestRequired     = "lock-digest-required"
	FindingSourceTypeNotAllowed   = "source-type-not-allowed"
	FindingSourceHostNotAllowed   = "source-host-not-allowed"
	FindingImmutableResolution    = "immutable-resolution-required"
	FindingSubjectMismatch        = "evidence-subject-mismatch"
	FindingEvidenceExpired        = "evidence-expired"
	// FindingSemanticsInvalid reports a caller-supplied validator rejecting
	// the payload. Distinct from every trust code: the artifact may be
	// perfectly trusted and its content still wrong.
	FindingSemanticsInvalid        = "semantics-invalid"
	FindingMatchingEvidenceInvalid = "matching-evidence-invalid"
	FindingIgnoredEvidence         = "evidence-ignored"
	FindingTagFallbackNotAllowed   = "evidence-tag-fallback-not-allowed"
)

// Report is the outcome of verifying one subject: the DevProof proof report.
//
// It records what was checked, not merely whether it passed, so that a
// consumer can tell a verification that proved a great deal from one that
// proved very little.
type Report struct {
	// Integrity reports whether the artifact's own parts agree. It is always
	// evaluated; there is no flag that disables it.
	Integrity Status `json:"integrity"`
	// Trust reports whether evidence satisfied the supplied policy.
	Trust Status `json:"trust"`
	// Semantics reports whether a caller-supplied validator accepted the
	// payload.
	Semantics Status `json:"semantics"`

	// SubjectDigest identifies what was verified. A result always names its
	// subject by digest, never by the tag it may have been reached through
	// (DP-007).
	SubjectDigest string `json:"subjectDigest"`
	// TreeDigest identifies the payload independently of its encoding.
	TreeDigest string `json:"treeDigest,omitempty"`
	// Format is the bundle format version that was read.
	Format string `json:"format,omitempty"`

	FileCount  int64 `json:"fileCount"`
	TotalBytes int64 `json:"totalBytes"`

	// AcceptedIdentities are the signers whose signatures verified and whose
	// identities a policy rule accepted. A report records who was believed,
	// not merely that somebody was.
	AcceptedIdentities []string `json:"acceptedIdentities,omitempty"`
	// PolicyDigest identifies the policy that was applied, so a result can
	// be re-checked against the rules that produced it.
	PolicyDigest string `json:"policyDigest,omitempty"`
	// PolicyName is the policy's metadata name, for diagnostics.
	PolicyName string `json:"policyName,omitempty"`
	// EvaluatedAt is the single time every time-dependent rule used.
	EvaluatedAt string `json:"evaluatedAt,omitempty"`
	// EvidenceStorage reports how evidence was found: "referrers" or
	// "tag-fallback". The fallback cannot express a set, so a consumer needs
	// to know which mode produced the answer (DP-028).
	EvidenceStorage string `json:"evidenceStorage,omitempty"`
	// AcceptedEvidence describes the evidence the conclusion rests on.
	//
	// Recording who signed is not enough. Two statements from the same trusted
	// signer can say entirely different things about an artifact, and a report
	// that named the signer but not the statement could not answer "what was
	// this verified against" after the fact.
	AcceptedEvidence []AcceptedEvidence `json:"acceptedEvidence,omitempty"`
	// RejectedEvidence summarizes candidates that did not verify, kept
	// separate from findings so "the policy was not satisfied" and "somebody
	// attached junk" stay distinguishable.
	RejectedEvidence []string `json:"rejectedEvidence,omitempty"`
	// TrustRoots identifies the trust material by digest.
	//
	// The same policy reaches different conclusions under different roots, so
	// a result that named only the policy did not identify the rules that
	// produced it. Digests rather than paths: a path is a fact about one
	// machine, and trust material is not a secret but its location can be.
	TrustRoots []string `json:"trustRoots,omitempty"`

	// Validators records which semantic validators ran and what each
	// concluded.
	//
	// Same principle as PolicyDigest and TrustRoots: a passing result has to
	// name what produced it. A report showing semantics: pass without naming
	// the validators is not auditable, and two consumers running different
	// validator sets would produce identical-looking results.
	Validators []Record `json:"validators,omitempty"`

	// Limits records the bounds this verification actually ran under and
	// where each came from (DP-021).
	//
	// A limit is only meaningful if a consumer can tell which one applied. A
	// policy that tightened maxExpandedBytes and a client that did are the
	// same number in the result and very different facts about who decided
	// it, and "the policy asked for a bound nothing applied" was previously
	// indistinguishable from "the policy's bound held".
	Limits []Limit `json:"limits,omitempty"`

	Findings []Finding `json:"findings,omitempty"`
}

// AcceptedEvidence is one verified statement the result relied on.
type AcceptedEvidence struct {
	// Digest identifies the evidence object.
	Digest string `json:"digest"`
	// PredicateType is what the statement claims to be.
	PredicateType string `json:"predicateType,omitempty"`
	// TransparencyLogVerified reports whether an inclusion proof was checked.
	TransparencyLogVerified bool `json:"transparencyLogVerified,omitempty"`
	// IntegratedTime is the authenticated signing time, when one exists.
	IntegratedTime string `json:"integratedTime,omitempty"`
	// ViaTagFallback reports that the evidence was found under the fallback
	// tag scheme, which cannot express a set (DP-028).
	ViaTagFallback bool `json:"viaTagFallback,omitempty"`
}

// Record is one semantic validator and what it concluded.
type Record struct {
	// Name is the validator's stable identifier.
	Name string `json:"name"`
	// Status is that validator's own verdict. The report's Semantics is the
	// conjunction: one failure fails the dimension.
	Status Status `json:"status"`
}

// Limit is one resource bound as it applied to a verification.
type Limit struct {
	// Name is the bound's stable name, matching the policy field that sets
	// it.
	Name string `json:"name"`
	// Value is the effective bound: the smallest anybody asked for.
	Value int64 `json:"value"`
	// Origin is which input supplied that value: default, client, request,
	// or policy.
	Origin string `json:"origin"`
}

// OK reports whether the operation should be considered successful.
//
// Integrity must pass, and any dimension that was evaluated must pass.
// A dimension that was not evaluated cannot fail the result — but it cannot
// satisfy a requirement either, which is why callers that need trust must ask
// for it explicitly rather than reading OK.
func (r *Report) OK() bool {
	if r.Integrity != StatusPass {
		return false
	}
	if r.Trust == StatusFail || r.Semantics == StatusFail {
		return false
	}
	return true
}

// AddFinding appends a finding.
func (r *Report) AddFinding(f Finding) { r.Findings = append(r.Findings, f) }

// HasErrors reports whether any finding is an error.
func (r *Report) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}
