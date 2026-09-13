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

package policy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/evidence"
)

// VerifiedEvidence is one evidence object whose signatures have been checked.
//
// Nothing reaches this type without a verifier having established its
// identities. That is the whole structural guarantee of DP-014: the evaluator
// has no access to candidate evidence, so it cannot accidentally treat a
// parsed claim as an established one.
type VerifiedEvidence struct {
	// Descriptor identifies the evidence blob.
	Digest string
	// Statement is the verified statement.
	Statement *evidence.Statement
	// Identities are the signers whose signatures verified.
	Identities []evidence.Identity
	// TransparencyLogVerified reports a proven log inclusion.
	TransparencyLogVerified bool
	// IntegratedTime is an authenticated signing time, when one exists.
	IntegratedTime *time.Time
	// ViaTagFallback reports that this evidence was found under the
	// fallback tag scheme rather than the referrers API (DP-028).
	ViaTagFallback bool
}

// RejectedEvidence is a candidate that did not become evidence.
//
// Rejected candidates are reported separately rather than merged into the
// findings, so that "the policy was not satisfied" and "somebody attached
// junk to this repository" remain distinguishable.
type RejectedEvidence struct {
	Digest string
	Reason string
	// MatchedRequiredType reports whether the candidate claimed a type the
	// policy requires. Junk of an unrelated type is noise; junk claiming to
	// be the thing you asked for may be an attack.
	MatchedRequiredType bool
}

// Input is everything an evaluation considers.
type Input struct {
	// SubjectDigest is what is being verified.
	SubjectDigest string
	// Format is the bundle format that was read.
	Format bundle.Format
	// SuppliedDigestReference reports whether the caller named a digest
	// rather than a tag.
	SuppliedDigestReference bool
	// FileCount and TotalBytes describe the payload.
	FileCount  int64
	TotalBytes int64

	// Evidence is the cryptographically verified evidence. Candidates that
	// failed verification are not here; they are in Rejected.
	Evidence []VerifiedEvidence
	// Rejected are candidates that did not verify.
	Rejected []RejectedEvidence

	// EvaluatedAt is the single time used by every time-dependent rule,
	// captured once at the start of verification and recorded in the result.
	EvaluatedAt time.Time
}

// Evaluate applies a policy to verified facts.
//
// It reports findings rather than stopping at the first failure, because a
// consumer fixing a policy mismatch wants to know everything that is wrong,
// not to discover it one run at a time.
func Evaluate(doc *Document, input Input) *Report {
	report := &Report{
		Integrity:     StatusPass,
		Trust:         StatusPass,
		Semantics:     StatusNotEvaluated,
		SubjectDigest: input.SubjectDigest,
		Format:        input.Format.String(),
		FileCount:     input.FileCount,
		TotalBytes:    input.TotalBytes,
	}

	evaluateSubject(doc, input, report)
	accepted := evaluateSignatures(doc, input, report)
	evaluateProvenance(doc, input, accepted, report)
	evaluateCandidates(doc, input, report)

	if report.HasErrors() {
		report.Trust = StatusFail
	}
	return report
}

func evaluateSubject(doc *Document, input Input, report *Report) {
	rules := doc.Spec.Subject

	if rules.RequireDigestReference && !input.SuppliedDigestReference {
		report.AddFinding(Finding{
			Code: FindingDigestReferenceRequired, Rule: "subject.requireDigestReference",
			Severity: SeverityError, Subject: input.SubjectDigest,
			Message: "the policy requires a digest reference, but a tag was supplied",
		})
	}

	if len(rules.AllowedFormats) > 0 && !slices.Contains(rules.AllowedFormats, input.Format.String()) {
		report.AddFinding(Finding{
			Code: FindingFormatNotAllowed, Rule: "subject.allowedFormats",
			Severity: SeverityError, Subject: input.Format.String(),
			Message: fmt.Sprintf("bundle format %q is not in the policy's allowed list", input.Format),
		})
	}

	if rules.MaxFiles > 0 && input.FileCount > rules.MaxFiles {
		report.AddFinding(Finding{
			Code: FindingResourceLimit, Rule: "subject.maxFiles", Severity: SeverityError,
			Message: fmt.Sprintf("the bundle has %d files, the policy allows %d",
				input.FileCount, rules.MaxFiles),
		})
	}
	if rules.MaxExpandedBytes > 0 && input.TotalBytes > rules.MaxExpandedBytes {
		report.AddFinding(Finding{
			Code: FindingResourceLimit, Rule: "subject.maxExpandedBytes", Severity: SeverityError,
			Message: fmt.Sprintf("the bundle expands to %d bytes, the policy allows %d",
				input.TotalBytes, rules.MaxExpandedBytes),
		})
	}
}

// evaluateSignatures counts distinct accepted identities and returns the
// evidence that contributed to the count.
func evaluateSignatures(doc *Document, input Input, report *Report) []VerifiedEvidence {
	threshold := doc.EffectiveThreshold()
	rules := doc.Spec.Signatures

	var accepted []VerifiedEvidence
	// Counted by matched policy identity, not by signature. One signer
	// signing twice, or one evidence object carrying two signatures from the
	// same key, is one identity — otherwise a threshold of two could be met
	// by a single compromised signer.
	matched := make(map[string]struct{})

	// Only signers a rule actually named are recorded, and each once.
	//
	// Every identity on a contributing object used to be copied in, so a
	// signer the policy had never heard of appeared as accepted whenever
	// somebody else on the same object matched. A report records who was
	// believed; listing an unexamined signer beside a trusted one makes it
	// useless for the question it exists to answer.
	reported := make(map[string]struct{})
	for _, item := range input.Evidence {
		contributed := false
		for _, identity := range item.Identities {
			rule, ok := matchIdentity(rules.Identities, identity)
			if !ok {
				continue
			}
			matched[rule] = struct{}{}
			contributed = true

			name := identity.String()
			if _, seen := reported[name]; name != "" && !seen {
				reported[name] = struct{}{}
				report.AcceptedIdentities = append(report.AcceptedIdentities, name)
			}
		}
		if contributed {
			accepted = append(accepted, item)
		}
	}

	if threshold == 0 {
		return accepted
	}

	if len(rules.Identities) > 0 && len(matched) < threshold {
		report.AddFinding(Finding{
			Code: FindingSignatureThreshold, Rule: "signatures.threshold", Severity: SeverityError,
			Subject: input.SubjectDigest,
			Message: fmt.Sprintf("the policy requires %d distinct accepted signing identities, "+
				"and %d verified", threshold, len(matched)),
		})
	}
	if len(rules.Identities) == 0 && len(input.Evidence) == 0 {
		// Provenance required with no identity list: any verified signature
		// satisfies the identity half, but there has to be one.
		report.AddFinding(Finding{
			Code: FindingSignatureThreshold, Rule: "provenance.required", Severity: SeverityError,
			Subject: input.SubjectDigest,
			Message: "the policy requires signed provenance, and no verified evidence was found",
		})
	}

	if rules.RequireTransparencyLog {
		for _, item := range accepted {
			if !item.TransparencyLogVerified {
				report.AddFinding(Finding{
					Code: FindingTransparencyProof, Rule: "signatures.requireTransparencyLog",
					Severity: SeverityError, Subject: item.Digest,
					Message: "the policy requires a transparency-log inclusion proof, " +
						"and none was verified for this evidence",
				})
			}
		}
		if len(accepted) == 0 {
			report.AddFinding(Finding{
				Code: FindingTransparencyProof, Rule: "signatures.requireTransparencyLog",
				Severity: SeverityError, Subject: input.SubjectDigest,
				Message: "the policy requires a transparency-log inclusion proof, " +
					"and no evidence was accepted",
			})
		}
	}
	return accepted
}

// matchIdentity returns a stable key for the policy rule an identity matched.
func matchIdentity(rules []IdentityRule, identity evidence.Identity) (string, bool) {
	if len(rules) == 0 {
		// No identity list means any verified signer counts, and each
		// distinct signer counts once.
		return identity.String(), !identity.IsZero()
	}
	for i := range rules {
		if rules[i].Matches(identity.KeyID, identity.Issuer, identity.Subject) {
			return fmt.Sprintf("rule[%d]", i), true
		}
	}
	return "", false
}

func evaluateProvenance(doc *Document, input Input, accepted []VerifiedEvidence, report *Report) {
	rules := doc.Spec.Provenance
	if !rules.Required && len(rules.PredicateTypes) == 0 &&
		!rules.RequireLockDigest && len(rules.AllowedBuilders) == 0 &&
		len(rules.Sources.AllowedTypes) == 0 && len(rules.Sources.AllowedHosts) == 0 &&
		!rules.Sources.RequireImmutableResolution {

		return
	}

	if rules.Required && len(accepted) == 0 {
		report.AddFinding(Finding{
			Code: FindingProvenanceRequired, Rule: "provenance.required", Severity: SeverityError,
			Subject: input.SubjectDigest,
			Message: "the policy requires provenance, and no verified evidence was found",
		})
		return
	}

	for _, item := range accepted {
		evaluateOneProvenance(rules, item, input, report)
	}
}

func evaluateOneProvenance(rules ProvenanceRules, item VerifiedEvidence, input Input, report *Report) {
	statement := item.Statement

	if len(rules.PredicateTypes) > 0 && !slices.Contains(rules.PredicateTypes, statement.PredicateType) {
		report.AddFinding(Finding{
			Code: FindingPredicateNotAllowed, Rule: "provenance.predicateTypes",
			Severity: SeverityError, Subject: item.Digest,
			Message: fmt.Sprintf("predicate type %q is not in the policy's allowed list",
				statement.PredicateType),
		})
	}

	// The binding is re-checked here even though discovery filtered on it.
	// A signature proves who wrote a statement; only the subject digest
	// proves what it is about, and a statement bound to something else is
	// evidence for something else.
	if statement.Subject[0].Digest["sha256"] != strings.TrimPrefix(input.SubjectDigest, "sha256:") {
		report.AddFinding(Finding{
			Code: FindingSubjectMismatch, Rule: "provenance.subject", Severity: SeverityError,
			Subject: item.Digest,
			Message: "this evidence is bound to a different subject",
		})
		return
	}

	provenance := statement.Predicate.DevProof

	if rules.RequireLockDigest && provenance.LockDigest == "" {
		report.AddFinding(Finding{
			Code: FindingLockDigestRequired, Rule: "provenance.requireLockDigest",
			Severity: SeverityError, Subject: item.Digest,
			Message: "the policy requires provenance to record a lock digest, and this does not",
		})
	}

	if len(rules.AllowedBuilders) > 0 {
		builder := statement.Predicate.RunDetails.Builder.ID
		if !slices.Contains(rules.AllowedBuilders, builder) {
			report.AddFinding(Finding{
				Code: FindingBuilderNotAllowed, Rule: "provenance.allowedBuilders",
				Severity: SeverityError, Subject: item.Digest,
				Message: fmt.Sprintf("builder %q is not in the policy's allowed list", builder),
			})
		}
	}

	for _, source := range provenance.Sources {
		evaluateSource(rules.Sources, source, item.Digest, report)
	}
}

func evaluateSource(rules SourceRules, source evidence.SourceProvenance, evidenceDigest string, report *Report) {
	if len(rules.AllowedTypes) > 0 && !slices.Contains(rules.AllowedTypes, source.Type) {
		report.AddFinding(Finding{
			Code: FindingSourceTypeNotAllowed, Rule: "provenance.sources.allowedTypes",
			Severity: SeverityError, Subject: evidenceDigest,
			Message: fmt.Sprintf("source %q has type %q, which the policy does not allow",
				source.Name, source.Type),
		})
	}

	if len(rules.AllowedHosts) > 0 {
		if host, ok := sourceHost(source); ok && !slices.Contains(rules.AllowedHosts, host) {
			report.AddFinding(Finding{
				Code: FindingSourceHostNotAllowed, Rule: "provenance.sources.allowedHosts",
				Severity: SeverityError, Subject: evidenceDigest,
				Message: fmt.Sprintf("source %q came from host %q, which the policy does not allow",
					source.Name, host),
			})
		}
	}

	if rules.RequireImmutableResolution && !hasImmutableResolution(source) {
		report.AddFinding(Finding{
			Code: FindingImmutableResolution, Rule: "provenance.sources.requireImmutableResolution",
			Severity: SeverityError, Subject: evidenceDigest,
			Message: fmt.Sprintf("source %q does not record an immutable resolution", source.Name),
		})
	}
}

// sourceHost extracts the host a remote source came from.
func sourceHost(source evidence.SourceProvenance) (string, bool) {
	raw, ok := source.Requested["url"].(string)
	if !ok || raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	return parsed.Host, true
}

// hasImmutableResolution reports whether a source resolved to something that
// cannot change.
//
// A tree digest always qualifies: it is the content itself. A commit
// qualifies for Git. A branch name or a bare path does not, which is exactly
// the case this rule exists to catch.
func hasImmutableResolution(source evidence.SourceProvenance) bool {
	if source.TreeDigest == "" {
		return false
	}
	if _, err := bundle.ParseDigest(source.TreeDigest); err != nil {
		return false
	}
	return true
}

func evaluateCandidates(doc *Document, input Input, report *Report) {
	for _, rejected := range input.Rejected {
		severity := SeverityWarning
		code := FindingIgnoredEvidence

		// A repository is an open attachment surface, so junk of an
		// unrelated type is noise and must not make a valid subject
		// unverifiable. Junk that claims to be the thing the policy requires
		// is a different matter, and the policy decides.
		if rejected.MatchedRequiredType && doc.Spec.Evidence.RejectInvalidMatchingEvidence {
			severity = SeverityError
			code = FindingMatchingEvidenceInvalid
		}
		report.AddFinding(Finding{
			Code: code, Rule: "evidence.rejectInvalidMatchingEvidence",
			Severity: severity, Subject: rejected.Digest, Message: rejected.Reason,
		})
	}

	if !doc.Spec.Evidence.AllowTagFallback {
		for _, item := range input.Evidence {
			if item.ViaTagFallback {
				report.AddFinding(Finding{
					Code: FindingTagFallbackNotAllowed, Rule: "evidence.allowTagFallback",
					Severity: SeverityError, Subject: item.Digest,
					Message: "this evidence was found under the fallback tag scheme, " +
						"which cannot express a set of evidence and silently replaces; " +
						"the policy does not allow it",
				})
			}
		}
	}
}
