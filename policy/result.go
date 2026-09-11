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
	SeverityError   Severity = "error"
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

// Stable finding codes. The set grows as policy evaluation lands; these are
// the ones integrity verification can produce.
const (
	FindingIntegrityFailed   = "integrity-failed"
	FindingDigestMismatch    = "digest-mismatch"
	FindingInvalidArtifact   = "invalid-artifact"
	FindingFormatNotAllowed  = "format-not-allowed"
	FindingResourceLimit     = "resource-limit-exceeded"
	FindingPolicyNotSupplied = "policy-not-supplied"
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

	Findings []Finding `json:"findings,omitempty"`
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
