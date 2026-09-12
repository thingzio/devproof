package cli

import (
	"os"
	"strings"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/policy"
)

// usageError reports a command-line mistake.
//
// Usage errors carry CodeInvalidInput, which maps to exit 2 — the same code a
// malformed manifest produces, because from a shell's point of view both mean
// "you asked for something that does not make sense".
func usageError(message string) error {
	return fault.New(fault.CodeInvalidInput, "cli", message)
}

// policyFailure turns an unsatisfied report into a typed error.
//
// A verification that reports trust: fail and exits zero is worse than no
// verification at all: every gate built on it silently passes. The exit code
// comes from the error class, so a policy failure is exit 5 whatever else
// went right.
func policyFailure(report *policy.Report) error {
	var reasons []string
	for _, finding := range report.Findings {
		if finding.Severity == policy.SeverityError {
			reasons = append(reasons, finding.Code)
		}
	}

	switch {
	case report.Integrity != policy.StatusPass:
		return fault.New(fault.CodeInvalidArtifact, "verify",
			"the artifact failed integrity verification").
			WithPath(report.SubjectDigest)
	case len(reasons) > 0:
		return fault.New(fault.CodePolicyFailed, "verify",
			"the policy was not satisfied: "+strings.Join(reasons, ", ")).
			WithPath(report.SubjectDigest)
	default:
		return fault.New(fault.CodePolicyFailed, "verify",
			"the policy was not satisfied").WithPath(report.SubjectDigest)
	}
}

// looksLikePath reports whether a target names a local file.
//
// Decided by asking the filesystem rather than by parsing: a directory named
// like a registry reference is still a directory, and a reference that
// happens to look like a path is still a reference if nothing is there.
func looksLikePath(target string) bool {
	if strings.Contains(target, "://") {
		return false
	}
	info, err := os.Lstat(target)
	return err == nil && !info.IsDir()
}
