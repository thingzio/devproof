package fault

import (
	"context"
	stderrors "errors"
)

// CLI exit codes. Deliberately coarser than Code so that shell callers can
// branch on them stably while the JSON envelope carries the finer code.
//
// There is no exit code 1: every failure DevProof produces is classified, and
// a bare 1 would hide which class. See DP-023.
const (
	// ExitSuccess reports a completed operation.
	ExitSuccess = 0
	// ExitUsage reports a command usage, manifest, lock, or version error.
	ExitUsage = 2
	// ExitSource reports source resolution, stale lock, unsafe path, or
	// composition failure.
	ExitSource = 3
	// ExitArtifact reports artifact construction, integrity, digest, or
	// expansion failure.
	ExitArtifact = 4
	// ExitPolicy reports an evidence or verification-policy failure.
	ExitPolicy = 5
	// ExitTransport reports authentication, authorization, registry, or
	// network failure.
	ExitTransport = 6
	// ExitInternal reports a broken invariant.
	ExitInternal = 10
	// ExitInterrupted reports termination by SIGINT, following the shell's
	// 128+signal convention.
	ExitInterrupted = 130
)

// exitCodes maps every classification onto its exit code. It is a total map:
// the test suite asserts that every declared Code has an entry, so adding a
// code without deciding its exit status fails the build rather than silently
// falling through to ExitInternal.
var exitCodes = map[Code]int{
	CodeInvalidInput:       ExitUsage,
	CodeUnsupportedVersion: ExitUsage,
	CodeUnsupportedSource:  ExitUsage,

	CodeSourceResolution: ExitSource,
	CodeStaleLock:        ExitSource,
	CodeUnsafePath:       ExitSource,
	CodeUnsupportedFile:  ExitSource,
	CodePathCollision:    ExitSource,

	CodeDigestMismatch:    ExitArtifact,
	CodeInvalidArtifact:   ExitArtifact,
	CodeDestinationExists: ExitArtifact,
	CodeLimitExceeded:     ExitArtifact,

	CodeEvidenceInvalid: ExitPolicy,
	CodePolicyFailed:    ExitPolicy,

	CodeAuthentication: ExitTransport,
	CodeAuthorization:  ExitTransport,
	CodeTransport:      ExitTransport,
	CodeTimeout:        ExitTransport,

	CodeCanceled: ExitInterrupted,
	CodeInternal: ExitInternal,
}

// ExitCode maps err onto a CLI exit code.
//
// interrupted reports whether the process observed SIGINT. A cancellation that
// did not come from a signal is programmatic, and reporting 130 for it would
// tell a shell caller a lie about how the process ended; such a cancellation
// takes the exit code of the operation it interrupted.
func ExitCode(err error, interrupted bool) int {
	if err == nil {
		return ExitSuccess
	}
	code := CodeOf(err)
	if code == CodeCanceled || stderrors.Is(err, context.Canceled) {
		if interrupted {
			return ExitInterrupted
		}
		return ExitTransport
	}
	if exit, ok := exitCodes[code]; ok {
		return exit
	}
	return ExitInternal
}
