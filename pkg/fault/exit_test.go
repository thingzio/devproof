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

package fault

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
)

// Every declared Code must have a decided exit status. Without this, a new
// code silently falls through to ExitInternal and the CLI reports a broken
// invariant for what is really a user error.
func TestExitCodesAreTotal(t *testing.T) {
	t.Parallel()

	for _, code := range allCodes {
		if _, ok := exitCodes[code]; !ok {
			t.Errorf("code %q has no exit-code mapping", code)
		}
	}
	if len(exitCodes) != len(allCodes) {
		t.Errorf("exitCodes has %d entries, allCodes has %d: the two are out of sync",
			len(exitCodes), len(allCodes))
	}
}

// The mapping is a documented contract (DP-023), so it is asserted directly
// rather than inferred from the table it is read out of.
func TestExitCodeMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code Code
		want int
	}{
		{CodeInvalidInput, ExitUsage},
		{CodeUnsupportedVersion, ExitUsage},
		{CodeUnsupportedSource, ExitUsage},

		{CodeSourceResolution, ExitSource},
		{CodeStaleLock, ExitSource},
		{CodeUnsafePath, ExitSource},
		{CodeUnsupportedFile, ExitSource},
		{CodePathCollision, ExitSource},

		{CodeDigestMismatch, ExitArtifact},
		{CodeInvalidArtifact, ExitArtifact},
		{CodeDestinationExists, ExitArtifact},
		{CodeLimitExceeded, ExitArtifact},

		{CodeEvidenceInvalid, ExitPolicy},
		{CodePolicyFailed, ExitPolicy},

		{CodeAuthentication, ExitTransport},
		{CodeAuthorization, ExitTransport},
		{CodeTransport, ExitTransport},
		{CodeTimeout, ExitTransport},

		{CodeInternal, ExitInternal},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			t.Parallel()
			err := New(tc.code, "op", "message")
			if got := ExitCode(err, false); got != tc.want {
				t.Errorf("ExitCode(%q) = %d, want %d", tc.code, got, tc.want)
			}
		})
	}
}

func TestExitCodeSuccessOnNil(t *testing.T) {
	t.Parallel()

	if got := ExitCode(nil, false); got != ExitSuccess {
		t.Errorf("ExitCode(nil) = %d, want %d", got, ExitSuccess)
	}
	// Even if a signal arrived, a successful operation exits 0.
	if got := ExitCode(nil, true); got != ExitSuccess {
		t.Errorf("ExitCode(nil, interrupted) = %d, want %d", got, ExitSuccess)
	}
}

// 130 means "the user pressed Ctrl-C". Reporting it for a programmatic
// cancellation would tell a shell caller something untrue about how the
// process ended.
func TestExitCodeCancellationDependsOnSignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		interrupted bool
		want        int
	}{
		{"SIGINT", New(CodeCanceled, "build", "interrupted"), true, ExitInterrupted},
		{"programmatic", New(CodeCanceled, "build", "canceled"), false, ExitTransport},
		{"bare context.Canceled with signal", context.Canceled, true, ExitInterrupted},
		{"bare context.Canceled without signal", context.Canceled, false, ExitTransport},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitCode(tc.err, tc.interrupted); got != tc.want {
				t.Errorf("ExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestExitCodeUnclassifiedIsInternal(t *testing.T) {
	t.Parallel()

	if got := ExitCode(stderrors.New("boom"), false); got != ExitInternal {
		t.Errorf("ExitCode(unclassified) = %d, want %d", got, ExitInternal)
	}
}

// A code must survive wrapping on its way to the process exit status.
func TestExitCodeThroughWrapping(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("build: %w", New(CodePolicyFailed, "verify", "threshold not met"))
	if got := ExitCode(err, false); got != ExitPolicy {
		t.Errorf("ExitCode(wrapped) = %d, want %d", got, ExitPolicy)
	}
}

// No failure exits 1: every failure is classified, and a bare 1 would hide
// which class.
//
// Exit 1 does exist -- ExitDifferences, which `diff` returns when the two
// sides are not the same. That is a successful comparison with a negative
// answer, reachable only from a result and never from an error, which is what
// this test keeps true. If a Code ever mapped here, a script branching on
// "they differ" would start treating failures as differences.
func TestExitCodeNeverReturnsOne(t *testing.T) {
	t.Parallel()

	for _, code := range allCodes {
		for _, interrupted := range []bool{false, true} {
			if got := ExitCode(New(code, "op", "msg"), interrupted); got == 1 {
				t.Errorf("code %q (interrupted=%v) produced the unclassified exit code 1",
					code, interrupted)
			}
		}
	}
}
