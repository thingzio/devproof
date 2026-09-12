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
	"net"
	"strings"
	"testing"
	"time"
)

// A Code is usable directly as an errors.Is target. This is the property the
// whole public error contract rests on: callers classify without constructing
// a comparison value.
func TestErrorIsMatchesCodeSentinel(t *testing.T) {
	t.Parallel()

	err := New(CodeStaleLock, "build", "source no longer matches the lock")

	if !stderrors.Is(err, CodeStaleLock) {
		t.Error("errors.Is did not match the error's own code")
	}
	if stderrors.Is(err, CodeInvalidInput) {
		t.Error("errors.Is matched an unrelated code")
	}
}

// Classification must survive being wrapped by intermediate layers, otherwise
// every caller has to unwrap by hand before it can branch.
func TestErrorIsMatchesThroughWrapping(t *testing.T) {
	t.Parallel()

	inner := New(CodeDigestMismatch, "verify", "layer digest does not match descriptor")
	outer := fmt.Errorf("packaging failed: %w", inner)

	if !stderrors.Is(outer, CodeDigestMismatch) {
		t.Error("code did not survive fmt.Errorf wrapping")
	}
	if got := CodeOf(outer); got != CodeDigestMismatch {
		t.Errorf("CodeOf = %q, want %q", got, CodeDigestMismatch)
	}
}

// Wrap(nil) returning nil lets callers write `return Wrap(...)` after a
// guarded check without accidentally manufacturing a non-nil error.
func TestWrapNilCauseReturnsNil(t *testing.T) {
	t.Parallel()

	if err := Wrap(CodeInternal, "build", "should not appear", nil); err != nil {
		t.Errorf("Wrap with nil cause returned %v, want nil", err)
	}
}

func TestWrapPreservesCause(t *testing.T) {
	t.Parallel()

	cause := stderrors.New("underlying failure")
	err := Wrap(CodeTransport, "push", "registry rejected the upload", cause)

	if !stderrors.Is(err, cause) {
		t.Error("wrapped cause is not reachable via errors.Is")
	}
	if !stderrors.Is(err, CodeTransport) {
		t.Error("wrapping a cause lost the classification")
	}
}

func TestCodeOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want Code
	}{
		{"nil error has no code", nil, ""},
		{"typed error", New(CodePolicyFailed, "verify", "threshold not met"), CodePolicyFailed},
		{"bare code sentinel", CodeUnsafePath, CodeUnsafePath},
		{"unclassified error is internal", stderrors.New("boom"), CodeInternal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CodeOf(tc.err); got != tc.want {
				t.Errorf("CodeOf(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// The With* helpers must copy. A shared *Error tagged with one source's name
// would otherwise mislabel every other source that observed it.
func TestWithHelpersDoNotMutateReceiver(t *testing.T) {
	t.Parallel()

	base := New(CodeSourceResolution, "lock", "clone failed")

	tagged := base.WithSource("application").WithPath("app/config.yaml").AsTemporary()

	if base.Source != "" || base.Path != "" || base.Temporary {
		t.Errorf("receiver mutated: %+v", base)
	}
	if tagged.Source != "application" || tagged.Path != "app/config.yaml" || !tagged.Temporary {
		t.Errorf("copy missing context: %+v", tagged)
	}
	if tagged.Code != base.Code {
		t.Error("copy lost its classification")
	}
}

func TestErrorMessageIncludesContext(t *testing.T) {
	t.Parallel()

	err := Wrap(CodeSourceResolution, "lock", "clone failed", stderrors.New("dial tcp: refused")).
		WithSource("application").
		WithPath("app/config.yaml")

	msg := err.Error()
	for _, want := range []string{
		"source-resolution", "lock", "clone failed",
		"application", "app/config.yaml", "dial tcp: refused",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

// errors.Is and errors.As must reach every source failure, not just the one
// that happened to stop the operation.
func TestSourceErrorsUnwrapsEveryFailure(t *testing.T) {
	t.Parallel()

	primary := New(CodeSourceResolution, "lock", "clone failed").WithSource("application")
	secondary := New(CodeUnsafePath, "lock", "symlink rejected").WithSource("environment")

	multi := &SourceErrors{Primary: primary, Additional: []error{secondary}}

	if !stderrors.Is(multi, CodeSourceResolution) {
		t.Error("primary failure not reachable")
	}
	if !stderrors.Is(multi, CodeUnsafePath) {
		t.Error("additional failure not reachable")
	}
	if !strings.Contains(multi.Error(), "1 more") {
		t.Errorf("message does not report additional count: %q", multi.Error())
	}
}

func TestSourceErrorsSingleFailureReadsAsPrimary(t *testing.T) {
	t.Parallel()

	primary := New(CodeStaleLock, "build", "lock is stale")
	multi := &SourceErrors{Primary: primary}

	if multi.Error() != primary.Error() {
		t.Errorf("Error() = %q, want the bare primary message", multi.Error())
	}
}

func TestIsTransient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"timeout", New(CodeTimeout, "push", "deadline exceeded"), true},
		{"transport", New(CodeTransport, "push", "registry 503"), true},
		{"explicitly marked temporary", New(CodeInternal, "push", "flaky").AsTemporary(), true},

		// The safety-relevant half: none of these become true by retrying.
		{"digest mismatch", New(CodeDigestMismatch, "verify", "mismatch"), false},
		{"policy failure", New(CodePolicyFailed, "verify", "threshold"), false},
		{"authentication", New(CodeAuthentication, "push", "denied"), false},
		{"unsafe path", New(CodeUnsafePath, "build", "escapes root"), false},
		{"invalid input", New(CodeInvalidInput, "lock", "bad manifest"), false},

		// A Ctrl-C must never re-enter a retry loop.
		{"canceled code", New(CodeCanceled, "build", "interrupted"), false},
		{"context canceled", context.Canceled, false},

		{"context deadline", context.DeadlineExceeded, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTransient(tc.err); got != tc.want {
				t.Errorf("IsTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A cancellation marked Temporary by a careless caller still must not retry:
// the code is checked before the advisory flag.
func TestIsTransientCanceledOutranksTemporaryFlag(t *testing.T) {
	t.Parallel()

	err := New(CodeCanceled, "build", "interrupted").AsTemporary()
	if IsTransient(err) {
		t.Error("a canceled error was reported transient because it was marked temporary")
	}
}

func TestIsNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"dns error", &net.DNSError{Err: "no such host", Name: "registry.example.com"}, true},
		{"op error", &net.OpError{Op: "dial", Err: stderrors.New("connection refused")}, true},
		{"opaque connection refused", stderrors.New("dial tcp: connection refused"), true},
		{"opaque tls timeout", stderrors.New("net/http: TLS handshake timeout"), true},
		{"unrelated", stderrors.New("invalid manifest"), false},

		// Control flow is not an outage.
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNetwork(tc.err); got != tc.want {
				t.Errorf("IsNetwork(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestFromContext(t *testing.T) {
	t.Parallel()

	t.Run("live context yields nil", func(t *testing.T) {
		t.Parallel()
		if err := FromContext(t.Context(), "expand", "canceled"); err != nil {
			t.Errorf("FromContext on a live context = %v, want nil", err)
		}
	})

	t.Run("cancellation is distinguished from deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := FromContext(ctx, "expand", "extraction canceled")
		if got := CodeOf(err); got != CodeCanceled {
			t.Errorf("CodeOf = %q, want %q", got, CodeCanceled)
		}
		if IsTransient(err) {
			t.Error("a cancellation was classified transient")
		}
	})

	t.Run("deadline is a timeout", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		<-ctx.Done()

		err := FromContext(ctx, "push", "upload timed out")
		if got := CodeOf(err); got != CodeTimeout {
			t.Errorf("CodeOf = %q, want %q", got, CodeTimeout)
		}
		if !IsTransient(err) {
			t.Error("a deadline was not classified transient")
		}
	})
}
