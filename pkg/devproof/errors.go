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

package devproof

import (
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

// Error is the error type every DevProof operation returns. Inspect it with
// [errors.As], and classify with [errors.Is] against a Code:
//
//	if errors.Is(err, devproof.CodeStaleLock) {
//	    // refresh the lock
//	}
//
//	var dperr *devproof.Error
//	if errors.As(err, &dperr) {
//	    log.Printf("source %q failed at %q", dperr.Source, dperr.Path)
//	}
type Error = fault.Error

// Code classifies a failure. It is also a valid [errors.Is] target.
type Code = fault.Code

// SourceErrors reports a multi-source failure: the cause that stopped the
// operation, plus the other sources that also failed, in deterministic order.
// [errors.Is] and [errors.As] traverse all of them.
type SourceErrors = fault.SourceErrors

// Stable classification codes. These appear in JSON results and map onto the
// documented CLI exit codes.
const (
	CodeInvalidInput       = fault.CodeInvalidInput
	CodeUnsupportedVersion = fault.CodeUnsupportedVersion
	CodeUnsupportedSource  = fault.CodeUnsupportedSource
	CodeSourceResolution   = fault.CodeSourceResolution
	CodeStaleLock          = fault.CodeStaleLock
	CodeUnsafePath         = fault.CodeUnsafePath
	CodeUnsupportedFile    = fault.CodeUnsupportedFile
	CodePathCollision      = fault.CodePathCollision
	CodeLimitExceeded      = fault.CodeLimitExceeded
	CodeDigestMismatch     = fault.CodeDigestMismatch
	CodeInvalidArtifact    = fault.CodeInvalidArtifact
	CodeAuthentication     = fault.CodeAuthentication
	CodeAuthorization      = fault.CodeAuthorization
	CodeTransport          = fault.CodeTransport
	CodeEvidenceInvalid    = fault.CodeEvidenceInvalid
	CodePolicyFailed       = fault.CodePolicyFailed
	CodeDestinationExists  = fault.CodeDestinationExists
	CodeTimeout            = fault.CodeTimeout
	CodeCanceled           = fault.CodeCanceled
	CodeInternal           = fault.CodeInternal
)

// IsTransient reports whether err may succeed on a later attempt.
//
// It is advisory for callers deciding whether to retry. DevProof's own
// retries are governed by its bounded retry policy, not by this function, and
// a caller that retries a non-transient failure will simply fail identically:
// a digest mismatch, a policy failure, and an authentication denial are all
// permanent for a given input.
func IsTransient(err error) bool { return fault.IsTransient(err) }

// Limits bounds the resources one operation may consume. A zero field
// inherits the documented default; zero never means unlimited.
//
// Limits supplied by the client, by a request, and by a verification policy
// are intersected, so any of them may tighten a bound and none may relax one.
type Limits = bundle.Limits

// DefaultLimits returns the documented default resource bounds.
func DefaultLimits() Limits { return bundle.DefaultLimits() }
