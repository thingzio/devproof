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

// Package fault is DevProof's typed error model.
//
// It is public because the extension points are. A custom [source.Resolver],
// transport, or attester returns errors into the same pipeline the built-in
// ones do, and an error that is not an [Error] classifies as [CodeInternal] --
// exit 10, "unexpected internal error". An extension that could not construct
// a classified error would report every ordinary failure, a missing file or a
// refused credential, as a bug in DevProof. [New] and [Wrap] exist so it can.
//
// Named "fault" rather than "errors" so that a call site needing both this and
// the standard library does not have to rename one of them, which is most call
// sites.
//
// The root devproof package aliases [Error] and [Code], so callers who only
// consume the SDK never need to import this package directly.
//
// A Code doubles as a sentinel, so callers match on classification without
// constructing a comparison value:
//
//	if errors.Is(err, devproof.CodeStaleLock) { ... }
//
// Codes are a compatibility surface. Messages are not: they are written for a
// human deciding what to do next, and may be reworded freely. Nothing should
// parse them.
package fault

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// Code classifies a failure. It implements error so that it can be used as an
// errors.Is target directly.
type Code string

// Error lets a Code act as a sentinel target for errors.Is. A bare Code is
// never returned as an operation's error; it carries no context.
func (c Code) Error() string { return string(c) }

// Stable classification codes. These appear in JSON results and map onto CLI
// exit codes (DP-023); neither the set nor the spellings may change without a
// compatibility decision.
const (
	// CodeInvalidInput covers malformed arguments, manifests, locks, and
	// policies: input that is wrong regardless of the state of the world.
	CodeInvalidInput Code = "invalid-input"
	// CodeUnsupportedVersion covers a known document or format kind at a
	// version this build cannot process. Distinct from CodeInvalidInput
	// because the input may be perfectly valid for a newer reader.
	CodeUnsupportedVersion Code = "unsupported-version"
	// CodeUnsupportedSource covers a source type with no registered resolver.
	CodeUnsupportedSource Code = "unsupported-source"
	// CodeSourceResolution covers a resolver failing to obtain its material.
	CodeSourceResolution Code = "source-resolution"
	// CodeStaleLock covers resolved material disagreeing with the lock.
	CodeStaleLock Code = "stale-lock"
	// CodeUnsafePath covers a path that escapes its root, aliases another
	// path, or is not representable in the portable profile.
	CodeUnsafePath Code = "unsafe-path"
	// CodeUnsupportedFile covers a file type the portable profile rejects:
	// links, devices, sockets, FIFOs.
	CodeUnsupportedFile Code = "unsupported-file"
	// CodePathCollision covers two sources claiming one final path.
	CodePathCollision Code = "path-collision"
	// CodeLimitExceeded covers any configured resource bound being crossed.
	CodeLimitExceeded Code = "limit-exceeded"
	// CodeDigestMismatch covers content not matching its descriptor,
	// inventory, or recomputed tree digest.
	CodeDigestMismatch Code = "digest-mismatch"
	// CodeInvalidArtifact covers a structurally invalid bundle: wrong media
	// types, wrong cardinality, inconsistent config.
	CodeInvalidArtifact Code = "invalid-artifact"
	// CodeAuthentication covers a rejected or absent credential.
	CodeAuthentication Code = "authentication"
	// CodeAuthorization covers an authenticated identity lacking permission.
	CodeAuthorization Code = "authorization"
	// CodeTransport covers network and registry failures that are not
	// specifically authentication, authorization, or timeout.
	CodeTransport Code = "transport"
	// CodeEvidenceInvalid covers evidence that is absent, malformed, or fails
	// cryptographic verification.
	CodeEvidenceInvalid Code = "evidence-invalid"
	// CodePolicyFailed covers verified facts not satisfying the policy.
	CodePolicyFailed Code = "policy-failed"

	// CodeSemanticsFailed reports that a caller-supplied validator rejected
	// the payload. The artifact is intact and may be perfectly trusted; its
	// content is not what the caller requires.
	CodeSemanticsFailed Code = "semantics-failed"
	// CodeDestinationExists covers an expansion destination already present.
	CodeDestinationExists Code = "destination-exists"
	// CodeTimeout covers an operation exceeding its deadline.
	CodeTimeout Code = "timeout"
	// CodeCanceled covers deliberate cancellation. Never transient: a Ctrl-C
	// must not re-enter a retry loop.
	CodeCanceled Code = "canceled"
	// CodeInternal covers a broken invariant. Reaching it is a bug.
	CodeInternal Code = "internal"
)

// allCodes enumerates every declared Code.
//
// It must be kept in sync with the const block above; it sits directly below
// it so the two are edited together. TestExitCodesAreTotal asserts that every
// entry has an exit-code mapping and that the two sets are the same size, so
// adding a code without deciding how the CLI reports it fails the suite.
var allCodes = []Code{
	CodeInvalidInput,
	CodeUnsupportedVersion,
	CodeUnsupportedSource,
	CodeSourceResolution,
	CodeStaleLock,
	CodeUnsafePath,
	CodeUnsupportedFile,
	CodePathCollision,
	CodeLimitExceeded,
	CodeDigestMismatch,
	CodeInvalidArtifact,
	CodeAuthentication,
	CodeAuthorization,
	CodeTransport,
	CodeEvidenceInvalid,
	CodePolicyFailed,
	CodeSemanticsFailed,
	CodeDestinationExists,
	CodeTimeout,
	CodeCanceled,
	CodeInternal,
}

// Error is the error every DevProof operation returns.
//
// Op, Source, and Path are optional context. They exist so that a caller can
// report which source or canonical path failed without parsing a message.
type Error struct {
	// Code classifies the failure.
	Code Code
	// Op names the operation, such as "build" or "source.resolve".
	Op string
	// Source names the logical source involved, when one is.
	Source string
	// Path names the canonical path involved, when one is. It is a
	// bundle-relative path, never a host absolute path.
	Path string
	// Msg explains the failure and the next action. Not a stable API.
	Msg string
	// Temporary advises callers that a retry may succeed. It is advisory
	// only; the SDK's own retries are governed by its bounded retry policy,
	// not by this field.
	Temporary bool
	// Err is the wrapped cause, if any.
	Err error
}

// New builds an Error with no wrapped cause.
func New(code Code, op, msg string) *Error {
	return &Error{Code: code, Op: op, Msg: msg}
}

// Wrap builds an Error around a cause. It returns nil when err is nil, so it
// is safe in a `return Wrap(...)` position guarded by an earlier check.
func Wrap(code Code, op, msg string, err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Code: code, Op: op, Msg: msg, Err: err}
}

// WithSource returns a copy tagged with a logical source name.
func (e *Error) WithSource(name string) *Error {
	if e == nil {
		return nil
	}
	out := *e
	out.Source = name
	return &out
}

// WithPath returns a copy tagged with a canonical bundle path.
func (e *Error) WithPath(p string) *Error {
	if e == nil {
		return nil
	}
	out := *e
	out.Path = p
	return &out
}

// AsTemporary returns a copy marked retryable.
func (e *Error) AsTemporary() *Error {
	if e == nil {
		return nil
	}
	out := *e
	out.Temporary = true
	return &out
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteByte('[')
	b.WriteString(string(e.Code))
	b.WriteByte(']')
	if e.Op != "" {
		b.WriteByte(' ')
		b.WriteString(e.Op)
		b.WriteByte(':')
	}
	if e.Msg != "" {
		b.WriteByte(' ')
		b.WriteString(e.Msg)
	}
	if e.Source != "" {
		fmt.Fprintf(&b, " (source %s)", e.Source)
	}
	if e.Path != "" {
		fmt.Fprintf(&b, " (path %s)", e.Path)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is this Error's Code, which is what makes
// errors.Is(err, CodeStaleLock) work.
func (e *Error) Is(target error) bool {
	c, ok := target.(Code)
	return ok && c == e.Code
}

// SourceErrors reports a multi-source failure: one primary cause plus the
// other sources that also failed.
//
// Primary is the failure that stopped the operation. Additional preserves the
// rest in deterministic source-name order so that two runs of the same broken
// manifest report the same thing.
type SourceErrors struct {
	Primary    error
	Additional []error
}

func (e *SourceErrors) Error() string {
	if len(e.Additional) == 0 {
		return e.Primary.Error()
	}
	return fmt.Sprintf("%s (and %d more source failures)", e.Primary, len(e.Additional))
}

// Unwrap returns every contained error so that errors.Is and errors.As
// traverse the additional failures as well as the primary one.
func (e *SourceErrors) Unwrap() []error {
	out := make([]error, 0, len(e.Additional)+1)
	out = append(out, e.Primary)
	out = append(out, e.Additional...)
	return out
}

// CodeOf reports the classification of err, or CodeInternal when err carries
// no DevProof code. An unclassified error reaching a boundary is a bug, and
// CodeInternal is the honest answer rather than a guess.
//
// CodeOf returns the empty Code for a nil error.
func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	if e, ok := stderrors.AsType[*Error](err); ok {
		return e.Code
	}
	if c, ok := stderrors.AsType[Code](err); ok {
		return c
	}
	return CodeInternal
}

// AsError extracts the typed Error from an error chain.
//
// It exists so that callers can add context — a source name, a path — to an
// error raised deeper down, without reconstructing it and losing the cause.
func AsError(err error) (*Error, bool) {
	return stderrors.AsType[*Error](err)
}
