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
	"net"
	"strings"
)

// retryableCodes are the classifications a bounded retry may act on.
//
// The set is deliberately short. Everything absent from it is either a
// deterministic rejection that will fail identically on the next attempt, or a
// safety decision that must not be worn down by repetition: an authentication
// denial, a digest mismatch, a policy failure, and unsafe content are all
// permanent for a given input.
var retryableCodes = map[Code]bool{
	CodeTimeout:   true,
	CodeTransport: true,
}

// IsTransient reports whether err may succeed on a later attempt.
//
// Cancellation is never transient even though it interrupts work the same way
// a timeout does: a timeout is an environmental fault worth retrying, and a
// cancellation is an instruction to stop.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, context.Canceled) {
		return false
	}
	if e, ok := stderrors.AsType[*Error](err); ok {
		if e.Code == CodeCanceled {
			return false
		}
		if e.Temporary {
			return true
		}
		return retryableCodes[e.Code]
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return IsNetwork(err)
}

// networkErrStrings match network failures that arrive as opaque wrapped
// strings. Typed checks run first; this is the fallback for errors that lost
// their type crossing a library boundary.
var networkErrStrings = []string{
	"connection refused",
	"connection reset by peer",
	"no such host",
	"network is unreachable",
	"host is unreachable",
	"tls handshake timeout",
	"unexpected eof",
	"broken pipe",
	"i/o timeout",
	"server misbehaving",
}

// IsNetwork reports whether err indicates a network-level connectivity
// problem: DNS resolution, dial, or TLS handshake.
//
// It deliberately does not match context.DeadlineExceeded or context.Canceled.
// Those are application-level control flow, and conflating them with network
// faults makes a deadline look like an infrastructure outage.
func IsNetwork(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, context.Canceled) || stderrors.Is(err, context.DeadlineExceeded) {
		return false
	}

	if _, ok := stderrors.AsType[*net.DNSError](err); ok {
		return true
	}
	if _, ok := stderrors.AsType[*net.OpError](err); ok {
		return true
	}
	if _, ok := stderrors.AsType[net.Error](err); ok {
		return true
	}

	msg := strings.ToLower(err.Error())
	for _, s := range networkErrStrings {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// FromContext converts a context error into a typed Error, distinguishing a
// deadline from a cancellation. It returns nil when ctx is still live, so it
// reads naturally as a cancellation checkpoint between units of work:
//
//	if err := fault.FromContext(ctx, "expand", "extraction canceled"); err != nil {
//	    return err
//	}
func FromContext(ctx context.Context, op, msg string) error {
	err := ctx.Err()
	switch {
	case err == nil:
		return nil
	case stderrors.Is(err, context.DeadlineExceeded):
		return Wrap(CodeTimeout, op, msg, err)
	default:
		return Wrap(CodeCanceled, op, msg, err)
	}
}
