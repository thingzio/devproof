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

// Package semantic decides whether a verified payload means what a consumer
// requires.
//
// It is the third verification dimension. Integrity asks whether the bytes
// survived and trust asks who vouched for them; both are answered by DevProof
// itself, because both are questions about the artifact. Whether the content
// is *correct* is a question about a domain, and DevProof has none — so it is
// answered by code the embedding application supplies.
//
// This package is internal on purpose (DP-026). A public interface is a
// permanent compatibility obligation, and two real validators are needed before
// the shape can be trusted. Being internal is what makes the seam honest rather
// than cosmetic: nothing outside this module can name these types, so the
// interface cannot acquire external implementers before it is ready for them.
//
// Nothing here is discovered from an artifact. A bundle cannot name its own
// validator any more than it can name the policy that judges it — an attacker
// who controlled the artifact would otherwise control the rules applied to it.
package semantic

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/policy"
)

// Validator decides whether a verified payload is valid for the caller's use.
//
// Implementations are compiled into the embedding application. They receive a
// context, a read-only view of the payload, and what verification already
// established — and no capability belonging to DevProof: no transport, no
// credential provider, no writable path. That is a statement about what the
// SDK hands over, not a sandbox: a validator is ordinary in-process Go code and
// can do whatever the application it lives in can do. What it cannot do is
// reach the registry DevProof was talking to, or the credentials it used.
type Validator interface {
	// Name identifies the validator in results, because a report has to name
	// what judged it. Stable across runs.
	Name() string

	// Validate examines the payload and reports what it found.
	//
	// Returning an error means the validator could not reach a conclusion,
	// which is a failure rather than an absence: see [Run].
	Validate(ctx context.Context, payload fs.FS, subject Subject) (*Verdict, error)
}

// Subject is what verification established before a validator ran.
//
// It carries the inventory because the most useful validators — is every
// required component present, is the set complete, does any path look wrong —
// need paths and digests and never open a file. A validator that needs only
// this should not pay for reading content.
type Subject struct {
	// Digest is the OCI subject digest: the artifact's identity.
	Digest string
	// TreeDigest is the payload's identity, independent of encoding.
	TreeDigest string
	// Format is the bundle format version that was read.
	Format string
	// Files is the verified inventory: path, mode, size, content digest.
	//
	// The config's own shape, with plain strings rather than the internal
	// typed path and digest. A validator should not need to learn this
	// module's type aliases to read a file list.
	Files []bundle.ConfigFile
}

// Verdict is what one validator concluded.
//
// An empty verdict is a pass. A validator that finds nothing wrong says so by
// returning no findings, rather than by returning a status — there is one
// place that decides what a set of findings means, and it is [Run].
type Verdict struct {
	Findings []Finding
}

// Finding is one thing a validator concluded about the payload.
//
// Rule is the validator's own identifier for the check, not a global one. [Run]
// namespaces it, so two validators may both have a "missing-component" rule
// without colliding in a report.
type Finding struct {
	Rule     string
	Severity policy.Severity
	Path     string
	Message  string
}

// Run executes every validator and decides what their findings mean.
//
// The fail-closed rules live here rather than in each validator, so that a
// validator cannot decide it is allowed to pass:
//
//   - no validators is not-evaluated, which is never a pass (DP-014);
//   - an error-severity finding is a failure;
//   - a validator returning an error is a failure, not an absence. "Nobody
//     looked" and "somebody looked and could not finish" are different facts,
//     and conflating them makes a broken validator indistinguishable from a
//     missing one — which is how a gate becomes decorative;
//   - a validator that panics is a failure, recovered. A validator is
//     third-party code running inside a verification, and a panic that killed
//     the process would turn a content check into a denial of service against
//     the tool that invoked it.
//
// Every validator runs even after one fails, because a consumer fixing content
// wants the whole list rather than one item at a time — the same reason policy
// evaluation reports every finding.
func Run(
	ctx context.Context,
	validators []Validator,
	payload fs.FS,
	subject Subject,
) (policy.Status, []policy.Record, []policy.Finding) {

	if len(validators) == 0 {
		return policy.StatusNotEvaluated, nil, nil
	}

	status := policy.StatusPass
	records := make([]policy.Record, 0, len(validators))
	var findings []policy.Finding

	for _, validator := range validators {
		name := validator.Name()
		verdict, err := runOne(ctx, validator, payload, subject)

		outcome := policy.StatusPass
		if err != nil {
			outcome = policy.StatusFail
			findings = append(findings, policy.Finding{
				Code:     policy.FindingSemanticsInvalid,
				Rule:     ruleName(name, "validator"),
				Severity: policy.SeverityError,
				Subject:  subject.Digest,
				Message:  fmt.Sprintf("validator %q could not reach a conclusion: %v", name, err),
			})
		}
		for _, finding := range verdict.Findings {
			if finding.Severity == policy.SeverityError {
				outcome = policy.StatusFail
			}
			findings = append(findings, policy.Finding{
				Code:     policy.FindingSemanticsInvalid,
				Rule:     ruleName(name, finding.Rule),
				Severity: finding.Severity,
				Subject:  finding.Path,
				Message:  finding.Message,
			})
		}

		if outcome == policy.StatusFail {
			status = policy.StatusFail
		}
		records = append(records, policy.Record{Name: name, Status: outcome})
	}

	return status, records, findings
}

// runOne calls a validator, converting a panic into an error.
//
// The returned verdict is never nil, so a caller cannot dereference one after
// an error it decided to tolerate.
func runOne(
	ctx context.Context,
	validator Validator,
	payload fs.FS,
	subject Subject,
) (verdict *Verdict, err error) {

	defer func() {
		if recovered := recover(); recovered != nil {
			verdict = &Verdict{}
			err = fmt.Errorf("validator panicked: %v", recovered)
		}
	}()

	verdict, err = validator.Validate(ctx, payload, subject)
	if verdict == nil {
		verdict = &Verdict{}
	}
	return verdict, err
}

// ruleName namespaces a validator's rule so a reader can tell a content
// finding from a trust finding without consulting a table.
func ruleName(validator, rule string) string {
	if rule == "" {
		rule = "unnamed"
	}
	return "semantics/" + validator + "/" + rule
}
