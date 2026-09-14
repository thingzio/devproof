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
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/internal/semantic"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/policy"
)

// validating reports whether any validator was supplied.
//
// Every semantic cost is behind this. A client with no validators does exactly
// what it did before the dimension existed: nothing is materialized and
// semantics reports not-evaluated.
func (c *Client) validating() bool { return len(c.validators) > 0 }

// semanticSubject is what verification established, handed to a validator so
// it does not re-derive any of it.
func semanticSubject(subject *canonical.Subject) semantic.Subject {
	return semantic.Subject{
		Digest:     subject.ManifestDigest.String(),
		TreeDigest: subject.TreeDigest.String(),
		Format:     subject.Config.Format.String(),
		Files:      subject.Config.Files,
	}
}

// applyVerdict records a validation outcome on a report.
func applyVerdict(report *policy.Report, status policy.Status,
	records []policy.Record, findings []policy.Finding) {

	report.Semantics = status
	report.Validators = records
	for _, finding := range findings {
		report.AddFinding(finding)
	}
}

// runValidators answers the semantics dimension for a verification.
//
// A no-op when no validator was supplied, which keeps the cost of the third
// dimension exactly zero for callers who did not ask for it.
func (c *Client) runValidators(
	ctx context.Context,
	pinned artifact.Reference,
	subject *canonical.Subject,
	limits bundle.Resolved,
	report *policy.Report,
) error {

	if !c.validating() {
		return nil
	}
	transport, err := c.transportFor(pinned)
	if err != nil {
		return err
	}
	return c.validatePayload(ctx, transport, pinned, subject, limits.Limits, report)
}

// validatePayload materializes a verified payload and runs every validator
// over it.
//
// The payload is expanded into a private directory that is removed before this
// returns. `verify` writes nothing a caller can see, and that stays true: a
// validator needs the content on disk, and the caller asked for validation, not
// for an expansion.
//
// Extraction rather than a second verification pass: safefs.Extract already
// checks every entry against the inventory and the compressed stream against
// its descriptor, so materializing here establishes integrity at the same time
// rather than in addition.
func (c *Client) validatePayload(
	ctx context.Context,
	transport artifact.Transport,
	pinned artifact.Reference,
	subject *canonical.Subject,
	limits bundle.Limits,
	report *policy.Report,
) (retErr error) {

	staging, err := os.MkdirTemp(c.tempRoot, "devproof-validate-")
	if err != nil {
		return fault.Wrap(fault.CodeInternal, "verify",
			"creating a directory to validate in", err)
	}
	// Extract publishes with an exclusive rename into a path that must not
	// exist, so it is handed a name inside the directory rather than the
	// directory itself.
	destination := filepath.Join(staging, "payload")
	defer func() {
		if removeErr := os.RemoveAll(staging); removeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, "verify",
				"removing the validation directory", removeErr)
		}
	}()

	layer, err := transport.Fetch(ctx, pinned, subject.LayerDescriptor())
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := layer.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, "verify", "closing the layer blob", closeErr)
		}
	}()

	if _, err := safefs.Extract(ctx, layer, safefs.ExtractOptions{
		Destination: destination,
		Config:      subject.Config,
		Limits:      limits,
		LayerDigest: subject.LayerDigest,
		LayerSize:   subject.LayerSize,
	}); err != nil {
		return err
	}

	status, records, findings := semantic.Run(ctx, c.validators,
		os.DirFS(destination), semanticSubject(subject))
	applyVerdict(report, status, records, findings)
	return nil
}

// validateStaged returns the hook that judges an expansion before it is
// published.
//
// Returning an error from the hook is what makes a semantic failure leave
// nothing behind. The report is filled in either way, so a caller that
// tolerates the failure still learns what every validator concluded.
func (c *Client) validateStaged(
	ctx context.Context,
	subject *canonical.Subject,
	report *policy.Report,
) func(fs.FS) error {

	if !c.validating() {
		return nil
	}
	return func(payload fs.FS) error {
		status, records, findings := semantic.Run(ctx, c.validators,
			payload, semanticSubject(subject))
		applyVerdict(report, status, records, findings)

		if status == policy.StatusFail {
			return fault.New(fault.CodeSemanticsFailed, "expand",
				"a validator rejected the payload, so nothing was written").
				WithPath(report.SubjectDigest)
		}
		return nil
	}
}
