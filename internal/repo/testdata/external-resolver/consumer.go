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

package external

// This file is the external consumer fixture.
//
// It names every operation an embedding application reaches for and every
// request and result field it would set, from a module that can see only the
// public surface. Compiling is the whole assertion: a renamed method, a
// removed field, a request type that quietly started requiring something, or a
// result field that changed type all fail here, in the one place inside this
// repository that is subject to the same rules an outside caller is.
//
// It is not an API-compatibility gate. Before 1.0 a minor version may break
// this on purpose, and the correct response is to update it in the same commit
// as the break -- which is the point: the break becomes visible and deliberate
// rather than discovered by somebody else.

import (
	"context"
	"time"

	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/conformance"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/policy"
)

// Embed exercises the client facade an application depends on.
func Embed(ctx context.Context) error {
	client, err := devproof.New(
		devproof.WithResolver(&Resolver{}),
		devproof.WithLimits(devproof.Limits{MaxFiles: 1000}),
		devproof.WithOffline(),
	)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Lock(ctx, devproof.LockRequest{
		SpecPath: "devproof.yaml",
		Check:    true,
	}); err != nil {
		return err
	}

	built, err := client.Build(ctx, devproof.BuildRequest{
		SpecPath:    "devproof.yaml",
		SourcePath:  "./content",
		MountPath:   "app",
		Include:     []string{"**"},
		Exclude:     []string{"**/*.tmp"},
		Destination: "oci-layout://./artifact",
		Tag:         "v1",
		Attest:      true,
	})
	if err != nil {
		return err
	}

	report, err := client.Verify(ctx, devproof.VerifyRequest{
		Reference:     built.Reference,
		PolicyPath:    "policy.yaml",
		RequireDigest: true,
	})
	if err != nil {
		return err
	}
	useReport(report)

	if _, err := client.Expand(ctx, devproof.ExpandRequest{
		Reference:   built.Reference,
		Destination: "./expanded",
	}); err != nil {
		return err
	}
	if _, err := client.Diff(ctx, devproof.DiffRequest{
		From: built.Reference,
		To:   "./content",
	}); err != nil {
		return err
	}
	if _, err := client.Copy(ctx, devproof.CopyRequest{
		Source:      built.Reference,
		Destination: "oci-layout://./mirror",
	}); err != nil {
		return err
	}
	if _, err := client.Inspect(ctx, devproof.InspectRequest{
		Reference: built.Reference,
		Files:     true,
		Evidence:  true,
	}); err != nil {
		return err
	}
	return nil
}

// useReport reads the result fields a consumer makes decisions on.
func useReport(report *policy.Report) {
	_ = report.OK()
	_ = report.Integrity == policy.StatusPass
	_ = report.Trust == policy.StatusNotEvaluated
	_ = report.Semantics
	_ = report.SubjectDigest
	_ = report.TreeDigest
	_ = report.AcceptedIdentities
	_ = report.TrustRoots
	_ = report.EvaluatedAt

	for _, item := range report.AcceptedEvidence {
		_ = item.Digest
		_ = item.PredicateType
		_ = item.TransparencyLogVerified
		_ = item.IntegratedTime
	}
	for _, limit := range report.Limits {
		_ = limit.Name + limit.Origin
		_ = limit.Value
	}
	for _, finding := range report.Findings {
		_ = finding.Code + finding.Rule + finding.Message
		_ = finding.Severity == policy.SeverityError
	}
}

// Author writes the documents a consumer authors, and reads the ones it is
// given.
func Author() error {
	template, err := bundle.Template("./content")
	if err != nil {
		return err
	}
	spec, err := bundle.ParseSpec(template)
	if err != nil {
		return err
	}
	_ = spec.Metadata.Name
	for _, source := range spec.Spec.Sources {
		_ = source.Name + source.Type + source.MountPath
	}

	doc, err := policy.ParseDocument(nil)
	if err == nil {
		_ = doc.Spec.Evidence.MaxAge
		_ = doc.Spec.Signatures.Threshold
		_ = doc.Spec.Provenance.RequireLockDigest
	}

	// Typed errors are the contract a caller branches on, not message text.
	_ = fault.CodeOf(err) == fault.CodeInvalidInput
	_ = fault.ExitPolicy

	_ = bundle.MediaTypeArtifactV1
	_ = artifact.SchemeLayout
	_ = evidence.StatementType
	return nil
}

// Check reads an artifact with the independent conformance implementation.
func Check(dir string) error {
	report, err := conformance.VerifyLayout(dir, "v1", conformance.LevelCanonical)
	if err != nil {
		return err
	}
	_ = report.Level == conformance.LevelBytes
	_ = report.Deviations
	_ = report.FileCount
	_ = time.Now()
	return nil
}
