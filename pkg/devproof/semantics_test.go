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

package devproof_test

import (
	"context"
	stderrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/semantic"
	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/policy"
)

// stubValidator is a validator whose verdict a test dictates.
type stubValidator struct {
	name     string
	findings []semantic.Finding
	err      error
	panics   bool
	// saw records what the validator was handed, so a test can assert the
	// payload really was readable rather than assuming it.
	saw *stubObservation
}

type stubObservation struct {
	files      []string
	content    string
	subject    semantic.Subject
	invocation int
}

func (v *stubValidator) Name() string { return v.name }

func (v *stubValidator) Validate(
	_ context.Context,
	payload fs.FS,
	subject semantic.Subject,
) (*semantic.Verdict, error) {

	if v.panics {
		panic("this validator is broken")
	}
	if v.saw != nil {
		v.saw.invocation++
		v.saw.subject = subject
		_ = fs.WalkDir(payload, ".", func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			v.saw.files = append(v.saw.files, path)
			if file, openErr := payload.Open(path); openErr == nil {
				data, _ := io.ReadAll(file)
				v.saw.content += string(data)
				_ = file.Close()
			}
			return nil
		})
	}
	if v.err != nil {
		return nil, v.err
	}
	return &semantic.Verdict{Findings: v.findings}, nil
}

func rejecting(name, message string) *stubValidator {
	return &stubValidator{name: name, findings: []semantic.Finding{{
		Rule: "content", Severity: policy.SeverityError, Message: message,
	}}}
}

// TestSemanticsIsNotEvaluatedWithoutAValidator pins the default.
//
// The dimension costs nothing when nobody asked for it, and reports the one
// answer that is never mistaken for a pass.
func TestSemanticsIsNotEvaluatedWithoutAValidator(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Semantics != policy.StatusNotEvaluated {
		t.Errorf("semantics = %s, want not-evaluated", report.Semantics)
	}
	if len(report.Validators) != 0 {
		t.Errorf("a client with no validators reported %d", len(report.Validators))
	}
}

// TestValidatorSeesTheVerifiedPayload is the contract a validator is written
// against.
func TestValidatorSeesTheVerifiedPayload(t *testing.T) {
	t.Parallel()

	seen := &stubObservation{}
	validator := &stubValidator{name: "inspector", saw: seen}

	client := newClient(t, devproof.WithValidator(validator))
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if report.Semantics != policy.StatusPass {
		t.Errorf("semantics = %s, want pass: %v", report.Semantics, report.Findings)
	}
	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %s; materializing must still establish it", report.Integrity)
	}
	if len(report.Validators) != 1 || report.Validators[0].Name != "inspector" {
		t.Errorf("validators = %+v, want one named inspector", report.Validators)
	}
	if seen.invocation != 1 {
		t.Errorf("the validator ran %d times, want 1", seen.invocation)
	}
	if len(seen.files) == 0 {
		t.Error("the validator was handed an empty filesystem")
	}
	if seen.content == "" {
		t.Error("the validator could not read file content")
	}
	if seen.subject.Digest != built.SubjectDigest {
		t.Errorf("subject digest = %q, want %q", seen.subject.Digest, built.SubjectDigest)
	}
	if len(seen.subject.Files) != len(seen.files) {
		t.Errorf("the inventory lists %d files and the payload held %d",
			len(seen.subject.Files), len(seen.files))
	}
}

// TestVerifyLeavesNothingBehind keeps validation from turning verify into an
// expansion.
//
// The payload has to reach disk for a validator to read it. What must not
// happen is that any of it survives, or that a caller has to know where it
// went.
func TestVerifyLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	client := newClient(t,
		devproof.WithTempRoot(temp),
		devproof.WithValidator(&stubValidator{name: "inspector"}),
	)
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	entries, err := os.ReadDir(temp)
	if err != nil {
		t.Fatalf("reading the temp root: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "devproof-validate-") {
			t.Errorf("validation left %s behind", entry.Name())
		}
	}
}

// TestSemanticFailureModes covers every way a validator can fail to say yes.
//
// The distinction that matters is between "nobody looked" and "somebody looked
// and could not finish". Reporting the second as not-evaluated would make a
// broken validator indistinguishable from an absent one, which is how a gate
// becomes decorative.
func TestSemanticFailureModes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		validator *stubValidator
	}{
		{"an error finding", rejecting("strict", "this payload is wrong")},
		{"a validator that errors", &stubValidator{
			name: "broken", err: stderrors.New("could not read the schema"),
		}},
		{"a validator that panics", &stubValidator{name: "crasher", panics: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := newClient(t, devproof.WithValidator(tc.validator))
			layout := filepath.Join(t.TempDir(), "layout")
			built, err := client.Build(t.Context(), devproof.BuildRequest{
				SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			report, err := client.Verify(t.Context(), devproof.VerifyRequest{
				Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if report.Semantics != policy.StatusFail {
				t.Errorf("semantics = %s, want fail", report.Semantics)
			}
			if report.OK() {
				t.Error("a report with a failed dimension reports OK")
			}
			if !hasCode(report, policy.FindingSemanticsInvalid) {
				t.Errorf("no semantics finding was recorded: %v", report.Findings)
			}
		})
	}
}

// TestAWarningIsNotAFailure keeps severity meaningful.
func TestAWarningIsNotAFailure(t *testing.T) {
	t.Parallel()

	validator := &stubValidator{name: "advisory", findings: []semantic.Finding{{
		Rule: "style", Severity: policy.SeverityWarning, Message: "unconventional layout",
	}}}

	client := newClient(t, devproof.WithValidator(validator))
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Semantics != policy.StatusPass {
		t.Errorf("semantics = %s; a warning is not a failure", report.Semantics)
	}
	if !hasCode(report, policy.FindingSemanticsInvalid) {
		t.Error("the warning was not reported at all")
	}
}

// TestEveryValidatorRuns covers composition.
//
// A consumer fixing content wants the whole list, not one item per run, so a
// failure does not stop the ones after it.
func TestEveryValidatorRuns(t *testing.T) {
	t.Parallel()

	second := &stubObservation{}
	client := newClient(t,
		devproof.WithValidator(rejecting("first", "no")),
		devproof.WithValidator(&stubValidator{name: "second", saw: second}),
	)
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layout + "@" + built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if second.invocation != 1 {
		t.Error("a failing validator stopped the ones after it")
	}
	if len(report.Validators) != 2 {
		t.Fatalf("validators = %+v, want two", report.Validators)
	}
	failed, passed := report.Validators[0].Status, report.Validators[1].Status
	if failed != policy.StatusFail || passed != policy.StatusPass {
		t.Errorf("per-validator status is wrong: %+v", report.Validators)
	}
	if report.Semantics != policy.StatusFail {
		t.Error("one failure must fail the dimension")
	}
}

// TestRejectedExpansionWritesNothing is the guarantee that makes this usable
// as a gate.
//
// Not written and then removed. Content that briefly existed has already been
// readable by anything watching the directory, so cleaning up afterwards is a
// weaker promise than never having written it (DP-032).
func TestRejectedExpansionWritesNothing(t *testing.T) {
	t.Parallel()

	client := newClient(t, devproof.WithValidator(rejecting("strict", "wrong content")))
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "expanded")
	_, err = client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   "oci-layout://" + layout + "@" + built.SubjectDigest,
		Destination: destination,
	})
	if err == nil {
		t.Fatal("a rejected payload was expanded")
	}
	if !stderrors.Is(err, fault.CodeSemanticsFailed) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeSemanticsFailed)
	}
	if got := fault.ExitCode(err, false); got != fault.ExitSemantics {
		t.Errorf("exit = %d, want %d", got, fault.ExitSemantics)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Errorf("the destination exists after a rejected expansion: %v", statErr)
	}
}

// TestAcceptedExpansionPublishes guards the other direction.
func TestAcceptedExpansionPublishes(t *testing.T) {
	t.Parallel()

	client := newClient(t, devproof.WithValidator(&stubValidator{name: "permissive"}))
	layout := filepath.Join(t.TempDir(), "layout")
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), Destination: "oci-layout://" + layout,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "expanded")
	result, err := client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   "oci-layout://" + layout + "@" + built.SubjectDigest,
		Destination: destination,
	})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if result.Verification.Semantics != policy.StatusPass {
		t.Errorf("semantics = %s, want pass", result.Verification.Semantics)
	}
	if _, statErr := os.Stat(destination); statErr != nil {
		t.Errorf("an accepted expansion published nothing: %v", statErr)
	}
}

// TestValidatorMustBeUsable rejects a client that could not report what judged
// it.
func TestValidatorMustBeUsable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opt  devproof.Option
	}{
		{"nil validator", devproof.WithValidator(nil)},
		{"unnamed validator", devproof.WithValidator(&stubValidator{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, err := devproof.New(tc.opt)
			if err == nil {
				_ = client.Close()
				t.Error("an unusable validator was accepted")
			}
		})
	}
}

func hasCode(report *policy.Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
