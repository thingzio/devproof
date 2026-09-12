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

package bundle

import (
	stderrors "errors"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

// Every bound must appear in the table exactly once. A bound declared in the
// const block but missing from boundFields would silently default to zero,
// which WithDefaults would then leave at zero, which means "unlimited" to
// every caller that reads it.
func TestBoundTableIsComplete(t *testing.T) {
	t.Parallel()

	const lastBound = BoundMaxParallelSources

	if got, want := len(boundFields), int(lastBound)+1; got != want {
		t.Fatalf("boundFields has %d entries, %d bounds are declared", got, want)
	}

	seen := make(map[Bound]bool, len(boundFields))
	for _, f := range boundFields {
		if seen[f.bound] {
			t.Errorf("bound %s appears twice", f.name)
		}
		seen[f.bound] = true
		if f.name == "" {
			t.Errorf("bound %d has no name", f.bound)
		}
		if f.def <= 0 {
			t.Errorf("bound %s has a non-positive default %d", f.name, f.def)
		}
		if f.def > f.ceiling {
			t.Errorf("bound %s default %d exceeds its ceiling %d", f.name, f.def, f.ceiling)
		}
	}
	for b := Bound(0); b <= lastBound; b++ {
		if !seen[b] {
			t.Errorf("bound %d is declared but missing from boundFields", b)
		}
	}
}

// Zero must never survive as "unlimited". An unbounded extraction is exactly
// the decompression-bomb case.
func TestWithDefaultsFillsEveryUnsetBound(t *testing.T) {
	t.Parallel()

	got := Limits{}.WithDefaults()

	for _, f := range boundFields {
		if v := *f.get(&got); v <= 0 {
			t.Errorf("%s = %d after WithDefaults, want a positive default", f.name, v)
		}
	}
}

func TestWithDefaultsPreservesExplicitValues(t *testing.T) {
	t.Parallel()

	got := Limits{MaxFiles: 7}.WithDefaults()

	if got.MaxFiles != 7 {
		t.Errorf("MaxFiles = %d, want the explicitly supplied 7", got.MaxFiles)
	}
	if got.MaxExpandedBytes != DefaultLimits().MaxExpandedBytes {
		t.Error("an unset bound was not defaulted")
	}
}

func TestDefaultsAreWithinCeilings(t *testing.T) {
	t.Parallel()

	if err := DefaultLimits().Validate(); err != nil {
		t.Errorf("the documented defaults do not validate: %v", err)
	}
	if err := Ceilings().Validate(); err != nil {
		t.Errorf("the documented ceilings do not validate: %v", err)
	}
}

func TestValidateRejectsNegative(t *testing.T) {
	t.Parallel()

	err := Limits{MaxFiles: -1}.Validate()
	if !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("Validate(negative) = %v, want %v", err, fault.CodeInvalidInput)
	}
}

func TestValidateRejectsAboveCeiling(t *testing.T) {
	t.Parallel()

	for _, f := range boundFields {
		var l Limits
		*f.get(&l) = f.ceiling + 1

		err := l.Validate()
		if !stderrors.Is(err, fault.CodeInvalidInput) {
			t.Errorf("%s above ceiling: got %v, want %v", f.name, err, fault.CodeInvalidInput)
		}
	}
}

func TestValidateAcceptsExactCeiling(t *testing.T) {
	t.Parallel()

	for _, f := range boundFields {
		var l Limits
		*f.get(&l) = f.ceiling

		if err := l.Validate(); err != nil {
			t.Errorf("%s at exactly its ceiling was rejected: %v", f.name, err)
		}
	}
}

// The core of DP-021: any input may tighten a bound, none may relax one.
func TestResolveTakesTheStrictestValue(t *testing.T) {
	t.Parallel()

	got := Resolve(
		Input{Origin: OriginClient, Limits: Limits{MaxFiles: 500}},
		Input{Origin: OriginPolicy, Limits: Limits{MaxFiles: 100}},
		Input{Origin: OriginRequest, Limits: Limits{MaxFiles: 900}},
	)

	if got.Limits.MaxFiles != 100 {
		t.Errorf("MaxFiles = %d, want the strictest value 100", got.Limits.MaxFiles)
	}
	if o := got.Origin(BoundMaxFiles); o != OriginPolicy {
		t.Errorf("origin = %q, want %q", o, OriginPolicy)
	}
}

// A policy that asks for a *looser* bound than the embedding application
// configured must not get it. This is the privilege-escalation case.
func TestResolvePolicyCannotRelaxAClientBound(t *testing.T) {
	t.Parallel()

	got := Resolve(
		Input{Origin: OriginClient, Limits: Limits{MaxExpandedBytes: 1 << 20}},
		Input{Origin: OriginPolicy, Limits: Limits{MaxExpandedBytes: 64 << 30}},
	)

	if got.Limits.MaxExpandedBytes != 1<<20 {
		t.Errorf("MaxExpandedBytes = %d, want the client's stricter 1 MiB",
			got.Limits.MaxExpandedBytes)
	}
	if o := got.Origin(BoundMaxExpandedBytes); o != OriginClient {
		t.Errorf("origin = %q, want %q", o, OriginClient)
	}
}

// Resolve with nothing supplied is the defaults, attributed to the defaults.
func TestResolveWithNoInputsIsDefault(t *testing.T) {
	t.Parallel()

	got := Resolve()

	if got.Limits != DefaultLimits() {
		t.Errorf("Resolve() = %+v, want the defaults", got.Limits)
	}
	for _, f := range boundFields {
		if o := got.Origin(f.bound); o != OriginDefault {
			t.Errorf("%s origin = %q, want %q", f.name, o, OriginDefault)
		}
	}
}

// An unset field in one input must not wipe out a value another input set.
func TestResolveIgnoresUnsetFields(t *testing.T) {
	t.Parallel()

	got := Resolve(
		Input{Origin: OriginClient, Limits: Limits{MaxFiles: 10}},
		Input{Origin: OriginRequest, Limits: Limits{MaxReferrers: 8}},
	)

	if got.Limits.MaxFiles != 10 {
		t.Errorf("MaxFiles = %d, want 10", got.Limits.MaxFiles)
	}
	if got.Limits.MaxReferrers != 8 {
		t.Errorf("MaxReferrers = %d, want 8", got.Limits.MaxReferrers)
	}
	if got.Origin(BoundMaxFiles) != OriginClient {
		t.Error("MaxFiles origin was overwritten by an input that did not set it")
	}
}

// Resolve never widens past the defaults, so its output always validates.
func TestResolveOutputAlwaysValidates(t *testing.T) {
	t.Parallel()

	got := Resolve(
		Input{Origin: OriginClient, Limits: Ceilings()},
		Input{Origin: OriginPolicy, Limits: Limits{MaxFiles: 1}},
	)

	if err := got.Limits.Validate(); err != nil {
		t.Errorf("resolved limits do not validate: %v", err)
	}
}

func TestBoundString(t *testing.T) {
	t.Parallel()

	if got := BoundMaxFiles.String(); got != "maxFiles" {
		t.Errorf("BoundMaxFiles.String() = %q, want %q", got, "maxFiles")
	}
	if got := Bound(9999).String(); got != "unknown" {
		t.Errorf("unknown bound String() = %q, want %q", got, "unknown")
	}
}
