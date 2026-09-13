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

package conformance

import "fmt"

// Level selects how much of the specification a verification applies.
//
// The three levels answer three different questions, and conflating them is
// how an implementation ends up claiming more than it checked:
//
//   - [LevelStructure] asks whether the artifact is intact and internally
//     consistent, and whether expanding it is safe. Every digest is
//     recomputed, the inventory is compared against what the layer actually
//     held, and no path may escape the destination.
//   - [LevelCanonical] asks whether these are the only bytes a conforming
//     writer could have produced for this tree. Entry order, fixed header
//     fields, the extended-header restriction, the frozen gzip header, RFC
//     8785 member order, and the portable path rules are all in this level and
//     none of them affect whether the artifact can be read.
//   - [LevelBytes] asks whether a writer reproduces the published vectors
//     exactly. That is a property of an implementation rather than of an
//     artifact: it is checked by building the documented input tree and
//     comparing the result with vectors/format/v1. [VerifyVectors] runs the
//     comparison for the published files themselves.
//
// A deviation found above the requested level is reported in
// [Report.Deviations] rather than discarded, so a level-1 pass still says what
// it tolerated.
type Level int

const (
	// LevelStructure verifies structure and integrity.
	LevelStructure Level = iota + 1
	// LevelCanonical adds every rule that makes the encoding the only one.
	LevelCanonical
	// LevelBytes adds agreement with the published byte vectors.
	LevelBytes
)

// String names a level for diagnostics.
func (l Level) String() string {
	switch l {
	case LevelStructure:
		return "structure"
	case LevelCanonical:
		return "canonical"
	case LevelBytes:
		return "bytes"
	default:
		return fmt.Sprintf("Level(%d)", int(l))
	}
}

// valid reports whether a level is one this package implements for an
// artifact.
func (l Level) valid() bool {
	return l == LevelStructure || l == LevelCanonical
}

// findings collects canonical deviations while a read is in progress.
//
// They are gathered rather than returned at the first one because a writer
// being fixed wants the whole list, and because a level-1 caller needs them
// recorded even though they are not failures for it.
type findings struct {
	level Level
	notes []string
}

// canonical records a deviation from the canonical encoding.
//
// It returns an error only when the requested level cares, which is what keeps
// each call site free of a level test.
func (f *findings) canonical(format string, args ...any) error {
	note := fmt.Sprintf(format, args...)
	f.notes = append(f.notes, note)
	if f.level >= LevelCanonical {
		return fmt.Errorf("%s", note)
	}
	return nil
}
