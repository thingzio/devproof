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

// Path is a validated, normalized, relative bundle path.
//
// Its zero value is not a valid path. Canonicalization is the format's
// business and lives in an internal package; this type is here so that a
// source resolver written outside this module can name what it returns.
//
// That is not a hypothetical. The resolver contract is public and DP-009
// promises it, but the interface was written in terms of types under
// internal/, which no external module may name -- so the extension point
// could be described, and called, and never implemented.
type Path string

func (p Path) String() string { return string(p) }

// FileRecord is one entry of the canonical inventory: everything about a file
// that contributes to identity, and nothing that does not.
//
// Ownership, timestamps, and link targets are absent by construction rather
// than normalized away later, so there is no code path where one could reach
// the tree digest.
type FileRecord struct {
	// Path is the canonical bundle-relative path.
	Path Path
	// Mode is the normalized mode: ModeFile or ModeExecutable.
	Mode uint32
	// Size is the file's length in bytes.
	Size int64
	// Digest is the SHA-256 of the file's exact content bytes.
	Digest Digest
}
