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

// Package repo locates the repository and holds tests for the contracts its
// non-Go files make.
//
// Configuration that names paths — CODEOWNERS, workflows, lint ignores — fails
// silently when a path moves: the file stays valid, the rule matches nothing,
// and nobody notices until the protection it was supposed to provide was
// needed. These are cheap to assert and were not being asserted.
package repo

import (
	"os"
	"path/filepath"
)

// Root returns the directory holding go.mod, or "." if none is found.
//
// Derived by walking up from the working directory rather than from
// runtime.Caller, which reports a trimmed module path under this repository's
// build flags and so yields a path that does not exist.
func Root() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
