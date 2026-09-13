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

package repo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/repo"
)

// TestCodeownersPathsExist checks that every pattern names something.
//
// A CODEOWNERS entry for a path that has moved is not an error to GitHub: the
// file parses, the rule matches nothing, and review protection silently stops
// applying to the files it was written for. Two entries had been pointing at
// pre-`pkg/` locations — the format and policy packages, which are exactly the
// ones the rules exist to protect.
//
// Only literal prefixes are checked. A glob pattern is skipped rather than
// guessed at, because a glob that currently matches nothing may still be a
// deliberate rule about files that do not exist yet.
func TestCodeownersPathsExist(t *testing.T) {
	t.Parallel()

	root := repo.Root()
	data, err := os.ReadFile(filepath.Join(root, ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatalf("reading CODEOWNERS: %v", err)
	}

	var checked int
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pattern, _, found := strings.Cut(line, " ")
		if !found || pattern == "*" || strings.Contains(pattern, "*") {
			continue
		}

		checked++
		// A leading slash anchors to the repository root; a trailing one means
		// a directory. Neither survives a filesystem join.
		target := filepath.Join(root, filepath.FromSlash(strings.Trim(pattern, "/")))
		if _, err := os.Stat(target); err != nil {
			t.Errorf("CODEOWNERS line %d owns %q, which does not exist; "+
				"the rule matches nothing and its files are unprotected",
				i+1, pattern)
		}
	}

	if checked == 0 {
		t.Fatal("no literal CODEOWNERS patterns were checked; the parser is wrong")
	}
}
