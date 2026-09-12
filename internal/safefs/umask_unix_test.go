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

//go:build unix

package safefs

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/thingzio/devproof/internal/canonical"
)

// setUmask sets the process umask and returns the previous value. There is no
// way to read the umask without setting it, which is why this is a swap.
func setUmask(mask int) int { return unix.Umask(mask) }

// DP-012: a permissive umask and a restrictive one must produce the same
// bundle. Without mode normalization this is the most likely way two
// developers get different digests for identical content.
func TestBuildIsIndependentOfUmask(t *testing.T) {
	// Not parallel: umask is process-global.
	tree := fixtureTree()

	build := func(mask int) canonical.Digest {
		previous := setUmask(mask)
		defer setUmask(previous)

		dir := t.TempDir()
		writeTree(t, dir, tree)
		subject, _ := buildFrom(t, dir)
		return subject.ManifestDigest
	}

	permissive := build(0o022)
	restrictive := build(0o077)

	if permissive != restrictive {
		t.Errorf("umask changed the subject digest: %s under 022, %s under 077",
			permissive, restrictive)
	}
}
