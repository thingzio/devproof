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

// Package safefs contains DevProof's filesystem boundaries: private
// workspaces, snapshotting a source tree, and extracting a verified payload.
//
// Everything here assumes the filesystem is adversarial. A source directory
// can change while it is being read, a path can be a symlink to somewhere
// else, an archive entry can claim to live outside its root, and a
// destination can appear between the moment it was checked and the moment it
// is published. The package is built so that none of those produce a wrong
// answer — only a failure.
//
// Two rules run through all of it.
//
// Confinement is by file descriptor, not by string comparison. Operations go
// through [os.Root], which resolves every component relative to a held
// directory handle and refuses to traverse a symlink out of it. Checking that
// a cleaned path has the right prefix is not containment: the check and the
// open are separate moments, and a symlink can be introduced in between.
//
// Nothing is published until it is complete and verified. A snapshot is
// hashed as it is copied and read back through the same digests; an expansion
// is written into a private staging directory and moved into place with an
// exclusive rename. A failed, canceled, or interrupted operation leaves
// nothing that could be mistaken for a successful one.
package safefs
