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

//go:build darwin

package safefs

import "golang.org/x/sys/unix"

// exclusiveRename moves oldPath to newPath, failing if newPath exists.
//
// macOS rename(2) already refuses to replace a directory, so this would be
// safe without the flag. RENAME_EXCL is used anyway: relying on a platform
// quirk means the guarantee is invisible in the code and would disappear
// silently if the behavior ever changed.
func exclusiveRename(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}

const exclusiveRenameSupported = true
