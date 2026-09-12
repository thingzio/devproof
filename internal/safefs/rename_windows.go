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

//go:build windows

package safefs

import (
	"golang.org/x/sys/windows"
)

// exclusiveRename moves oldPath to newPath, failing if newPath exists.
//
// MoveFileExW without MOVEFILE_REPLACE_EXISTING is exactly the guarantee
// DP-022 asks for: the move succeeds only if nothing is already at the
// destination, and the check and the move are one operation inside the
// filesystem. It works for directories, which rules out ReplaceFileW —
// that one is file-only and replaces by design.
//
// os.Rename cannot be used here because Go passes MOVEFILE_REPLACE_EXISTING
// to match POSIX semantics, which is the behavior this function exists to
// avoid.
func exclusiveRename(oldPath, newPath string) error {
	from, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	// Flags are deliberately zero. MOVEFILE_COPY_ALLOWED is not set either:
	// a cross-volume move degrades into a copy that is no longer atomic, and
	// staging happens beside the destination precisely so that the move stays
	// within one volume.
	return windows.MoveFileEx(from, to, 0)
}

const exclusiveRenameSupported = true
