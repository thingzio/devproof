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

//go:build linux

package safefs

import "golang.org/x/sys/unix"

// exclusiveRename moves oldPath to newPath, failing if newPath exists.
//
// On Linux this needs renameat2: plain rename(2) silently replaces an
// existing empty directory, so a destination that appeared between the
// pre-flight check and publication would be overwritten rather than reported
// (DP-022).
func exclusiveRename(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}

// exclusiveRenameSupported reports whether this platform can publish
// atomically. RENAME_NOREPLACE needs Linux 3.15, and on older kernels or
// filesystems that do not implement it renameat2 returns EINVAL or ENOSYS,
// which the caller surfaces rather than working around.
const exclusiveRenameSupported = true
