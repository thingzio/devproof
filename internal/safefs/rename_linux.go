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
