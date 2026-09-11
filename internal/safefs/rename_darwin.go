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
