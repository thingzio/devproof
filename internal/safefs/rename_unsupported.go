//go:build !linux && !darwin

package safefs

import "errors"

// exclusiveRename is unavailable on this platform.
//
// DP-022 requires failing rather than falling back to a plain rename. A
// fallback would be silently racy on exactly the platform nobody tested, and
// the whole value of staged publication is that a destination either appears
// complete or does not appear.
func exclusiveRename(_, _ string) error {
	return errors.New("atomic exclusive rename is not implemented on this platform")
}

const exclusiveRenameSupported = false
