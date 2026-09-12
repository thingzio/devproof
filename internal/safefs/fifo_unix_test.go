//go:build unix

package safefs

import "golang.org/x/sys/unix"

func mkfifo(path string) error { return unix.Mkfifo(path, 0o600) }
