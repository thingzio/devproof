//go:build !unix

package safefs

import "errors"

// mkfifo is unavailable off unix, which makes the FIFO test skip rather than
// fail. There is no named-pipe equivalent to place in a directory tree here,
// and the behavior under test — refusing a file that is neither regular nor a
// directory — has no way to be provoked.
func mkfifo(string) error { return errors.New("FIFOs are not available on this platform") }
