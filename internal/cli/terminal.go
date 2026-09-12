package cli

import (
	"io"
	"os"

	"golang.org/x/term"
)

// isTerminal reports whether w is an interactive terminal.
//
// Progress output and color are enabled only when it is. A redirected stream
// is a file or a pipe, and writing escape sequences into one produces noise
// that survives in logs long after the run.
//
// The check is delegated rather than hand-rolled: the ioctl that answers it
// has a different number on every platform — TIOCGETA on Darwin and the BSDs,
// TCGETS on Linux — and getting that wrong fails to compile on the platform
// you did not test on.
//
// Anything that is not an *os.File cannot be a terminal, which is also what
// makes a test with a buffer take the non-interactive path.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}
