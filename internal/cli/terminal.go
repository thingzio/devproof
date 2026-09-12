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
