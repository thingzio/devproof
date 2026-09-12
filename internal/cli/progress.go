package cli

import (
	"fmt"
	"strings"
	"sync"
)

// progressWidth bounds a transient line.
//
// A line longer than the terminal wraps, and a wrapped line cannot be erased
// by returning to its start — the tail stays on screen and accumulates.
// Truncating is what keeps the display to exactly one line.
const progressWidth = 72

// Progress reports what a command is currently doing.
//
// It writes to stderr and only when stderr is an interactive terminal. A
// progress indicator exists for a human watching a slow operation; written to
// a pipe or a log file it is noise, and written to stdout it is corruption.
//
// Under --verbose the same steps are written as ordinary permanent lines
// instead, because a CI log is exactly the case where knowing which step was
// running when something failed is worth the extra output.
type Progress struct {
	printer *Printer

	mu      sync.Mutex
	active  bool
	lastLen int
}

// Progress returns the printer's progress reporter.
//
// Owned by the printer so that every path that writes real output can erase a
// pending progress line first, without each call site having to remember to.
func (p *Printer) Progress() *Progress {
	p.progressOnce.Do(func() { p.progress = &Progress{printer: p} })
	return p.progress
}

// clearProgress erases any transient line before real output is written.
func (p *Printer) clearProgress() {
	if p.progress != nil {
		p.progress.Done()
	}
}

// enabled reports whether transient progress should be drawn.
func (p *Progress) enabled() bool {
	return p.printer.Streams.IsTerminal &&
		!p.printer.Quiet &&
		!p.printer.Verbose &&
		!p.printer.Debug &&
		p.printer.Format != FormatJSON
}

// Step reports the operation now in progress.
func (p *Progress) Step(format string, args ...any) {
	message := fmt.Sprintf(format, args...)

	if !p.enabled() {
		// Verbose turns the same information into permanent lines; quiet and
		// JSON modes drop it entirely.
		p.printer.Info("%s", message)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(message) > progressWidth {
		message = message[:progressWidth-1] + "…"
	}

	// Redrawn in place: the sequence is carriage return, the new text, then
	// enough spaces to erase whatever the previous line left behind.
	padding := 0
	if p.lastLen > len(message) {
		padding = p.lastLen - len(message)
	}
	fmt.Fprint(p.printer.Streams.Err, "\r"+p.printer.paint(colorDim, message)+strings.Repeat(" ", padding))

	p.lastLen = len(message)
	p.active = true
}

// Done erases the transient line.
//
// Called before any other output so that a result, a warning, or an error is
// never printed on top of a half-erased progress line.
func (p *Progress) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}
	fmt.Fprint(p.printer.Streams.Err, "\r"+strings.Repeat(" ", p.lastLen)+"\r")
	p.active = false
	p.lastLen = 0
}
