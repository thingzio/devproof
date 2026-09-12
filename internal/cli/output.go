// Package cli implements the devproof command line.
//
// Every command is a thin adapter: it parses input, calls one public SDK
// operation, renders the result, and maps a typed error to an exit code
// (DP-001). No command contains logic that an embedding application could not
// reach through the SDK.
//
// The stream discipline here is load-bearing. stdout carries the requested
// result and nothing else, so `devproof build ... | xargs crane` works and
// keeps working; every diagnostic, warning, progress indicator, and error
// goes to stderr. A tool that prints "Building..." to stdout is a tool nobody
// can safely pipe.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/thingzio/devproof/internal/fault"
)

// Format selects how a result is rendered.
type Format string

const (
	// FormatText is human-readable output.
	FormatText Format = "text"
	// FormatJSON is one JSON document followed by a newline.
	FormatJSON Format = "json"
)

// EnvelopeAPIVersion identifies the CLI's JSON contract. It is versioned
// separately from the bundle format: the two change for different reasons.
const EnvelopeAPIVersion = "devproof.thingz.io/cli/v1alpha1"

// Envelope wraps every JSON result.
//
// The shape is the same for every command so that a caller can find the
// apiVersion and kind without knowing which command produced the output.
type Envelope struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Result     any      `json:"result,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// ErrorEnvelope is the JSON failure shape.
type ErrorEnvelope struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Error      ErrorPayload `json:"error"`
}

// ErrorPayload is the machine-readable half of a failure.
//
// Code and the field names are a stable API. Message is not: it is written
// for the human deciding what to do next, and nothing should parse it.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Source  string `json:"source,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Streams are a command's output destinations.
//
// Passed rather than taken from the process so that a test can capture them
// and assert the discipline holds, which is the only way to know it does.
type Streams struct {
	Out io.Writer
	Err io.Writer
	// IsTerminal reports whether Err is an interactive terminal. Progress and
	// color are enabled only when it is.
	IsTerminal bool
}

// DefaultStreams returns the process streams.
func DefaultStreams() Streams {
	return Streams{Out: os.Stdout, Err: os.Stderr, IsTerminal: isTerminal(os.Stderr)}
}

// Printer renders results according to the selected output mode.
type Printer struct {
	Streams  Streams
	Format   Format
	Quiet    bool
	Verbose  bool
	Debug    bool
	NoColor  bool
	warnings []string

	progressOnce sync.Once
	progress     *Progress
}

// Warn records a warning.
//
// Warnings go to stderr in text mode and into the JSON envelope otherwise, so
// they never corrupt a piped result either way.
func (p *Printer) Warn(format string, args ...any) {
	p.clearProgress()
	message := fmt.Sprintf(format, args...)
	p.warnings = append(p.warnings, message)
	if p.Format != FormatJSON && !p.Quiet {
		fmt.Fprintln(p.Streams.Err, p.paint(colorYellow, "warning: ")+message)
	}
}

// Info writes an informational line to stderr, when verbose.
func (p *Printer) Info(format string, args ...any) {
	if p.Verbose || p.Debug {
		p.clearProgress()
		fmt.Fprintln(p.Streams.Err, fmt.Sprintf(format, args...))
	}
}

// Result renders a successful outcome.
//
// kind names the result type in JSON. quiet is the single value a pipeline
// wants — a digest, a path — and is the only thing printed under --quiet,
// because a script that has to parse prose is a script that breaks.
func (p *Printer) Result(kind string, result any, quiet string, text func(w io.Writer)) error {
	p.clearProgress()

	switch {
	case p.Format == FormatJSON:
		envelope := Envelope{
			APIVersion: EnvelopeAPIVersion,
			Kind:       kind,
			Result:     result,
			Warnings:   p.warnings,
		}
		encoder := json.NewEncoder(p.Streams.Out)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(envelope)

	case p.Quiet:
		if quiet == "" {
			return nil
		}
		_, err := fmt.Fprintln(p.Streams.Out, quiet)
		return err

	default:
		text(p.Streams.Out)
		return nil
	}
}

// Failure renders an error and returns the process exit code.
//
// In JSON mode the failure envelope goes to stdout, because a caller parsing
// JSON needs to read the error the same way it reads a result. In text mode
// stdout stays empty: a pipeline that got no result should receive no bytes.
func (p *Printer) Failure(err error, interrupted bool) int {
	p.clearProgress()

	if err == nil {
		return fault.ExitSuccess
	}

	code := fault.CodeOf(err)
	payload := ErrorPayload{Code: string(code), Message: userMessage(err)}
	if typed, ok := fault.AsError(err); ok {
		payload.Source = typed.Source
		payload.Path = typed.Path
	}

	if p.Format == FormatJSON {
		encoder := json.NewEncoder(p.Streams.Out)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(ErrorEnvelope{
			APIVersion: EnvelopeAPIVersion,
			Kind:       "Error",
			Error:      payload,
		})
	}

	fmt.Fprintln(p.Streams.Err, p.paint(colorRed, "error: ")+payload.Message)
	if p.Debug {
		// The full chain, including causes, is debug output. It can carry
		// library detail that is noise to everyone else, and it is on stderr
		// so it never reaches a pipeline.
		fmt.Fprintf(p.Streams.Err, "debug: %+v\n", err)
	}

	return fault.ExitCode(err, interrupted)
}

// userMessage extracts the actionable part of an error.
//
// The typed message says what failed and what to do; the wrapped cause is
// library detail. Showing the whole chain by default buries the sentence that
// matters under transport noise.
func userMessage(err error) string {
	typed, ok := fault.AsError(err)
	if !ok {
		return err.Error()
	}

	var b strings.Builder
	if typed.Msg != "" {
		b.WriteString(typed.Msg)
	} else {
		b.WriteString(string(typed.Code))
	}
	if typed.Source != "" {
		fmt.Fprintf(&b, " (source %s)", typed.Source)
	}
	if typed.Path != "" {
		fmt.Fprintf(&b, " (path %s)", typed.Path)
	}
	return b.String()
}

// ANSI colors, used only when stderr is an interactive terminal.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorDim    = "\033[2m"
)

// paint colors text, unless color is disabled.
//
// Color is off unless stderr is a terminal, and is additionally suppressed by
// --no-color, NO_COLOR, TERM=dumb, --quiet, and JSON mode. Escape sequences in
// a log file or a pipeline are noise at best and corruption at worst.
func (p *Printer) paint(color, text string) string {
	if p.NoColor || !p.Streams.IsTerminal || p.Quiet || p.Format == FormatJSON {
		return text
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return text
	}
	return color + text + colorReset
}

// Success writes a short confirmation line to stderr in text mode.
func (p *Printer) Success(format string, args ...any) {
	p.clearProgress()
	if p.Format == FormatJSON || p.Quiet {
		return
	}
	fmt.Fprintln(p.Streams.Err, p.paint(colorGreen, "✓ ")+fmt.Sprintf(format, args...))
}

// Field writes an aligned name/value line for text output.
func Field(w io.Writer, name, value string) {
	fmt.Fprintf(w, "%-16s %s\n", name+":", value)
}
