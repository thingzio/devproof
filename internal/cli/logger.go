package cli

import (
	"io"
	"log/slog"
)

// slogLogger is the logger type the SDK accepts.
type slogLogger = slog.Logger

// newStderrLogger builds the logger the SDK writes diagnostics through.
//
// It always writes to stderr, never to stdout: a log line in a piped result
// is corruption. When neither --verbose nor --debug is set the level is high
// enough that nothing is emitted, rather than the logger being nil — a nil
// logger would mean every call site had to guard, and one that forgot would
// panic in the field.
func newStderrLogger(w io.Writer, verbose, debug bool) *slog.Logger {
	level := slog.LevelError + 1 // above everything: silent by default
	switch {
	case debug:
		level = slog.LevelDebug
	case verbose:
		level = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		// Timestamps are noise in interactive output and are already added
		// by every log collector that wants them.
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	}))
}
