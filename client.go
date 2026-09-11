package devproof

import (
	"context"
	"log/slog"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const clientOp = "devproof.client"

// Client is the SDK facade. Every operation the CLI performs is a method
// here; the CLI parses input, calls one of these, and renders the result
// (DP-001).
//
// A Client is safe for concurrent use after construction. Its methods never
// call os.Exit, print, prompt, or open a browser — those are a command-line
// program's business, and a library that does them cannot be embedded.
type Client struct {
	limits   bundle.Limits
	tempRoot string
	logger   *slog.Logger
	closed   bool
}

// Option configures a Client.
type Option func(*Client) error

// New constructs a Client.
//
// Defaults are safe and deterministic: unset limits become the documented
// defaults rather than "unlimited", and no logger means no output rather than
// output to stderr.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		limits: bundle.DefaultLimits(),
		logger: slog.New(discardHandler{}),
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fault.New(fault.CodeInvalidInput, clientOp, "nil option")
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if err := c.limits.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// WithLimits sets the client's resource bounds.
//
// These are intersected with any per-request and policy limits, so this sets
// a ceiling the rest of the system can tighten but never relax (DP-021).
func WithLimits(limits Limits) Option {
	return func(c *Client) error {
		if err := limits.Validate(); err != nil {
			return err
		}
		c.limits = limits.WithDefaults()
		return nil
	}
}

// WithTempRoot sets the parent directory for snapshot and layout scratch
// space.
//
// It deliberately does not affect expansion staging, which must be a sibling
// of the destination for publication to be an atomic same-filesystem rename
// (DP-022).
func WithTempRoot(dir string) Option {
	return func(c *Client) error {
		c.tempRoot = dir
		return nil
	}
}

// WithLogger sets a structured logger for diagnostics.
//
// Events name the operation and the logical source. They never carry a
// credential-bearing URL or a secret header, and nothing logged is ever an
// input to artifact identity.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) error {
		if logger == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "logger must not be nil")
		}
		c.logger = logger
		return nil
	}
}

// Close releases client-owned resources.
//
// It does not remove artifacts, layouts, or output directories: those belong
// to the caller, and a library that deleted them on shutdown would be
// impossible to reason about.
func (c *Client) Close() error {
	c.closed = true
	return nil
}

func (c *Client) checkOpen() error {
	if c.closed {
		return fault.New(fault.CodeInvalidInput, clientOp, "client is closed")
	}
	return nil
}

// effectiveLimits intersects the client's limits with a request's.
func (c *Client) effectiveLimits(request Limits) bundle.Resolved {
	return bundle.Resolve(
		bundle.Input{Origin: bundle.OriginClient, Limits: c.limits},
		bundle.Input{Origin: bundle.OriginRequest, Limits: request},
	)
}

// discardHandler is a no-op slog handler. The zero-configuration Client
// should be silent, not chatty: a library that writes to stderr by default
// corrupts the output of whatever embeds it.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs(_ []slog.Attr) slog.Handler        { return h }
func (h discardHandler) WithGroup(_ string) slog.Handler             { return h }
