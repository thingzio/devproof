package devproof

import (
	"context"
	stderrors "errors"
	"log/slog"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/oci"
	"github.com/thingzio/devproof/source"
	sourcegit "github.com/thingzio/devproof/source/git"
	sourcepath "github.com/thingzio/devproof/source/path"
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
	limits     bundle.Limits
	tempRoot   string
	logger     *slog.Logger
	resolvers  map[string]source.Resolver
	transports map[string]artifact.Transport
	closed     bool
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
		limits:     bundle.DefaultLimits(),
		logger:     slog.New(discardHandler{}),
		resolvers:  make(map[string]source.Resolver),
		transports: defaultTransports(),
	}
	// The built-in resolvers are registered first so an application can
	// replace one deliberately, rather than being unable to.
	for _, builtin := range []source.Resolver{sourcepath.New(), sourcegit.New()} {
		c.resolvers[builtin.Type()] = builtin
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

// WithResolver registers a source resolver, replacing any resolver already
// registered for the same type.
//
// Registration is explicit and per-client. There is no global registry, no
// plugin loading, and nothing discovered from a bundle, so the set of things
// that can fetch material during a build is exactly what the embedding
// application chose (DP-009).
func WithResolver(resolver source.Resolver) Option {
	return func(c *Client) error {
		if resolver == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "resolver must not be nil")
		}
		if resolver.Type() == "" {
			return fault.New(fault.CodeInvalidInput, clientOp, "resolver has no source type")
		}
		c.resolvers[resolver.Type()] = resolver
		return nil
	}
}

// WithAbsolutePathSources allows path sources to name absolute paths.
//
// Off by default: a manifest that reaches outside its own directory is not
// portable, and a manifest that does so by accident should say so loudly.
func WithAbsolutePathSources() Option {
	return func(c *Client) error {
		c.resolvers[bundle.SourceTypePath] = &sourcepath.Resolver{AllowAbsolute: true}
		return nil
	}
}

// WithTransport registers an artifact transport, replacing any transport
// already registered for the same scheme.
func WithTransport(transport artifact.Transport) Option {
	return func(c *Client) error {
		if transport == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "transport must not be nil")
		}
		if transport.Scheme() == "" {
			return fault.New(fault.CodeInvalidInput, clientOp, "transport has no scheme")
		}
		c.transports[transport.Scheme()] = transport
		return nil
	}
}

// WithRegistryCredentials supplies per-host registry credentials.
//
// Lookup is by host, so a credential issued for one registry is never offered
// to another (DP-013).
func WithRegistryCredentials(provider artifact.CredentialProvider) Option {
	return func(c *Client) error {
		if provider == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "credential provider must not be nil")
		}
		c.transports[artifact.SchemeRegistry] = oci.NewRegistry(oci.RegistryOptions{
			Credentials: provider,
		})
		return nil
	}
}

// WithInsecureRegistry disables TLS for registry transport.
//
// It exists for a local test registry. Using it against anything else sends
// credentials and content in the clear, which is why it is a named option
// rather than a field on a config struct somebody might set by accident.
func WithInsecureRegistry(provider artifact.CredentialProvider) Option {
	return func(c *Client) error {
		c.transports[artifact.SchemeRegistry] = oci.NewRegistry(oci.RegistryOptions{
			Credentials: provider,
			PlainHTTP:   true,
		})
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

	var errs []error
	for scheme, transport := range c.transports {
		if err := transport.Close(); err != nil {
			errs = append(errs, fault.Wrap(fault.CodeInternal, clientOp,
				"closing the "+scheme+" transport", err))
		}
	}
	return stderrors.Join(errs...)
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
