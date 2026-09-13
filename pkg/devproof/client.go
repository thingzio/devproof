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

package devproof

import (
	"context"
	stderrors "errors"
	"log/slog"
	"time"

	"github.com/thingzio/devproof/internal/oci"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/evidence"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/policy"
	"github.com/thingzio/devproof/pkg/source"
	sourcegit "github.com/thingzio/devproof/pkg/source/git"
	sourcepath "github.com/thingzio/devproof/pkg/source/path"
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
	attester   evidence.Attester
	verifier   evidence.Verifier
	trustRoots [][]byte
	clock      func() time.Time
	offline    bool
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

// WithSigstore enables keyless signing and verification.
//
// This is the default posture for a build that asks to sign: an ephemeral key
// certified by Fulcio against an OIDC identity, recorded in a transparency
// log, with nothing durable to protect or rotate. On a CI runner that already
// has an OIDC token it needs no configuration at all.
func WithSigstore(opts evidence.SigstoreOptions) Option {
	return func(c *Client) error {
		c.attester = evidence.NewSigstoreAttester(opts)
		c.verifier = evidence.NewSigstoreVerifier(opts)
		return nil
	}
}

// WithAttester registers the implementation that signs evidence.
func WithAttester(attester evidence.Attester) Option {
	return func(c *Client) error {
		if attester == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "attester must not be nil")
		}
		c.attester = attester
		return nil
	}
}

// WithVerifier registers the implementation that checks evidence signatures.
//
// Verification and signing are configured separately on purpose: a consumer
// verifies without ever signing, and making one imply the other would mean
// every verifier carried a signing path it never uses.
func WithVerifier(verifier evidence.Verifier) Option {
	return func(c *Client) error {
		if verifier == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "verifier must not be nil")
		}
		c.verifier = verifier
		return nil
	}
}

// WithTrustRoots supplies trust material for evidence verification.
//
// Supplying roots is what makes offline verification possible: nothing is
// fetched, and the material came from somewhere the caller chose rather than
// from the network at verification time.
func WithTrustRoots(roots ...[]byte) Option {
	return func(c *Client) error {
		if len(roots) == 0 {
			return fault.New(fault.CodeInvalidInput, clientOp, "no trust roots supplied")
		}
		c.trustRoots = append(c.trustRoots, roots...)
		return nil
	}
}

// WithClock supplies the time a verification evaluates against.
//
// The clock is used for evidence and diagnostics only. Canonical artifact
// encoding has no clock dependency at all, which is why a bundle built at two
// different moments has one identity (DP-012).
func WithClock(clock func() time.Time) Option {
	return func(c *Client) error {
		if clock == nil {
			return fault.New(fault.CodeInvalidInput, clientOp, "clock must not be nil")
		}
		c.clock = clock
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

// WithOffline refuses every operation that would use the network.
//
// It is a capability boundary rather than a preference: a transport that has
// not promised to stay local is rejected when it is selected, before a
// reference is resolved or a byte is fetched. A flag that merely expressed an
// intention would be worse than none, because the situations where offline
// matters -- an air gap, an incident, a machine that must not phone home --
// are exactly the ones where nobody is watching for an unexpected connection.
//
// Evidence verification must also be offline: supply a trusted root with
// WithSigstore, or a key with WithVerifier. Without one, verification would
// fetch the public Sigstore root over TUF, and this option cannot reach inside
// an attester or verifier an application supplied.
func WithOffline() Option {
	return func(c *Client) error {
		c.offline = true
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

// limitsFor resolves the bounds one operation runs under.
//
// One call site, before any I/O, so every stage of that operation is bounded
// by the same numbers. Resolving per stage was how a policy's limits came to
// apply to evidence discovery and nothing else.
func (c *Client) limitsFor(request Limits, doc *policy.Document, havePolicy bool) bundle.Resolved {
	if !havePolicy || doc == nil {
		return c.effectiveLimits(request)
	}
	return c.effectiveLimitsWithPolicy(request, doc.Spec.Limits)
}

// effectiveLimitsWithPolicy adds a policy's limits to the intersection.
//
// A policy may tighten a bound and never relax one, which is what stops a
// policy — which can travel with an artifact — being usable as privilege
// escalation against the embedding application's own configuration (DP-021).
func (c *Client) effectiveLimitsWithPolicy(request, fromPolicy Limits) bundle.Resolved {
	return bundle.Resolve(
		bundle.Input{Origin: bundle.OriginClient, Limits: c.limits},
		bundle.Input{Origin: bundle.OriginRequest, Limits: request},
		bundle.Input{Origin: bundle.OriginPolicy, Limits: fromPolicy},
	)
}

// now returns the evaluation time.
//
// Injected so that a time-dependent policy rule can be tested without waiting
// for the clock, and so that one evaluation uses exactly one time rather than
// reading the clock at each rule.
func (c *Client) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

// discardHandler is a no-op slog handler. The zero-configuration Client
// should be silent, not chatty: a library that writes to stderr by default
// corrupts the output of whatever embeds it.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (h discardHandler) WithAttrs(_ []slog.Attr) slog.Handler        { return h }
func (h discardHandler) WithGroup(_ string) slog.Handler             { return h }
