package artifact

import (
	"context"
	"io"
)

// Transport stores and retrieves OCI objects at one kind of location.
//
// The interface is deliberately small. Adding a method breaks every external
// implementation, so capability is added through optional subinterfaces — see
// [ReferrerTransport] — rather than by growing this one.
//
// A Transport moves bytes and nothing else. It does not decide the order
// blobs are published in, when a tag may be assigned, or whether content is
// acceptable; those are the SDK's, and keeping them out of here means a
// custom transport cannot weaken them.
type Transport interface {
	// Scheme is the reference scheme this transport handles.
	Scheme() string

	// Resolve freezes a reference to one descriptor.
	//
	// This is where a tag stops being a tag. Everything afterwards works
	// from the returned descriptor, so a tag that moves mid-operation cannot
	// change what was fetched or verified (DP-007).
	Resolve(ctx context.Context, ref Reference) (Descriptor, error)

	// Fetch returns the content a descriptor names.
	//
	// The caller verifies the bytes against the descriptor. A transport that
	// verified internally would still have to be checked by the caller,
	// because the caller cannot know whether it did.
	Fetch(ctx context.Context, ref Reference, target Descriptor) (io.ReadCloser, error)

	// Push stores content under its descriptor.
	//
	// Push is idempotent: content that is already present is not an error.
	// Storage is content-addressed, so a second push of the same descriptor
	// can only be the same bytes.
	Push(ctx context.Context, ref Reference, target Descriptor, content io.Reader) error

	// Tag assigns a mutable name to an already-stored manifest.
	//
	// A transport may assume the manifest is present; the SDK does not call
	// this until it has read the manifest back and compared its descriptor.
	Tag(ctx context.Context, ref Reference, target Descriptor, tag string) error

	// Close releases connections and handles.
	Close() error
}

// Credential authenticates to a registry.
//
// It carries no host: a credential is selected for a host by the provider,
// and a credential that named its own host could be returned for a different
// one.
type Credential struct {
	Username string
	Password string
	// Token is a bearer or identity token, used when Username and Password
	// are empty.
	Token string
}

// IsZero reports whether the credential is empty, meaning anonymous access.
func (c Credential) IsZero() bool {
	return c.Username == "" && c.Password == "" && c.Token == ""
}

// CredentialProvider supplies registry credentials.
//
// Lookup is by host so that a credential is scoped to the registry it was
// issued for. A provider that returned the same credential for every host
// would send a token for one registry to another, which is the disclosure
// DP-013 exists to prevent.
//
// Returning a zero Credential means anonymous access, which is not an error:
// public registries exist.
type CredentialProvider interface {
	Credential(ctx context.Context, registry string) (Credential, error)
}

// CredentialFunc adapts a function to [CredentialProvider].
type CredentialFunc func(ctx context.Context, registry string) (Credential, error)

func (f CredentialFunc) Credential(ctx context.Context, registry string) (Credential, error) {
	return f(ctx, registry)
}

// AnonymousCredentials is a provider that never supplies a credential.
var AnonymousCredentials CredentialProvider = CredentialFunc(
	func(context.Context, string) (Credential, error) { return Credential{}, nil },
)

// Capabilities reports what a location supports.
//
// It is reported rather than probed at the point of use so that a policy can
// refuse a registry whose storage mode it does not accept, before anything is
// published there.
type Capabilities struct {
	// ReferrersAPI reports whether the OCI referrers API is available.
	// Where it is not, evidence discovery falls back to a tag scheme, which
	// has weaker concurrency guarantees.
	ReferrersAPI bool
}

// CapabilityReporter is implemented by transports that can describe a
// location's storage mode.
type CapabilityReporter interface {
	Capabilities(ctx context.Context, ref Reference) (Capabilities, error)
}
