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

// Package source defines how DevProof obtains material, and ships the
// built-in resolvers for local paths and HTTPS Git.
//
// A resolver's whole job is to turn a possibly-mutable reference into an
// immutable, private snapshot plus enough public fact to describe what it
// resolved. It never writes into the bundle tree and never decides where its
// content lands; composition does that, so that a resolver cannot influence
// anything beyond its own contribution.
package source

import (
	"context"
	"io"

	"github.com/thingzio/devproof/pkg/bundle"
)

// Resolver obtains material for one source type.
//
// Implementations are registered explicitly when a client is constructed.
// There is no global registry, no plugin loading, and no discovery from a
// bundle: an application decides exactly which resolvers exist in its process
// (DP-009).
type Resolver interface {
	// Type is the manifest source type this resolver handles, such as
	// "path", or a domain-qualified name for an extension.
	Type() string

	// Identity names the implementation and its version. It is recorded in
	// the lock, so a resolver whose behavior changes cannot silently satisfy
	// a lock an earlier version produced.
	Identity() Identity

	// Resolve obtains material and returns a frozen snapshot.
	//
	// When the request carries a Locked source, the resolver must reproduce
	// exactly that resolution and report a stale-lock error if it cannot.
	Resolve(ctx context.Context, req ResolveRequest) (Snapshot, error)
}

// Identity names a resolver implementation.
type Identity struct {
	// Name is a stable identifier such as "devproof.thingz.io/path/v1".
	Name string `json:"name"`
	// Version is the implementation version.
	Version string `json:"version"`
}

// ResolveRequest is everything a resolver is given.
//
// It is a value, not an interface onto the wider system, so a resolver has no
// route to the destination, the other sources, or the caller's credentials
// beyond what is handed to it here.
type ResolveRequest struct {
	// Name is the logical source name, for diagnostics and evidence.
	Name string
	// Config is the resolver-specific configuration from the manifest.
	Config map[string]any

	// Include and Exclude filter source-relative paths before composition.
	Include []string
	Exclude []string

	// BaseDir is the manifest's directory. Relative local paths resolve
	// against it rather than the process working directory, so a manifest
	// means the same thing wherever it is invoked from (DP-012).
	BaseDir string

	// Locked, when set, is the resolution this build must reproduce.
	Locked *bundle.LockedSource

	// Limits bounds what the resolver may produce.
	Limits bundle.Limits

	// TempRoot is the parent for private snapshot storage.
	TempRoot string
}

// Snapshot is a frozen, private copy of one source's selected material.
//
// Paths are source-relative: a snapshot does not know its mount path, and
// applying one is composition's job. That separation is what lets the same
// source be described by one tree digest regardless of where it is mounted.
type Snapshot interface {
	// Material describes what was resolved, in terms safe to publish.
	Material() Material

	// Records returns the canonical file records, source-relative and sorted
	// by path.
	Records() []bundle.FileRecord

	// Open returns the content of a path previously returned by Records.
	Open(ctx context.Context, path bundle.Path) (io.ReadCloser, error)

	// Close releases the snapshot's private storage.
	Close() error
}

// Material is the publishable truth about a resolution.
//
// Everything here can appear in a lock and in signed provenance, so it must
// contain no credential, no token-bearing URL, and no local absolute path
// (DP-025). A resolver that cannot describe its material without one of those
// should describe less.
type Material struct {
	// Type is the manifest source type.
	Type string
	// Resolver identifies the implementation.
	Resolver Identity

	// Requested is what the manifest asked for, which may be mutable.
	Requested map[string]any
	// Resolved is what it resolved to, which must be immutable. A resolver
	// that cannot produce an immutable resolution must fail rather than
	// record a moving reference.
	Resolved map[string]any

	// TreeDigest is the canonical digest of the filtered, source-relative
	// contribution.
	TreeDigest bundle.Digest
}
