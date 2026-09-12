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

package artifact

import (
	"fmt"
	"strings"

	"github.com/distribution/reference"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

const referenceOp = "artifact.reference"

// URI schemes DevProof accepts for a bundle location.
const (
	// SchemeRegistry addresses an OCI Distribution registry.
	SchemeRegistry = "oci"
	// SchemeLayout addresses a local OCI image layout directory.
	SchemeLayout = "oci-layout"
)

// Reference names a bundle location.
//
// A Reference distinguishes a tag from a digest because the difference is the
// whole of DP-007: a tag is a pointer someone else can move, a digest is the
// content. Every operation resolves a tag exactly once and works from the
// digest afterwards, so a tag that moves mid-operation cannot change what was
// verified.
type Reference struct {
	// Scheme is SchemeRegistry or SchemeLayout.
	Scheme string

	// Registry is the host, for a registry reference.
	Registry string
	// Repository is the repository path, for a registry reference.
	Repository string
	// Path is the layout directory, for a layout reference.
	Path string

	// Tag is the mutable name, if one was given.
	Tag string
	// Digest is the immutable identity, if one was given.
	Digest string
}

// ParseReference parses a bundle location.
//
// A bare reference with no scheme is treated as a registry reference, which
// is what every other OCI tool does. A reference with no registry host is an
// error rather than a Docker Hub default: silently reaching out to a registry
// nobody named is exactly the ambient behavior DP-012 excludes.
func ParseReference(raw string) (Reference, error) {
	if raw == "" {
		return Reference{}, fault.New(fault.CodeInvalidInput, referenceOp, "reference is empty")
	}

	scheme, rest, hasScheme := strings.Cut(raw, "://")
	if !hasScheme {
		scheme, rest = SchemeRegistry, raw
	}

	switch scheme {
	case SchemeRegistry:
		return parseRegistryReference(rest)
	case SchemeLayout:
		return parseLayoutReference(rest)
	default:
		return Reference{}, fault.New(fault.CodeInvalidInput, referenceOp,
			fmt.Sprintf("reference scheme %q is not supported; use %s:// or %s://",
				scheme, SchemeRegistry, SchemeLayout))
	}
}

func parseRegistryReference(raw string) (Reference, error) {
	// Parse, not ParseNormalizedNamed: normalization is what inserts
	// docker.io and the library/ prefix, and DevProof does not guess which
	// registry a user meant.
	named, err := reference.Parse(raw)
	if err != nil {
		return Reference{}, fault.Wrap(fault.CodeInvalidInput, referenceOp,
			fmt.Sprintf("registry reference %q is malformed", raw), err)
	}

	withName, ok := named.(reference.Named)
	if !ok {
		return Reference{}, fault.New(fault.CodeInvalidInput, referenceOp,
			fmt.Sprintf("reference %q names no repository", raw))
	}

	domain := reference.Domain(withName)
	if domain == "" || !strings.ContainsAny(domain, ".:") && domain != "localhost" {
		return Reference{}, fault.New(fault.CodeInvalidInput, referenceOp,
			fmt.Sprintf("reference %q has no registry host; write it in full, such as "+
				"registry.example.com/team/config:v1", raw))
	}

	ref := Reference{
		Scheme:     SchemeRegistry,
		Registry:   domain,
		Repository: reference.Path(withName),
	}
	if tagged, ok := named.(reference.Tagged); ok {
		ref.Tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		ref.Digest = digested.Digest().String()
	}
	if err := ref.validate(raw); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

func parseLayoutReference(raw string) (Reference, error) {
	path, tag, digest, err := splitLocator(raw)
	if err != nil {
		return Reference{}, err
	}
	if path == "" {
		return Reference{}, fault.New(fault.CodeInvalidInput, referenceOp,
			"layout reference names no directory")
	}

	ref := Reference{Scheme: SchemeLayout, Path: path, Tag: tag, Digest: digest}
	if err := ref.validate(raw); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

// splitLocator separates a path from a trailing tag or digest.
//
// The digest separator is checked first and the tag separator only after the
// last path element, so that a colon inside a directory name is not mistaken
// for a tag.
func splitLocator(raw string) (path, tag, digest string, err error) {
	base := raw

	if prefix, encoded, found := strings.Cut(raw, "@"); found {
		if strings.Contains(encoded, "@") {
			return "", "", "", fault.New(fault.CodeInvalidInput, referenceOp,
				"reference contains more than one digest separator")
		}
		if _, parseErr := bundle.ParseDigest(encoded); parseErr != nil {
			return "", "", "", fault.Wrap(fault.CodeInvalidInput, referenceOp,
				"reference digest is invalid", parseErr)
		}
		digest = encoded
		base = prefix
	}

	// The tag is parsed out of the remainder even when a digest was present,
	// so that a reference carrying both is detected rather than silently
	// folding the tag into the path.
	lastSlash := strings.LastIndex(base, "/")
	if colon := strings.LastIndex(base, ":"); colon > lastSlash {
		tag = base[colon+1:]
		base = base[:colon]
	}
	return base, tag, digest, nil
}

func (r Reference) validate(raw string) error {
	if r.Tag != "" && r.Digest != "" {
		// Both is not an error in the OCI grammar, but it is ambiguous about
		// which one identifies the content, and DevProof always works from
		// the digest. Requiring one keeps the answer obvious.
		return fault.New(fault.CodeInvalidInput, referenceOp,
			fmt.Sprintf("reference %q gives both a tag and a digest; supply one", raw))
	}
	if r.Digest != "" {
		if _, err := bundle.ParseDigest(r.Digest); err != nil {
			return fault.Wrap(fault.CodeInvalidInput, referenceOp, "reference digest is invalid", err)
		}
	}
	return nil
}

// IsDigest reports whether the reference names immutable content.
func (r Reference) IsDigest() bool { return r.Digest != "" }

// IsRegistry reports whether the reference addresses a registry.
func (r Reference) IsRegistry() bool { return r.Scheme == SchemeRegistry }

// Locator returns the scheme-specific location without any tag or digest:
// "registry/repository" for a registry, or the directory for a layout.
func (r Reference) Locator() string {
	if r.Scheme == SchemeLayout {
		return r.Path
	}
	return r.Registry + "/" + r.Repository
}

// String renders the reference in its canonical form.
func (r Reference) String() string {
	var b strings.Builder
	b.WriteString(r.Scheme)
	b.WriteString("://")
	b.WriteString(r.Locator())
	switch {
	case r.Digest != "":
		b.WriteByte('@')
		b.WriteString(r.Digest)
	case r.Tag != "":
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	return b.String()
}

// WithDigest returns a copy pinned to a digest, dropping any tag.
//
// This is how a resolved tag stops being a tag. Every step after resolution
// takes the pinned reference, so there is no later code path that could
// consult the name again (DP-007).
func (r Reference) WithDigest(digest string) Reference {
	out := r
	out.Tag = ""
	out.Digest = digest
	return out
}

// Target returns the string a transport should address: the digest when the
// reference has one, otherwise the tag.
func (r Reference) Target() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}
