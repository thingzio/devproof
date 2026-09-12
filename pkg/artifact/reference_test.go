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
	stderrors "errors"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/fault"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want Reference
	}{
		{
			"bare registry reference with a tag",
			"registry.example.com/team/config:v1",
			Reference{Scheme: SchemeRegistry, Registry: "registry.example.com",
				Repository: "team/config", Tag: "v1"},
		},
		{
			"explicit scheme",
			"oci://registry.example.com/team/config:v1",
			Reference{Scheme: SchemeRegistry, Registry: "registry.example.com",
				Repository: "team/config", Tag: "v1"},
		},
		{
			"digest reference",
			"oci://registry.example.com/team/config@" + testDigest,
			Reference{Scheme: SchemeRegistry, Registry: "registry.example.com",
				Repository: "team/config", Digest: testDigest},
		},
		{
			"no tag or digest",
			"registry.example.com/team/config",
			Reference{Scheme: SchemeRegistry, Registry: "registry.example.com",
				Repository: "team/config"},
		},
		{
			"host with a port",
			"localhost:5000/team/config:v1",
			Reference{Scheme: SchemeRegistry, Registry: "localhost:5000",
				Repository: "team/config", Tag: "v1"},
		},
		{
			"nested repository path",
			"registry.example.com/org/team/config:v1",
			Reference{Scheme: SchemeRegistry, Registry: "registry.example.com",
				Repository: "org/team/config", Tag: "v1"},
		},
		{
			"layout",
			"oci-layout://./artifact",
			Reference{Scheme: SchemeLayout, Path: "./artifact"},
		},
		{
			"layout with a tag",
			"oci-layout://./artifact:v1",
			Reference{Scheme: SchemeLayout, Path: "./artifact", Tag: "v1"},
		},
		{
			"layout with a digest",
			"oci-layout://./artifact@" + testDigest,
			Reference{Scheme: SchemeLayout, Path: "./artifact", Digest: testDigest},
		},
		{
			"absolute layout path",
			"oci-layout:///var/lib/bundles/artifact",
			Reference{Scheme: SchemeLayout, Path: "/var/lib/bundles/artifact"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseReference(tc.raw)
			if err != nil {
				t.Fatalf("ParseReference(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("= %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// A reference with no registry host must fail rather than silently reaching
// out to Docker Hub. Guessing which registry someone meant is exactly the
// ambient behavior DP-012 excludes.
func TestParseReferenceRequiresAnExplicitRegistry(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"ubuntu:latest", "team/config:v1", "config"} {
		got, err := ParseReference(raw)
		if err == nil {
			t.Errorf("ParseReference(%q) = %+v, want a rejection", raw, got)
			continue
		}
		if !strings.Contains(err.Error(), "registry host") {
			t.Errorf("ParseReference(%q) error does not explain the problem: %v", raw, err)
		}
	}
}

func TestParseReferenceRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"unknown scheme", "https://registry.example.com/team/config"},
		{"file scheme", "file:///etc/passwd"},
		{"malformed registry reference", "registry.example.com/TEAM/Config:v1"},
		{"invalid digest", "registry.example.com/team/config@sha256:nothex"},
		{"unsupported digest algorithm", "oci-layout://./artifact@md5:abcd"},
		{"layout with no path", "oci-layout://"},
		{
			// Ambiguous about which one identifies the content. DevProof
			// always works from the digest, so requiring one keeps the
			// answer obvious.
			"both tag and digest",
			"oci-layout://./artifact:v1@" + testDigest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseReference(tc.raw); !stderrors.Is(err, fault.CodeInvalidInput) {
				t.Errorf("ParseReference(%q) code = %q, want %q",
					tc.raw, fault.CodeOf(err), fault.CodeInvalidInput)
			}
		})
	}
}

func TestReferenceString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{"registry.example.com/team/config:v1", "oci://registry.example.com/team/config:v1"},
		{
			"oci://registry.example.com/team/config@" + testDigest,
			"oci://registry.example.com/team/config@" + testDigest,
		},
		{"oci-layout://./artifact", "oci-layout://./artifact"},
		{"oci-layout://./artifact:v1", "oci-layout://./artifact:v1"},
	}

	for _, tc := range tests {
		ref, err := ParseReference(tc.raw)
		if err != nil {
			t.Fatalf("ParseReference(%q): %v", tc.raw, err)
		}
		if got := ref.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
		// The canonical form must parse back to the same reference.
		back, err := ParseReference(ref.String())
		if err != nil {
			t.Fatalf("re-parsing %q: %v", ref.String(), err)
		}
		if back != ref {
			t.Errorf("round trip changed %+v into %+v", ref, back)
		}
	}
}

// WithDigest is how a resolved tag stops being a tag. Leaving the tag behind
// would let a later step consult the name again (DP-007).
func TestWithDigestDropsTheTag(t *testing.T) {
	t.Parallel()

	ref, err := ParseReference("registry.example.com/team/config:v1")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}

	pinned := ref.WithDigest(testDigest)

	if pinned.Tag != "" {
		t.Errorf("the tag survived pinning: %q", pinned.Tag)
	}
	if pinned.Digest != testDigest {
		t.Errorf("digest = %q", pinned.Digest)
	}
	if !pinned.IsDigest() {
		t.Error("a pinned reference does not report IsDigest")
	}
	if ref.Tag != "v1" {
		t.Error("WithDigest mutated its receiver")
	}
}

func TestReferenceTargetPrefersDigest(t *testing.T) {
	t.Parallel()

	tagged, err := ParseReference("registry.example.com/team/config:v1")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if got := tagged.Target(); got != "v1" {
		t.Errorf("Target() = %q, want the tag", got)
	}
	if got := tagged.WithDigest(testDigest).Target(); got != testDigest {
		t.Errorf("Target() = %q, want the digest", got)
	}

	bare, err := ParseReference("registry.example.com/team/config")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if got := bare.Target(); got != "" {
		t.Errorf("Target() on a bare reference = %q, want empty", got)
	}
}

func TestReferenceLocator(t *testing.T) {
	t.Parallel()

	registry, err := ParseReference("registry.example.com/team/config:v1")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if got := registry.Locator(); got != "registry.example.com/team/config" {
		t.Errorf("Locator() = %q", got)
	}
	if !registry.IsRegistry() {
		t.Error("a registry reference does not report IsRegistry")
	}

	layout, err := ParseReference("oci-layout://./artifact:v1")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if got := layout.Locator(); got != "./artifact" {
		t.Errorf("Locator() = %q", got)
	}
	if layout.IsRegistry() {
		t.Error("a layout reference reports IsRegistry")
	}
}

// A colon in a path is not a tag separator unless a tag could actually follow
// it. Comparing the colon only against the last forward slash split
// "C:\dir\layout" into the repository "C" and the tag "\dir\layout",
// because there was no forward slash to beat.
//
// The registry-port cases are here to hold the fix honest: those must keep
// parsing exactly as before.
func TestColonIsOnlyATagWhenNoSeparatorFollows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		tag  string
	}{
		{"colon then backslashes", `oci-layout://C:\Users\runner\Temp\layout`, ""},
		{"colon then forward slashes", "oci-layout://C:/Users/runner/Temp/layout", ""},
		{"colon in path, tag at the end", `oci-layout://C:\Temp\layout:v1`, "v1"},
		{"relative path with a tag", "oci-layout://./layout:v1", "v1"},
		{"relative path, no tag", "oci-layout://./layout", ""},
		{"registry port is not a tag", "oci://registry.example.com:5000/team/config", ""},
		{"registry port with a tag", "oci://registry.example.com:5000/team/config:v1", "v1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ref, err := ParseReference(tc.raw)
			if err != nil {
				t.Fatalf("ParseReference(%q): %v", tc.raw, err)
			}
			if ref.Tag != tc.tag {
				t.Errorf("ParseReference(%q).Tag = %q, want %q", tc.raw, ref.Tag, tc.tag)
			}
		})
	}
}

// The whole path must survive, not be split at the first colon.
func TestPathWithAColonRoundTrips(t *testing.T) {
	t.Parallel()

	const raw = `oci-layout://C:\Users\runner\Temp\layout`

	ref, err := ParseReference(raw)
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if ref.Path != `C:\Users\runner\Temp\layout` {
		t.Errorf("Path = %q, want the full drive path", ref.Path)
	}
}

// ParseReference is the first thing that touches a string a user, a manifest,
// or a registry response supplied. It must classify or reject anything without
// panicking, and it must never invent a reference that claims both a tag and a
// digest — that combination is ambiguous about which one identifies content.
func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"", ":", "@", "://", "oci://",
		"oci-layout://./layout:v1",
		"oci://registry.example.com:5000/team/config:v1",
		"oci://registry.example.com/team/config@sha256:" + strings.Repeat("a", 64),
		`oci-layout://C:\dir\layout`,
		"oci://a@sha256:x@sha256:y",
		"\x00", "oci://\x00", strings.Repeat(":", 64),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := ParseReference(raw)
		if err != nil {
			return
		}
		if ref.Tag != "" && ref.Digest != "" {
			t.Fatalf("ParseReference(%q) accepted both a tag %q and a digest %q",
				raw, ref.Tag, ref.Digest)
		}
		if ref.Scheme == "" {
			t.Fatalf("ParseReference(%q) returned no scheme", raw)
		}
		// Parsing is a pure function of its input: the same string must not
		// resolve two ways in one process.
		again, againErr := ParseReference(raw)
		if againErr != nil || again != ref {
			t.Fatalf("ParseReference(%q) is not deterministic", raw)
		}
	})
}
