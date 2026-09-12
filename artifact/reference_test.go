package artifact

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
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
