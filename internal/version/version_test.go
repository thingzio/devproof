package version

import (
	"strings"
	"testing"
)

// Every accessor must return something usable even in a plain `go test`
// binary, where no link-time values were injected and the module version is
// "(devel)". A build identity of "" would end up embedded in provenance.
func TestAccessorsNeverReturnEmpty(t *testing.T) {
	t.Parallel()

	if got := Version(); got == "" {
		t.Error("Version returned an empty string")
	}
	if got := Commit(); got == "" {
		t.Error("Commit returned an empty string")
	}
}

func TestVersionPrefersInjectedValue(t *testing.T) {
	// Not parallel: these tests mutate package-level link-time variables.
	defer restore(version, commit)

	version = "v1.2.3"
	if got := Version(); got != "v1.2.3" {
		t.Errorf("Version = %q, want the injected %q", got, "v1.2.3")
	}
}

func TestCommitPrefersInjectedValue(t *testing.T) {
	defer restore(version, commit)

	commit = "0123abc"
	if got := Commit(); got != "0123abc" {
		t.Errorf("Commit = %q, want the injected %q", got, "0123abc")
	}
}

// A `go build`ed binary with nothing injected and no VCS stamp must still
// report a defined value rather than an empty one.
func TestVersionFallsBackToDev(t *testing.T) {
	defer restore(version, commit)

	version = ""
	if got := Version(); got == "" {
		t.Error("Version fell back to an empty string")
	}
}

// The user agent identifies the tool and nothing else. Registry and Git
// requests must not leak a hostname, username, or repository through it.
func TestUserAgentNamesOnlyTheTool(t *testing.T) {
	defer restore(version, commit)

	version = "v1.2.3"

	got := UserAgent()
	if got != "devproof/v1.2.3" {
		t.Errorf("UserAgent = %q, want %q", got, "devproof/v1.2.3")
	}
	if strings.ContainsAny(got, " ()") {
		t.Errorf("UserAgent %q contains comment syntax that could carry host detail", got)
	}
}

func restore(v, c string) {
	version, commit = v, c
}
