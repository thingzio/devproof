// Package version reports the build identity of this DevProof binary.
//
// Build identity is diagnostic and provenance material only. It never reaches
// canonical artifact bytes: two builds of different DevProof versions that
// package the same canonical tree must produce the same subject digest
// (DP-002, DP-012).
package version

import "runtime/debug"

// Injected at link time by the build. Left unset, they fall back to whatever
// the Go module system recorded, so a `go install`ed binary still reports
// something truthful rather than "unknown".
var (
	version = ""
	commit  = ""
)

// Version reports the release version, such as "v1.2.3", or "dev" for an
// untagged build.
func Version() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// Commit reports the source revision, or "unknown" when it cannot be
// established.
func Commit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return "unknown"
}

// UserAgent is the value sent on outbound registry and Git requests. It names
// the tool and version only: never a hostname, username, or repository.
func UserAgent() string {
	return "devproof/" + Version()
}
