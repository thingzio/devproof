package safefs

import "github.com/thingzio/devproof/internal/canonical"

// canonicalPath converts a test string to a canonical.Path without
// validation, so that a test can hand Open a path the normalizer would have
// rejected and confirm Open refuses it on its own.
func canonicalPath(s string) canonical.Path { return canonical.Path(s) }
