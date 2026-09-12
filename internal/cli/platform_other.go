//go:build !windows

package cli

// executableBitObservable reports whether the filesystem can tell an
// executable file from a non-executable one.
const executableBitObservable = true
