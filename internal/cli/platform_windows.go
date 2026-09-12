//go:build windows

package cli

// executableBitObservable reports whether the filesystem can tell an
// executable file from a non-executable one.
//
// False on Windows: os.Stat synthesizes a mode of 0666, or 0444 when the
// read-only attribute is set, and never reports an execute bit. NTFS has no
// equivalent — executability there is a property of the file extension and of
// ACLs, not of a permission bit the portable profile could read.
const executableBitObservable = false
