// Package deflate is a frozen copy of the Go standard library's DEFLATE
// encoder.
//
// # Why this exists
//
// A DevProof subject digest is computed over the compressed layer, so the
// exact bytes a compressor emits are part of artifact identity (DP-002,
// DP-015). Neither the Go standard library nor any third-party compressor
// promises byte-stable output across releases; they are free to improve
// their match-finding at any time, and doing so is not considered a breaking
// change by anyone but us.
//
// Compiling against compress/flate would therefore mean that upgrading Go
// silently reissues every artifact DevProof has ever produced under a new
// identity, with nothing to detect it but a golden-vector test failing long
// after the upgrade shipped. Freezing the encoder here removes that coupling
// entirely: the toolchain moves, the bytes do not.
//
// # What was frozen
//
// Copied from Go 1.27.1, compress/flate, at the revision recorded in
// SOURCE-VERSION. Only the encoder is present. Decompression is deliberately
// left to the standard library, because inflating a valid DEFLATE stream is
// unambiguous — any correct implementation yields the same bytes — so there
// is nothing to pin.
//
// The only edits are the package clause and the extraction of InternalError,
// which the encoder references from the decoder's file. No logic is changed.
//
// # Rules for this directory
//
// Do not reformat, relint, refactor, or "modernize" anything here. The files
// are excluded from the formatters and most linters in .golangci.yaml for
// that reason, and some declarations are unused because their callers live
// in the decoder that was not copied. Any of those changes risks perturbing
// output for no benefit.
//
// Updating to a newer upstream encoder is a bundle format version decision,
// not a dependency bump. It requires new golden vectors under a new format
// version, and the old encoder must be retained for as long as v1 artifacts
// are produced.
//
// Provenance and license are recorded in the repository NOTICE and in the
// LICENSE file in this directory.
package deflate
