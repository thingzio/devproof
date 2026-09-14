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

package safefs

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

const extractOp = "safefs.extract"

// ExtractOptions configures expansion.
type ExtractOptions struct {
	// Destination is the directory to publish. It must not exist.
	Destination string
	// Config is the verified inventory the layer must match exactly.
	Config *bundle.Config
	// Limits bounds the expansion.
	Limits bundle.Limits
	// LayerDigest is the compressed layer's digest from the OCI descriptor.
	//
	// Checking every decoded entry against the inventory is not the same
	// claim as checking the bytes. A differently compressed archive holding
	// exactly the declared files satisfies every entry check and is still not
	// the layer the subject names, so identity has to be established over the
	// compressed stream itself.
	LayerDigest canonical.Digest
	// LayerSize is the compressed layer's size from the OCI descriptor.
	LayerSize int64
	// BeforePublish inspects the staged tree and can refuse it.
	//
	// Called after every entry has been written and verified, and before the
	// rename that publishes it. A hook that returns an error means nothing is
	// published -- not written and then removed, which is a weaker guarantee,
	// because content that briefly existed has already been readable by
	// anything watching the directory (DP-032).
	//
	// The filesystem is read-only and rooted at the staging directory, so a
	// hook cannot reach outside it or modify what it was asked to judge.
	BeforePublish func(fs.FS) error
}

// ExtractResult reports what was published.
type ExtractResult struct {
	Destination string
	FileCount   int64
	TotalBytes  int64
}

// Extract expands a compressed layer into a new directory.
//
// Extraction and verification are one operation. Every entry is checked
// against the config inventory before its destination is opened, and its
// bytes are hashed as they are written, so nothing is ever on disk that has
// not been verified. The result is assembled in a private staging directory
// and published with an exclusive rename, which is what makes a failed,
// canceled, or interrupted expansion leave no destination at all rather than
// a partial one that looks finished (DP-008, DP-022).
func Extract(ctx context.Context, layer io.Reader, opts ExtractOptions) (_ *ExtractResult, retErr error) {
	if !exclusiveRenameSupported {
		return nil, fault.New(fault.CodeInternal, extractOp,
			"this platform has no atomic exclusive rename, so an expansion cannot be "+
				"published safely")
	}
	if opts.Destination == "" {
		return nil, fault.New(fault.CodeInvalidInput, extractOp, "destination must not be empty")
	}
	if opts.Config == nil {
		return nil, fault.New(fault.CodeInternal, extractOp,
			"extraction requires a verified config inventory")
	}

	limits := opts.Limits.WithDefaults()

	destination, err := filepath.Abs(opts.Destination)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, extractOp, "resolving destination", err)
	}

	// A pre-flight check so the common case reports a clear error rather
	// than an EEXIST from the rename at the very end. It is not the
	// safeguard; the exclusive rename is.
	if _, statErr := os.Lstat(destination); statErr == nil {
		return nil, fault.New(fault.CodeDestinationExists, extractOp,
			"destination already exists").WithPath(destination)
	} else if !os.IsNotExist(statErr) {
		return nil, fault.Wrap(fault.CodeInvalidInput, extractOp, "checking destination", statErr)
	}

	// Staging is a sibling of the destination so that publication is a
	// same-filesystem rename. A configurable temporary root would not be:
	// across filesystems the rename degrades to a copy, and atomicity is
	// exactly what cannot be given up here (DP-022).
	staging, err := NewWorkspace(filepath.Dir(destination), ".devproof-staging-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, staging.Close())
		}
	}()

	extractor := &extractor{
		ctx:           ctx,
		root:          staging.Root(),
		limits:        limits,
		expected:      inventoryIndex(opts.Config),
		buf:           make([]byte, copyBufferSize),
		expectDigest:  opts.LayerDigest,
		expectedBytes: opts.LayerSize,
	}
	if err := extractor.run(layer); err != nil {
		return nil, err
	}

	if err := extractor.verifyInventoryComplete(); err != nil {
		return nil, err
	}

	// Modes are applied only now, after every byte has been verified. Files
	// are written owner-only while their content is still in question, so a
	// half-written executable is never briefly executable.
	if err := extractor.applyModes(); err != nil {
		return nil, err
	}

	// The last point at which refusing costs nothing. Everything is written
	// and verified, and the destination does not exist yet.
	if opts.BeforePublish != nil {
		if err := opts.BeforePublish(os.DirFS(staging.Path())); err != nil {
			return nil, err
		}
	}

	// Every handle on the staging directory must be closed before it is
	// moved. Windows refuses to rename a directory that anything still holds
	// open, so leaving the confined root open failed the expansion at its very
	// last step, after all the work was done and verified.
	if err := staging.ReleaseHandle(); err != nil {
		return nil, err
	}

	if err := exclusiveRename(staging.Path(), destination); err != nil {
		if os.IsExist(err) || stderrors.Is(err, os.ErrExist) {
			return nil, fault.Wrap(fault.CodeDestinationExists, extractOp,
				"destination appeared while the expansion was in progress", err).
				WithPath(destination)
		}
		return nil, fault.Wrap(fault.CodeInternal, extractOp, "publishing the expansion", err).
			WithPath(destination)
	}
	staging.Detach()

	return &ExtractResult{
		Destination: destination,
		FileCount:   int64(len(extractor.seen)),
		TotalBytes:  extractor.totalBytes,
	}, nil
}

// VerifyLayerOptions configures a validate-only pass over a layer.
type VerifyLayerOptions struct {
	// Config is the inventory the layer must match exactly.
	Config *bundle.Config
	// Limits bounds the work.
	Limits bundle.Limits
	// LayerDigest and LayerSize come from the OCI layer descriptor.
	LayerDigest canonical.Digest
	LayerSize   int64
}

// VerifyLayerResult reports what a validate-only pass observed.
type VerifyLayerResult struct {
	FileCount  int64
	TotalBytes int64
}

// VerifyLayer streams a layer and checks it without writing anything.
//
// It runs the identical checks Extract runs — compressed identity, gzip
// framing, path canonicalization, inventory agreement, per-entry size and
// content digests, and every limit — and differs only in having nowhere to
// put the bytes. Sharing one implementation is the point: a verifier that
// checked less than the extractor would report a pass the extractor then
// refused, and a verifier that checked differently would eventually disagree
// with it about something subtler.
func VerifyLayer(ctx context.Context, layer io.Reader, opts VerifyLayerOptions) (*VerifyLayerResult, error) {
	if opts.Config == nil {
		return nil, fault.New(fault.CodeInternal, extractOp,
			"verification requires a config inventory")
	}

	verifier := &extractor{
		ctx:           ctx,
		root:          nil, // validate-only
		limits:        opts.Limits.WithDefaults(),
		expected:      inventoryIndex(opts.Config),
		buf:           make([]byte, copyBufferSize),
		expectDigest:  opts.LayerDigest,
		expectedBytes: opts.LayerSize,
	}
	if err := verifier.run(layer); err != nil {
		return nil, err
	}
	if err := verifier.verifyInventoryComplete(); err != nil {
		return nil, err
	}
	return &VerifyLayerResult{
		FileCount:  int64(len(verifier.seen)),
		TotalBytes: verifier.totalBytes,
	}, nil
}

func inventoryIndex(cfg *bundle.Config) map[string]bundle.ConfigFile {
	index := make(map[string]bundle.ConfigFile, len(cfg.Files))
	for _, file := range cfg.Files {
		index[file.Path] = file
	}
	return index
}

type extractor struct {
	ctx      context.Context
	root     *os.Root
	limits   bundle.Limits
	expected map[string]bundle.ConfigFile
	buf      []byte

	seen         map[string]struct{}
	directories  map[string]struct{}
	totalBytes   int64
	compressedIn int64

	// expectDigest and expectedBytes come from the OCI layer descriptor. A
	// zero digest means the caller has no descriptor to check against, which
	// is only true for tests that construct a layer directly.
	expectDigest  canonical.Digest
	expectedBytes int64
}

// writes reports whether this run publishes anything.
//
// A nil root is validate-only: every check still runs and every byte is still
// hashed, but nothing is created. It is the same code path Verify and Expand
// both need, and keeping it one path is what stops the two from disagreeing
// about what "integrity" means.
func (e *extractor) writes() bool { return e.root != nil }

func (e *extractor) run(layer io.Reader) error {
	e.seen = make(map[string]struct{}, len(e.expected))
	e.directories = make(map[string]struct{})

	// The compressed stream is hashed as it is consumed, before gzip sees it,
	// so the digest covers exactly the bytes that arrived rather than
	// anything reconstructed afterwards.
	layerHash := sha256.New()
	counted := &countingReader{r: io.TeeReader(layer, layerHash)}
	buffered := bufio.NewReader(counted)

	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, extractOp, "layer is not valid gzip", err)
	}
	// A gzip stream may legally contain several members. Format v1 has one,
	// and accepting more would let content be appended past the bytes the
	// descriptor covers.
	gzipReader.Multistream(false)

	limited := &limitedReader{
		r:     gzipReader,
		limit: e.limits.MaxExpandedBytes,
		err: fault.New(fault.CodeLimitExceeded, extractOp,
			fmt.Sprintf("expanded payload exceeds the limit of %d bytes", e.limits.MaxExpandedBytes)),
	}

	tarReader := tar.NewReader(limited)
	for {
		if err := fault.FromContext(e.ctx, extractOp, "extraction canceled"); err != nil {
			return stderrors.Join(err, gzipReader.Close())
		}

		header, err := tarReader.Next()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return stderrors.Join(classifyTarError(err), gzipReader.Close())
		}
		if err := e.entry(tarReader, header); err != nil {
			return stderrors.Join(err, gzipReader.Close())
		}
	}

	// Drain whatever remains inside this member so that trailing bytes are
	// counted against the limit rather than ignored.
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return stderrors.Join(classifyTarError(err), gzipReader.Close())
	}
	if err := gzipReader.Close(); err != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, extractOp, "closing the gzip stream", err)
	}

	// With Multistream(false), anything left in the reader is a second
	// member or appended junk. Either way it is content the layer descriptor
	// does not cover.
	if _, err := buffered.Peek(1); !stderrors.Is(err, io.EOF) {
		if err != nil {
			return fault.Wrap(fault.CodeInvalidArtifact, extractOp, "inspecting the gzip trailer", err)
		}
		return fault.New(fault.CodeInvalidArtifact, extractOp,
			"layer contains trailing or concatenated gzip data")
	}

	e.compressedIn = counted.n
	if err := e.verifyLayerIdentity(layerHash); err != nil {
		return err
	}
	return e.checkCompressionRatio()
}

// verifyLayerIdentity compares the consumed stream against its descriptor.
//
// Checked after the archive has been read rather than before, because the
// digest is only known once the last byte has passed through, and buffering
// the layer to check it first would make memory track payload size (DP-033).
// Nothing has been published at this point: files are written owner-only into
// a private staging directory and are only made visible by the exclusive
// rename that happens after this returns.
func (e *extractor) verifyLayerIdentity(hasher hash.Hash) error {
	if e.expectDigest == (canonical.Digest{}) {
		return nil
	}

	if e.expectedBytes > 0 && e.compressedIn != e.expectedBytes {
		return fault.New(fault.CodeDigestMismatch, extractOp,
			fmt.Sprintf("layer is %d compressed bytes, the descriptor declares %d",
				e.compressedIn, e.expectedBytes))
	}

	var observed canonical.Digest
	hasher.Sum(observed[:0])
	if observed != e.expectDigest {
		return fault.New(fault.CodeDigestMismatch, extractOp,
			fmt.Sprintf("layer content is %s, the descriptor declares %s",
				observed, e.expectDigest))
	}
	return nil
}

func (e *extractor) checkCompressionRatio() error {
	if e.compressedIn <= 0 || e.totalBytes <= 0 {
		return nil
	}
	if ratio := e.totalBytes / e.compressedIn; ratio > e.limits.MaxCompressionRatio {
		return fault.New(fault.CodeLimitExceeded, extractOp,
			fmt.Sprintf("layer expands %d:1, limit is %d:1", ratio, e.limits.MaxCompressionRatio))
	}
	return nil
}

func (e *extractor) entry(r io.Reader, header *tar.Header) error {
	name := strings.TrimSuffix(header.Name, "/")

	// The inventory is consulted before anything is created. An entry the
	// config does not describe is refused here, so an archive cannot smuggle
	// a file past verification by placing it early in the stream.
	switch header.Typeflag {
	case tar.TypeDir:
		return e.directory(name)
	case tar.TypeReg:
		return e.file(r, name)
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		// archive/tar applies PAX records to the following header itself.
		return nil
	default:
		return fault.New(fault.CodeUnsupportedFile, extractOp,
			fmt.Sprintf("layer contains an entry of unsupported type %q", header.Typeflag)).
			WithPath(name)
	}
}

func (e *extractor) directory(name string) error {
	validated, err := e.validatePath(name)
	if err != nil {
		return err
	}
	if _, exists := e.expected[string(validated)]; exists {
		return fault.New(fault.CodeInvalidArtifact, extractOp,
			"layer contains a directory where the inventory declares a file").
			WithPath(string(validated))
	}
	if _, duplicate := e.directories[string(validated)]; duplicate {
		return fault.New(fault.CodeInvalidArtifact, extractOp,
			"layer contains a duplicate directory entry").WithPath(string(validated))
	}
	e.directories[string(validated)] = struct{}{}

	if err := e.ensureNodeBudget(); err != nil {
		return err
	}
	if !e.writes() {
		return nil
	}
	return mkdirAllIn(e.root, storagePath(validated))
}

func (e *extractor) file(r io.Reader, name string) (retErr error) {
	validated, err := e.validatePath(name)
	if err != nil {
		return err
	}
	key := string(validated)

	expected, declared := e.expected[key]
	if !declared {
		return fault.New(fault.CodeInvalidArtifact, extractOp,
			"layer contains a file the inventory does not declare").WithPath(key)
	}
	if _, duplicate := e.seen[key]; duplicate {
		return fault.New(fault.CodeInvalidArtifact, extractOp,
			"layer contains a duplicate entry").WithPath(key)
	}
	if budgetErr := e.ensureNodeBudget(); budgetErr != nil {
		return budgetErr
	}

	// Validate-only still hashes every byte; it just has nowhere to put them.
	sink := io.Discard
	if e.writes() {
		target := storagePath(validated)
		if mkdirErr := mkdirAllIn(e.root, filepath.Dir(target)); mkdirErr != nil {
			return mkdirErr
		}

		// O_EXCL, and no O_NOFOLLOW needed: os.Root resolves every component
		// against a held directory handle and refuses to traverse a symlink
		// out of the staging tree. Mode 0600 while the content is unverified.
		dest, openErr := e.root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			if os.IsExist(openErr) {
				return fault.New(fault.CodeInvalidArtifact, extractOp,
					"layer entry conflicts with something already extracted").WithPath(key)
			}
			return fault.Wrap(fault.CodeInternal, extractOp, "creating extracted file", openErr).
				WithPath(key)
		}
		defer func() {
			if closeErr := dest.Close(); closeErr != nil && retErr == nil {
				retErr = fault.Wrap(fault.CodeInternal, extractOp,
					"closing extracted file", closeErr).WithPath(key)
			}
		}()
		sink = dest
	}

	hasher := sha256.New()
	written, err := copyWithContext(e.ctx, io.MultiWriter(sink, hasher), r, e.buf)
	if err != nil {
		if ctxErr := fault.FromContext(e.ctx, extractOp, "extraction canceled"); ctxErr != nil {
			return ctxErr
		}
		return classifyTarError(err)
	}

	if written != expected.Size {
		return fault.New(fault.CodeDigestMismatch, extractOp,
			fmt.Sprintf("entry is %d bytes, the inventory declares %d", written, expected.Size)).
			WithPath(key)
	}
	var observed canonical.Digest
	hasher.Sum(observed[:0])
	if observed.String() != expected.Digest {
		return fault.New(fault.CodeDigestMismatch, extractOp,
			fmt.Sprintf("entry content is %s, the inventory declares %s", observed, expected.Digest)).
			WithPath(key)
	}

	e.seen[key] = struct{}{}
	e.totalBytes += written
	return nil
}

// validatePath re-canonicalizes an archive path from scratch.
//
// The archive is untrusted input, so its paths go through exactly the same
// normalization a source path does. Re-deriving the canonical form is what
// catches an entry that differs from an inventory path only by encoding,
// case, or a traversal segment.
func (e *extractor) validatePath(name string) (canonical.Path, error) {
	if name == "" {
		return "", fault.New(fault.CodeUnsafePath, extractOp, "layer contains an entry with no name")
	}
	return canonical.NormalizePath(name, canonical.PathLimits{
		MaxBytes:        int(e.limits.MaxPathBytes),
		MaxSegmentBytes: int(e.limits.MaxPathSegmentBytes),
		MaxDepth:        int(e.limits.MaxPathDepth),
	})
}

func (e *extractor) ensureNodeBudget() error {
	if int64(len(e.seen)+len(e.directories)) > e.limits.MaxFiles {
		return fault.New(fault.CodeLimitExceeded, extractOp,
			fmt.Sprintf("layer contains more than %d entries", e.limits.MaxFiles))
	}
	return nil
}

// verifyInventoryComplete checks that the layer delivered everything the
// config promised. Extra entries were refused as they arrived; this is the
// other half, and without it a truncated layer would publish a destination
// missing files that verification said were present.
func (e *extractor) verifyInventoryComplete() error {
	if len(e.seen) == len(e.expected) {
		return nil
	}
	for path := range e.expected {
		if _, ok := e.seen[path]; !ok {
			return fault.New(fault.CodeInvalidArtifact, extractOp,
				"the inventory declares a file the layer does not contain").WithPath(path)
		}
	}
	return fault.New(fault.CodeInvalidArtifact, extractOp,
		fmt.Sprintf("layer delivered %d files, the inventory declares %d",
			len(e.seen), len(e.expected)))
}

func (e *extractor) applyModes() error {
	for path, file := range e.expected {
		if err := fault.FromContext(e.ctx, extractOp, "extraction canceled"); err != nil {
			return err
		}
		if err := e.root.Chmod(storagePath(canonical.Path(path)), os.FileMode(file.Mode)); err != nil {
			return fault.Wrap(fault.CodeInternal, extractOp, "setting the canonical mode", err).
				WithPath(path)
		}
	}
	for dir := range e.directories {
		if err := e.root.Chmod(storagePath(canonical.Path(dir)), bundle.ModeDirectory); err != nil {
			return fault.Wrap(fault.CodeInternal, extractOp,
				"setting the canonical directory mode", err).WithPath(dir)
		}
	}
	return nil
}

// classifyTarError turns a reader failure into a typed one. A truncated or
// malformed archive is invalid input, not an internal fault, and reporting it
// as the latter would send someone looking for a bug in DevProof.
func classifyTarError(err error) error {
	switch {
	case err == nil:
		return nil
	case stderrors.Is(err, io.ErrUnexpectedEOF), stderrors.Is(err, io.EOF):
		return fault.Wrap(fault.CodeInvalidArtifact, extractOp, "layer is truncated", err)
	case fault.CodeOf(err) != fault.CodeInternal:
		return err
	default:
		return fault.Wrap(fault.CodeInvalidArtifact, extractOp, "layer is malformed", err)
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// limitedReader stops at limit and reports a typed error.
//
// io.LimitedReader reports EOF instead, which a tar reader would interpret as
// a clean end of archive — so a decompression bomb would look like a valid
// short archive rather than a rejected one.
type limitedReader struct {
	r     io.Reader
	limit int64
	n     int64
	err   error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		return 0, l.err
	}
	if int64(len(p)) > l.limit-l.n {
		p = p[:l.limit-l.n]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}
