package safefs

import (
	"context"
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
)

const snapshotOp = "safefs.snapshot"

const copyBufferSize = 128 * 1024

// SnapshotOptions configures a source snapshot.
type SnapshotOptions struct {
	// Patterns filters source-relative paths. Nil selects everything.
	Patterns *bundle.PatternSet
	// Limits bounds what may be snapshotted.
	Limits bundle.Limits
	// TempRoot is the parent for the private workspace. Empty uses the
	// system temporary directory.
	TempRoot string
}

// Snapshot is a frozen, private copy of a source tree.
//
// Packaging reads only from here, never from the original location. That is
// what closes the time-of-check window: content is hashed as it is copied in,
// and hashed again as it is read out, so a source edited mid-build fails the
// operation instead of producing a bundle whose layer disagrees with the
// inventory that describes it.
//
// Paths are source-relative. A snapshot does not know where it will be
// mounted, which is what lets one source have a single tree digest no matter
// where composition places it.
type Snapshot struct {
	ws      *Workspace
	records []canonical.FileRecord
}

var _ canonical.ContentSource = (*Snapshot)(nil)

// Records returns the canonical inventory, sorted by path.
func (s *Snapshot) Records() []canonical.FileRecord { return slices.Clone(s.records) }

// Open returns the content of a path in the snapshot.
//
// Only a path that appears in the inventory can be opened. Anything else is
// refused before touching the filesystem, so there is no way to reach a file
// this snapshot did not record.
func (s *Snapshot) Open(_ context.Context, p canonical.Path) (io.ReadCloser, error) {
	idx := slices.IndexFunc(s.records, func(r canonical.FileRecord) bool { return r.Path == p })
	if idx < 0 {
		return nil, fault.New(fault.CodeInternal, snapshotOp,
			"path is not in the snapshot inventory").WithPath(string(p))
	}

	file, err := s.ws.Root().Open(storagePath(p))
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, snapshotOp, "opening snapshot content", err).
			WithPath(string(p))
	}
	return file, nil
}

// Close removes the snapshot's private storage.
func (s *Snapshot) Close() error { return s.ws.Close() }

// storagePath maps a canonical bundle path to its location in the workspace.
//
// Canonical paths are slash-separated by definition, and filepath.FromSlash
// is what makes that land correctly on a platform with a different separator.
func storagePath(p canonical.Path) string { return filepath.FromSlash(string(p)) }

// SnapshotDir copies a local directory into a private workspace.
//
// Every file is stat'd with Lstat and rejected unless it is a regular file.
// Following a symlink would let a source tree pull in content from anywhere
// the build account can read, and DP-005 excludes links from the portable
// profile precisely so that no consumer has to guess what one meant.
func SnapshotDir(ctx context.Context, dir string, opts SnapshotOptions) (_ *Snapshot, retErr error) {
	limits := opts.Limits.WithDefaults()

	patterns := opts.Patterns
	if patterns == nil {
		selectAll, err := bundle.NewPatternSet(nil, nil)
		if err != nil {
			return nil, err
		}
		patterns = selectAll
	}

	sourceRoot, err := openSourceRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := sourceRoot.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, snapshotOp, "closing source root", closeErr)
		}
	}()

	ws, err := NewWorkspace(opts.TempRoot, "devproof-snapshot-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, ws.Close())
		}
	}()

	walker := &snapshotWalker{
		ctx:      ctx,
		source:   sourceRoot,
		ws:       ws,
		patterns: patterns,
		limits:   limits,
		pathLimits: canonical.PathLimits{
			MaxBytes:        int(limits.MaxPathBytes),
			MaxSegmentBytes: int(limits.MaxPathSegmentBytes),
			MaxDepth:        int(limits.MaxPathDepth),
		},
		buf: make([]byte, copyBufferSize),
	}

	if err := walker.walk("."); err != nil {
		return nil, err
	}

	// Sorting here rather than relying on directory order is what makes the
	// result independent of the filesystem's enumeration (DP-012). Two
	// machines that list a directory differently must still produce the same
	// bundle.
	slices.SortFunc(walker.records, func(a, b canonical.FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})

	// Collision detection over the assembled set. Two source files whose
	// names differ only by case or Unicode form reach here as distinct
	// entries and must be refused before either is used.
	var paths canonical.PathSet
	for _, rec := range walker.records {
		if err := paths.Add(rec.Path); err != nil {
			return nil, err
		}
	}

	return &Snapshot{ws: ws, records: walker.records}, nil
}

// openSourceRoot opens dir for confined traversal, refusing a symlink.
func openSourceRoot(dir string) (*os.Root, error) {
	if dir == "" {
		return nil, fault.New(fault.CodeInvalidInput, snapshotOp, "source path must not be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, snapshotOp, "resolving source path", err)
	}

	// Lstat, not Stat: a source root that is itself a symlink is refused
	// rather than followed, so the manifest names what was actually read.
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, snapshotOp, "reading source path", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fault.New(fault.CodeUnsupportedFile, snapshotOp,
			"source path is a symlink; v1 does not follow links")
	}
	if !info.IsDir() {
		return nil, fault.New(fault.CodeInvalidInput, snapshotOp, "source path is not a directory")
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, snapshotOp, "opening source directory", err)
	}
	return root, nil
}

type snapshotWalker struct {
	ctx        context.Context
	source     *os.Root
	ws         *Workspace
	patterns   *bundle.PatternSet
	limits     bundle.Limits
	pathLimits canonical.PathLimits
	buf        []byte

	records   []canonical.FileRecord
	totalSize int64
}

func (w *snapshotWalker) walk(dir string) error {
	if err := fault.FromContext(w.ctx, snapshotOp, "snapshot canceled"); err != nil {
		return err
	}

	entries, err := w.readDir(dir)
	if err != nil {
		return err
	}

	// Sorted traversal makes the order files are visited, and therefore the
	// order limits are hit and errors are reported, identical on every run.
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

	for _, entry := range entries {
		child := entry.Name()
		if dir != "." {
			child = dir + "/" + entry.Name()
		}

		info, err := w.source.Lstat(child)
		if err != nil {
			return fault.Wrap(fault.CodeSourceResolution, snapshotOp, "reading source entry", err).
				WithPath(child)
		}

		switch {
		case info.IsDir():
			if err := w.walk(child); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := w.snapshotFile(child, info); err != nil {
				return err
			}
		default:
			return fault.New(fault.CodeUnsupportedFile, snapshotOp,
				fmt.Sprintf("%s is not a regular file; the v1 portable profile carries "+
					"regular files and derived directories only", describeMode(info.Mode()))).
				WithPath(child)
		}
	}
	return nil
}

func (w *snapshotWalker) readDir(dir string) ([]fs.DirEntry, error) {
	handle, err := w.source.Open(dir)
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, snapshotOp, "opening source directory", err).
			WithPath(dir)
	}
	defer func() { _ = handle.Close() }()

	entries, err := handle.ReadDir(-1)
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, snapshotOp, "listing source directory", err).
			WithPath(dir)
	}
	return entries, nil
}

func (w *snapshotWalker) snapshotFile(sourcePath string, info fs.FileInfo) (retErr error) {
	// The canonical form is derived before filtering so that patterns are
	// matched against the path the bundle would carry, not the one the
	// filesystem happened to spell.
	bundlePath, err := canonical.NormalizePath(sourcePath, w.pathLimits)
	if err != nil {
		return err
	}
	if !w.patterns.Selects(string(bundlePath)) {
		return nil
	}

	if int64(len(w.records)) >= w.limits.MaxFiles {
		return fault.New(fault.CodeLimitExceeded, snapshotOp,
			fmt.Sprintf("source contains more than %d files", w.limits.MaxFiles))
	}
	if info.Size() > w.limits.MaxFileBytes {
		return fault.New(fault.CodeLimitExceeded, snapshotOp,
			fmt.Sprintf("file is %d bytes, limit is %d", info.Size(), w.limits.MaxFileBytes)).
			WithPath(sourcePath)
	}

	// Hash and size come from the bytes actually copied, never from the
	// stat: a file that grows or shrinks during the copy is caught by the
	// comparison below rather than recorded at its old length.
	digest, written, err := w.copyIntoWorkspace(sourcePath, bundlePath)
	if err != nil {
		return err
	}
	if written != info.Size() {
		return fault.New(fault.CodeSourceResolution, snapshotOp,
			fmt.Sprintf("file changed while it was being read: stat reported %d bytes, copied %d",
				info.Size(), written)).WithPath(sourcePath)
	}

	w.totalSize += written
	if w.totalSize > w.limits.MaxExpandedBytes {
		return fault.New(fault.CodeLimitExceeded, snapshotOp,
			fmt.Sprintf("source exceeds the total size limit of %d bytes", w.limits.MaxExpandedBytes))
	}

	w.records = append(w.records, canonical.FileRecord{
		Path:   bundlePath,
		Mode:   normalizeMode(info.Mode()),
		Size:   written,
		Digest: digest,
	})
	return nil
}

func (w *snapshotWalker) copyIntoWorkspace(sourcePath string, bundlePath canonical.Path) (
	_ canonical.Digest, _ int64, retErr error) {

	source, err := w.source.Open(sourcePath)
	if err != nil {
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeSourceResolution, snapshotOp,
			"opening source file", err).WithPath(sourcePath)
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, snapshotOp, "closing source file", closeErr)
		}
	}()

	// Re-stat through the open descriptor. The Lstat that classified this
	// entry looked at a name; this looks at the file that was actually
	// opened, which is what defeats a swap between the two.
	opened, err := source.Stat()
	if err != nil {
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeSourceResolution, snapshotOp,
			"stat of opened source file", err).WithPath(sourcePath)
	}
	if !opened.Mode().IsRegular() {
		return canonical.Digest{}, 0, fault.New(fault.CodeUnsupportedFile, snapshotOp,
			"source entry was replaced by a non-regular file while it was being opened").
			WithPath(sourcePath)
	}

	target := storagePath(bundlePath)
	if mkdirErr := mkdirAllIn(w.ws.Root(), filepath.Dir(target)); mkdirErr != nil {
		return canonical.Digest{}, 0, mkdirErr
	}

	dest, err := w.ws.Root().OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeInternal, snapshotOp,
			"creating snapshot file", err).WithPath(string(bundlePath))
	}
	defer func() {
		if closeErr := dest.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, snapshotOp, "closing snapshot file", closeErr)
		}
	}()

	hasher := sha256.New()
	written, err := copyWithContext(w.ctx, io.MultiWriter(dest, hasher), source, w.buf)
	if err != nil {
		if ctxErr := fault.FromContext(w.ctx, snapshotOp, "snapshot canceled"); ctxErr != nil {
			return canonical.Digest{}, 0, ctxErr
		}
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeSourceResolution, snapshotOp,
			"copying source file", err).WithPath(sourcePath)
	}

	var digest canonical.Digest
	hasher.Sum(digest[:0])
	return digest, written, nil
}

// normalizeMode collapses a native file mode to one of the two the portable
// profile has.
//
// Any execute bit means executable. Setuid, setgid, sticky, and the
// read/write variations are discarded rather than preserved, so that a umask
// or a checkout order cannot change what a bundle contains (DP-005).
func normalizeMode(mode fs.FileMode) uint32 {
	if mode.Perm()&0o111 != 0 {
		return bundle.ModeExecutable
	}
	return bundle.ModeFile
}

func describeMode(mode fs.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symlink"
	case mode&os.ModeDevice != 0:
		return "a device"
	case mode&os.ModeNamedPipe != 0:
		return "a FIFO"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeIrregular != 0:
		return "an irregular file"
	default:
		return "an unsupported file type"
	}
}
