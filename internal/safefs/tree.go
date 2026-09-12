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
	"context"
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
)

const treeOp = "safefs.tree"

// TreeEntry is one file from a non-filesystem source.
type TreeEntry struct {
	// Path is source-relative and slash-separated.
	Path string
	// Mode is already normalized to bundle.ModeFile or ModeExecutable. The
	// source decides, because only it knows whether an execute bit is
	// authoritative — for Git it is the tree entry, for a filesystem it is
	// the stat.
	Mode uint32
	// Size is the entry's declared length, used for limit checks before any
	// bytes are read.
	Size int64
	// Open returns the entry's content.
	Open func() (io.ReadCloser, error)
}

// TreeSource yields entries from a source that is not a directory tree.
//
// It exists so that a Git resolver can hand over blobs from a commit object
// without ever materializing a working directory, where checkout filters
// would rewrite the bytes.
type TreeSource interface {
	Walk(yield func(TreeEntry) error) error
}

// TreeOptions configures a tree snapshot.
type TreeOptions struct {
	Patterns *bundle.PatternSet
	Limits   bundle.Limits
	TempRoot string
}

// SnapshotTree copies a non-filesystem source into a private workspace.
//
// It is the same contract as [SnapshotDir] — content hashed on the way in,
// stored privately, read back through the same digests — for sources that
// have no directory to walk.
func SnapshotTree(ctx context.Context, tree TreeSource, opts TreeOptions) (_ *Snapshot, retErr error) {
	limits := opts.Limits.WithDefaults()

	patterns := opts.Patterns
	if patterns == nil {
		selectAll, err := bundle.NewPatternSet(nil, nil)
		if err != nil {
			return nil, err
		}
		patterns = selectAll
	}

	ws, err := NewWorkspace(opts.TempRoot, "devproof-tree-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, ws.Close())
		}
	}()

	walker := &treeWalker{
		ctx:      ctx,
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

	if err := tree.Walk(walker.entry); err != nil {
		return nil, err
	}

	// Sorted here rather than relying on the source's iteration order, which
	// is the source's business and not an input to identity (DP-012).
	slices.SortFunc(walker.records, func(a, b canonical.FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})

	var paths canonical.PathSet
	for _, record := range walker.records {
		if err := paths.Add(record.Path); err != nil {
			return nil, err
		}
	}

	return &Snapshot{ws: ws, records: walker.records}, nil
}

type treeWalker struct {
	ctx        context.Context
	ws         *Workspace
	patterns   *bundle.PatternSet
	limits     bundle.Limits
	pathLimits canonical.PathLimits
	buf        []byte

	records   []canonical.FileRecord
	totalSize int64
}

func (w *treeWalker) entry(entry TreeEntry) error {
	if err := fault.FromContext(w.ctx, treeOp, "snapshot canceled"); err != nil {
		return err
	}
	if entry.Mode != bundle.ModeFile && entry.Mode != bundle.ModeExecutable {
		return fault.New(fault.CodeInternal, treeOp,
			fmt.Sprintf("tree source supplied unnormalized mode %#o", entry.Mode)).
			WithPath(entry.Path)
	}

	bundlePath, err := canonical.NormalizePath(entry.Path, w.pathLimits)
	if err != nil {
		return err
	}
	if !w.patterns.Selects(string(bundlePath)) {
		return nil
	}

	if int64(len(w.records)) >= w.limits.MaxFiles {
		return fault.New(fault.CodeLimitExceeded, treeOp,
			fmt.Sprintf("source contains more than %d files", w.limits.MaxFiles))
	}
	if entry.Size > w.limits.MaxFileBytes {
		return fault.New(fault.CodeLimitExceeded, treeOp,
			fmt.Sprintf("file is %d bytes, limit is %d", entry.Size, w.limits.MaxFileBytes)).
			WithPath(entry.Path)
	}

	digest, written, err := w.copyIntoWorkspace(entry, bundlePath)
	if err != nil {
		return err
	}
	// The declared size and the copied size must agree: a source that
	// misreports a length is either broken or is trying to slip past the
	// limit check above.
	if written != entry.Size {
		return fault.New(fault.CodeSourceResolution, treeOp,
			fmt.Sprintf("entry declares %d bytes but yielded %d", entry.Size, written)).
			WithPath(entry.Path)
	}

	w.totalSize += written
	if w.totalSize > w.limits.MaxExpandedBytes {
		return fault.New(fault.CodeLimitExceeded, treeOp,
			fmt.Sprintf("source exceeds the total size limit of %d bytes", w.limits.MaxExpandedBytes))
	}

	w.records = append(w.records, canonical.FileRecord{
		Path:   bundlePath,
		Mode:   entry.Mode,
		Size:   written,
		Digest: digest,
	})
	return nil
}

func (w *treeWalker) copyIntoWorkspace(entry TreeEntry, bundlePath canonical.Path) (
	_ canonical.Digest, _ int64, retErr error) {

	content, err := entry.Open()
	if err != nil {
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeSourceResolution, treeOp,
			"opening tree entry", err).WithPath(entry.Path)
	}
	defer func() {
		if closeErr := content.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, treeOp, "closing tree entry", closeErr)
		}
	}()

	target := storagePath(bundlePath)
	if mkdirErr := mkdirAllIn(w.ws.Root(), filepath.Dir(target)); mkdirErr != nil {
		return canonical.Digest{}, 0, mkdirErr
	}

	dest, err := w.ws.Root().OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeInternal, treeOp,
			"creating snapshot file", err).WithPath(string(bundlePath))
	}
	defer func() {
		if closeErr := dest.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, treeOp, "closing snapshot file", closeErr)
		}
	}()

	hasher := sha256.New()
	written, err := copyWithContext(w.ctx, io.MultiWriter(dest, hasher), content, w.buf)
	if err != nil {
		if ctxErr := fault.FromContext(w.ctx, treeOp, "snapshot canceled"); ctxErr != nil {
			return canonical.Digest{}, 0, ctxErr
		}
		return canonical.Digest{}, 0, fault.Wrap(fault.CodeSourceResolution, treeOp,
			"copying tree entry", err).WithPath(entry.Path)
	}

	var digest canonical.Digest
	hasher.Sum(digest[:0])
	return digest, written, nil
}
