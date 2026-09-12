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
	"crypto/rand"
	"encoding/hex"
	stderrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/thingzio/devproof/internal/fault"
)

const workspaceOp = "safefs.workspace"

// privateDirMode is the mode every directory DevProof creates while work is
// in progress. Owner-only, so that a partially built tree is never readable
// or writable by anyone else while it is still incomplete.
const privateDirMode fs.FileMode = 0o700

// Workspace is a private scratch directory owned by one operation.
//
// It holds an [os.Root] rather than a path so that everything written inside
// it is resolved against a directory handle. That makes the confinement
// survive an attacker who introduces a symlink partway through the operation,
// which a path-prefix check would not.
type Workspace struct {
	path   string
	root   *os.Root
	closed bool
}

// NewWorkspace creates a private directory under parent.
//
// parent must already exist. An empty parent uses the system temporary
// directory, which is the right default for snapshots; expansion staging
// passes the destination's own parent instead, because publication has to be
// a same-filesystem rename (DP-022).
func NewWorkspace(parent, prefix string) (_ *Workspace, retErr error) {
	if prefix == "" {
		return nil, fault.New(fault.CodeInternal, workspaceOp, "workspace prefix must not be empty")
	}
	if parent == "" {
		parent = os.TempDir()
	}

	name, err := uniqueName(parent, prefix)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(name)
	if err != nil {
		// Best effort: the directory was created a moment ago and nothing
		// else knows its name, so failing to open it is already anomalous.
		retErr = fault.Wrap(fault.CodeInternal, workspaceOp, "opening workspace root", err)
		if removeErr := os.RemoveAll(name); removeErr != nil {
			retErr = stderrors.Join(retErr, fault.Wrap(fault.CodeInternal, workspaceOp,
				"removing workspace after a failed open", removeErr))
		}
		return nil, retErr
	}
	return &Workspace{path: name, root: root}, nil
}

// uniqueName creates a directory with an unpredictable name.
//
// The name comes from crypto/rand rather than a counter or the process id: a
// predictable name in a shared temporary directory lets someone else create
// it first and choose what DevProof is really writing into.
func uniqueName(parent, prefix string) (string, error) {
	for range 128 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", fault.Wrap(fault.CodeInternal, workspaceOp,
				"generating a workspace name", err)
		}
		name := filepath.Join(parent, prefix+hex.EncodeToString(suffix[:]))

		// O_EXCL semantics: Mkdir fails if the name exists, so losing a race
		// is a retry rather than a silent adoption of someone else's
		// directory.
		err := os.Mkdir(name, privateDirMode)
		switch {
		case err == nil:
			return name, nil
		case os.IsExist(err):
			continue
		default:
			return "", fault.Wrap(fault.CodeInternal, workspaceOp,
				"creating a workspace directory", err)
		}
	}
	return "", fault.New(fault.CodeInternal, workspaceOp,
		"could not find an unused workspace name after 128 attempts")
}

// Path returns the workspace's absolute path.
func (w *Workspace) Path() string { return w.path }

// Root returns the confined root for operations inside the workspace.
func (w *Workspace) Root() *os.Root { return w.root }

// ReleaseHandle closes the confined directory handle without giving up
// ownership.
//
// Publication has to happen with no handle open on the staging directory:
// Windows refuses to move a directory that anything still holds open, and the
// expansion would fail at the last step with a sharing violation. Ownership is
// kept, so a failure after this still removes the staging directory on Close —
// which works from the path and does not need the handle.
//
// Safe to call more than once.
func (w *Workspace) ReleaseHandle() error {
	if w.root == nil {
		return nil
	}
	err := w.root.Close()
	w.root = nil
	if err != nil {
		return fault.Wrap(fault.CodeInternal, workspaceOp, "closing workspace root", err)
	}
	return nil
}

// Detach gives up ownership, returning the path without removing it.
//
// Expansion uses this after a successful publication: the staging directory
// has become the caller's destination, so removing it on Close would delete
// the result.
func (w *Workspace) Detach() string {
	path := w.path
	w.closed = true
	if w.root != nil {
		_ = w.root.Close()
		w.root = nil
	}
	return path
}

// Close removes the workspace and everything in it. It is idempotent.
//
// Cleanup removes only the exact directory this workspace created. It never
// walks up, resolves a symlink, or accepts a path from anywhere but
// uniqueName, so there is no input through which it could be aimed at a
// broader tree.
func (w *Workspace) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	var errs []error
	if w.root != nil {
		if err := w.root.Close(); err != nil {
			errs = append(errs, fault.Wrap(fault.CodeInternal, workspaceOp,
				"closing workspace root", err))
		}
		w.root = nil
	}
	if err := os.RemoveAll(w.path); err != nil {
		errs = append(errs, fault.Wrap(fault.CodeInternal, workspaceOp,
			"removing workspace", err))
	}
	return stderrors.Join(errs...)
}

// mkdirAllIn creates dir and its parents inside root.
//
// os.Root.MkdirAll resolves each component against the held handle, so a
// symlink planted mid-path cannot redirect the creation outside the root.
func mkdirAllIn(root *os.Root, dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	if err := root.MkdirAll(dir, privateDirMode); err != nil {
		return fault.Wrap(fault.CodeInternal, workspaceOp, "creating directory", err).WithPath(dir)
	}
	return nil
}

// copyWithContext copies src to dst, checking for cancellation between
// chunks.
//
// The chunk size bounds how long a cancellation waits: a blocking read
// already issued to the operating system cannot be interrupted, so the
// guarantee is that no *new* read starts after cancellation, not that an
// in-flight one returns immediately.
func copyWithContext(ctx contextLike, dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if stderrors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// contextLike is the slice of context.Context this file needs. Taking the
// narrow interface keeps copyWithContext testable with a fake that reports
// cancellation at an exact byte offset.
type contextLike interface{ Err() error }
