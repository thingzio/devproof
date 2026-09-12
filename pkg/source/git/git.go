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

// Package git resolves an HTTPS Git repository into a frozen snapshot.
//
// Content is read from the commit's object tree, never from a working
// directory. That is the whole design: a checkout applies the user's global
// and repository configuration — core.autocrlf, clean and smudge filters,
// .gitattributes — any of which silently rewrites file bytes. A bundle built
// from a checkout would therefore depend on whose machine built it, which
// DP-012 forbids. Reading blobs directly means the bytes are the bytes the
// commit contains, everywhere, always.
package git

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/source"
)

const op = "source.git"

var identity = source.Identity{
	Name:    "devproof.thingz.io/git/v1",
	Version: "1",
}

// Config is a Git source's configuration.
type Config struct {
	// URL is the repository. HTTPS only in v1.
	URL string `json:"url"`
	// Ref is a branch, tag, or commit to resolve. Required when locking.
	Ref string `json:"ref"`
	// SubPath selects a directory within the repository.
	SubPath string `json:"subPath,omitempty"`
}

// Resolver resolves HTTPS Git repositories.
type Resolver struct {
	// open obtains a repository. It is a field so that tests can supply a
	// local fixture without the resolver ever relaxing its HTTPS rule for
	// production callers.
	open func(ctx context.Context, cfg Config) (*gogit.Repository, error)
}

var _ source.Resolver = (*Resolver)(nil)

// New returns a Git resolver that clones over HTTPS.
func New() *Resolver { return &Resolver{open: cloneOverHTTPS} }

// Type is the manifest source type this resolver handles.
func (r *Resolver) Type() string { return bundle.SourceTypeGit }

// Identity describes the resolver in provenance, so evidence records which
// implementation produced a resolution rather than only what it resolved to.
func (r *Resolver) Identity() source.Identity { return identity }

// Resolve fetches the repository and snapshots the resolved commit.
func (r *Resolver) Resolve(ctx context.Context, req source.ResolveRequest) (_ source.Snapshot, retErr error) {
	var config Config
	if err := bundle.DecodeConfig(req.Config, &config); err != nil {
		return nil, err
	}
	if err := validateConfig(config); err != nil {
		return nil, err.WithSource(req.Name)
	}

	// A locked build fetches the commit the lock names, not the mutable ref
	// the manifest wrote. Otherwise moving a branch would change what a
	// locked build produces, which is the entire failure the lock exists to
	// prevent (DP-004).
	effective := config
	if req.Locked != nil {
		commit, ok := req.Locked.Resolved["commit"].(string)
		if !ok || commit == "" {
			return nil, fault.New(fault.CodeStaleLock, op,
				"the lock records no commit for this source").WithSource(req.Name)
		}
		effective.Ref = commit
	}

	repo, err := r.open(ctx, effective)
	if err != nil {
		return nil, err
	}

	commit, commitErr := resolveCommit(repo, effective.Ref)
	if commitErr != nil {
		// When the ref came from a lock, failing to find it is a statement
		// about the lock, not about the network: the commit was force-pushed
		// away, garbage collected, or the url now points somewhere else.
		// Reporting a resolution failure would send someone to check their
		// connectivity instead of their lock.
		if req.Locked != nil {
			return nil, fault.Wrap(fault.CodeStaleLock, op,
				fmt.Sprintf("the repository no longer contains commit %s, which the lock names",
					effective.Ref), commitErr).WithSource(req.Name)
		}
		return nil, commitErr.WithSource(req.Name)
	}

	tree, treeErr := commit.Tree()
	if treeErr != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, op, "reading the commit tree", treeErr).
			WithSource(req.Name)
	}
	if config.SubPath != "" {
		sub, subErr := subTree(tree, config.SubPath)
		if subErr != nil {
			return nil, subErr
		}
		tree = sub
	}

	patterns, err := bundle.NewPatternSet(req.Include, req.Exclude)
	if err != nil {
		return nil, err
	}

	snapshot, err := safefs.SnapshotTree(ctx, treeReader{tree}, safefs.TreeOptions{
		Patterns: patterns,
		Limits:   req.Limits,
		TempRoot: req.TempRoot,
	})
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, op, "snapshotting the commit tree", err).
			WithSource(req.Name)
	}
	defer func() {
		if retErr != nil {
			if closeErr := snapshot.Close(); closeErr != nil {
				retErr = fmt.Errorf("%w (and cleanup failed: %w)", retErr, closeErr)
			}
		}
	}()

	records := snapshot.Records()
	if len(records) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, op,
			"git source selected no files; check subPath and the include and exclude patterns").
			WithSource(req.Name)
	}

	treeDigest, err := canonical.TreeDigest(records)
	if err != nil {
		return nil, err
	}

	requested := map[string]any{"url": config.URL, "ref": config.Ref}
	if config.SubPath != "" {
		requested["subPath"] = config.SubPath
	}
	material := source.Material{
		Type:      bundle.SourceTypeGit,
		Resolver:  identity,
		Requested: requested,
		Resolved: map[string]any{
			// The object format is recorded alongside the commit so that a
			// SHA-1 and a SHA-256 repository cannot be confused for each
			// other by a reader comparing bare hex.
			"objectFormat": "sha1",
			"commit":       commit.Hash.String(),
			"treeDigest":   treeDigest.String(),
		},
		TreeDigest: treeDigest,
	}

	if req.Locked != nil {
		if err := verifyAgainstLock(req.Locked, material, req.Name); err != nil {
			return nil, err
		}
	}

	return &gitSnapshot{inner: snapshot, material: material}, nil
}

// validateConfig enforces the v1 transport and reference rules.
func validateConfig(config Config) *fault.Error {
	if config.URL == "" {
		return fault.New(fault.CodeInvalidInput, op, "git source has no url")
	}
	parsed, err := url.Parse(config.URL)
	if err != nil {
		return fault.Wrap(fault.CodeInvalidInput, op, "git source url is malformed", err)
	}
	// HTTPS only. ssh and git carry their own key material and host trust,
	// and file:// would let a manifest read anything the build account can
	// reach while claiming to be a remote source.
	if parsed.Scheme != "https" {
		return fault.New(fault.CodeInvalidInput, op,
			fmt.Sprintf("git source url uses scheme %q; v1 supports https only", parsed.Scheme))
	}
	// Credentials belong in a credential provider, not in a URL that ends up
	// in a lock, in provenance, and in every diagnostic (DP-013).
	if parsed.User != nil {
		return fault.New(fault.CodeInvalidInput, op,
			"git source url carries embedded credentials; supply them through a credential provider")
	}
	if config.Ref == "" {
		return fault.New(fault.CodeInvalidInput, op,
			"git source has no ref; a branch, tag, or commit is required")
	}
	if config.SubPath != "" {
		if _, err := bundle.NormalizeMountPath(config.SubPath); err != nil {
			return fault.New(fault.CodeInvalidInput, op,
				fmt.Sprintf("git source subPath %q must be a relative path within the repository",
					config.SubPath))
		}
	}
	return nil
}

// cloneOverHTTPS fetches a repository into memory.
func cloneOverHTTPS(ctx context.Context, config Config) (*gogit.Repository, error) {
	repo, err := gogit.CloneContext(ctx, memory.NewStorage(), nil, &gogit.CloneOptions{
		URL: config.URL,
		// The full history is fetched rather than a shallow clone because a
		// lock may name a commit that is not the tip, and a shallow clone
		// that happens not to contain it fails in a way that looks like a
		// stale lock rather than a fetch strategy.
		SingleBranch: false,
		// Tags are needed to resolve a tag ref.
		Tags: gogit.AllTags,
		// Submodules are a second set of remotes with their own credential
		// and host boundaries. v1 does not materialize them; a repository
		// that needs one has to be modeled as a separate source.
		RecurseSubmodules: gogit.NoRecurseSubmodules,
	})
	if err != nil {
		return nil, classifyCloneError(err, config.URL)
	}
	return repo, nil
}

// classifyCloneError maps a transport failure onto a typed code without
// echoing a URL that may carry a token in its query string.
func classifyCloneError(err error, rawURL string) error {
	safe := redactURL(rawURL)
	switch {
	case strings.Contains(err.Error(), "authentication required"),
		strings.Contains(err.Error(), "authorization failed"):
		return fault.Wrap(fault.CodeAuthentication, op,
			fmt.Sprintf("the repository at %s requires credentials", safe), err)
	case strings.Contains(err.Error(), "repository not found"):
		return fault.Wrap(fault.CodeSourceResolution, op,
			fmt.Sprintf("no repository at %s", safe), err)
	case fault.IsNetwork(err):
		return fault.Wrap(fault.CodeTransport, op,
			fmt.Sprintf("could not reach %s", safe), err).AsTemporary()
	default:
		return fault.Wrap(fault.CodeSourceResolution, op,
			fmt.Sprintf("cloning %s", safe), err)
	}
}

// redactURL strips userinfo and query values so a URL is safe to log.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "the configured repository"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// resolveCommit turns a branch, tag, or commit into a commit object.
func resolveCommit(repo *gogit.Repository, ref string) (*object.Commit, *fault.Error) {
	// ResolveRevision handles branches, tags (annotated and lightweight),
	// and raw hashes, and dereferences an annotated tag to its commit.
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, op,
			fmt.Sprintf("cannot resolve ref %q to a commit", ref), err)
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, op,
			fmt.Sprintf("ref %q does not name a commit", ref), err)
	}
	return commit, nil
}

// subTree descends to a directory within the repository.
func subTree(tree *object.Tree, subPath string) (*object.Tree, error) {
	found, err := tree.Tree(path.Clean(subPath))
	if err != nil {
		return nil, fault.Wrap(fault.CodeSourceResolution, op,
			fmt.Sprintf("subPath %q is not a directory in the repository", subPath), err)
	}
	return found, nil
}

// verifyAgainstLock reports a stale lock when a resolution differs.
func verifyAgainstLock(locked *bundle.LockedSource, material source.Material, name string) error {
	lockedCommit, _ := locked.Resolved["commit"].(string)
	currentCommit, _ := material.Resolved["commit"].(string)
	if lockedCommit != currentCommit {
		return fault.New(fault.CodeStaleLock, op,
			fmt.Sprintf("the lock names commit %s but this build resolved %s",
				lockedCommit, currentCommit)).WithSource(name)
	}
	// The commit matching but the tree digest differing means the filters or
	// subPath changed, not the repository.
	if locked.TreeDigest != material.TreeDigest.String() {
		return fault.New(fault.CodeStaleLock, op,
			fmt.Sprintf("commit %s now yields tree digest %s, the lock records %s; "+
				"the subPath or filters changed", currentCommit, material.TreeDigest, locked.TreeDigest)).
			WithSource(name)
	}
	if locked.Resolver != material.Resolver.Name {
		return fault.New(fault.CodeStaleLock, op,
			fmt.Sprintf("the lock was produced by resolver %q, this build uses %q",
				locked.Resolver, material.Resolver.Name)).WithSource(name)
	}
	return nil
}

// treeReader adapts a Git tree to the generic tree walker.
type treeReader struct{ tree *object.Tree }

// Walk yields every blob in the tree, rejecting anything the portable
// profile cannot represent.
func (t treeReader) Walk(yield func(safefs.TreeEntry) error) error {
	walker := object.NewTreeWalker(t.tree, true, nil)
	defer walker.Close()

	for {
		name, entry, err := walker.Next()
		if stderrors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fault.Wrap(fault.CodeSourceResolution, op, "walking the commit tree", err)
		}

		switch entry.Mode {
		case filemode.Dir:
			continue
		case filemode.Empty:
			// A zero mode is not a thing a well-formed tree contains. It is
			// called out rather than left to the default so that adding a
			// mode to the enum cannot silently land in the same bucket.
			return fault.New(fault.CodeSourceResolution, op,
				"repository tree contains an entry with no mode").WithPath(name)
		case filemode.Regular, filemode.Deprecated:
			if err := t.emit(yield, name, entry, bundle.ModeFile); err != nil {
				return err
			}
		case filemode.Executable:
			// The tree entry's mode is authoritative for a Git source. A
			// working-directory stat would reflect the checkout's umask
			// instead, which is exactly the ambient input DP-012 excludes.
			if err := t.emit(yield, name, entry, bundle.ModeExecutable); err != nil {
				return err
			}
		case filemode.Symlink:
			return fault.New(fault.CodeUnsupportedFile, op,
				"repository contains a symlink; the v1 portable profile has no link type").
				WithPath(name)
		case filemode.Submodule:
			return fault.New(fault.CodeUnsupportedFile, op,
				"repository contains a submodule; v1 does not materialize submodules").
				WithPath(name)
		default:
			return fault.New(fault.CodeUnsupportedFile, op,
				fmt.Sprintf("repository entry has unsupported mode %s", entry.Mode)).WithPath(name)
		}
	}
}

func (t treeReader) emit(yield func(safefs.TreeEntry) error, name string, entry object.TreeEntry, mode uint32) error {
	blob, err := t.tree.TreeEntryFile(&entry)
	if err != nil {
		return fault.Wrap(fault.CodeSourceResolution, op, "reading a repository blob", err).
			WithPath(name)
	}
	// Git LFS stores a pointer file in the tree. Materializing it would mean
	// a second remote with its own credentials and size limits, so v1 treats
	// a pointer as the content it literally is and refuses to pretend
	// otherwise.
	if isLFSPointer(blob) {
		return fault.New(fault.CodeUnsupportedFile, op,
			"repository contains a Git LFS pointer; v1 does not materialize LFS objects").
			WithPath(name)
	}

	return yield(safefs.TreeEntry{
		Path: name,
		Mode: mode,
		Size: blob.Size,
		Open: func() (io.ReadCloser, error) { return blob.Reader() },
	})
}

// lfsPointerPrefix is the first line every Git LFS pointer file carries.
const lfsPointerPrefix = "version https://git-lfs.github.com/spec/"

// maxLFSPointerSize bounds how much of a blob is inspected. A real pointer is
// a few hundred bytes; anything larger is ordinary content.
const maxLFSPointerSize = 1024

func isLFSPointer(blob *object.File) bool {
	if blob.Size > maxLFSPointerSize {
		return false
	}
	reader, err := blob.Reader()
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()

	head := make([]byte, len(lfsPointerPrefix))
	n, _ := io.ReadFull(reader, head)
	return string(head[:n]) == lfsPointerPrefix
}

// gitSnapshot adapts a filesystem snapshot to the source contract.
type gitSnapshot struct {
	inner    *safefs.Snapshot
	material source.Material
}

func (s *gitSnapshot) Material() source.Material       { return s.material }
func (s *gitSnapshot) Records() []canonical.FileRecord { return s.inner.Records() }
func (s *gitSnapshot) Close() error                    { return s.inner.Close() }

func (s *gitSnapshot) Open(ctx context.Context, p canonical.Path) (io.ReadCloser, error) {
	return s.inner.Open(ctx, p)
}
