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

// Package path resolves a local directory into a frozen snapshot.
//
// It is the simplest resolver and the one that shows what the contract is
// for: even for a directory the build account already owns, the material is
// copied into private storage and hashed on the way in, because "local" does
// not mean "stable for the duration of a build".
package path

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/source"
)

const op = "source.path"

// Identity names this resolver in locks and provenance.
var identity = source.Identity{
	Name:    "devproof.thingz.io/path/v1",
	Version: "1",
}

// Config is a path source's configuration.
type Config struct {
	// Path is the directory to package. A relative path resolves against the
	// manifest's directory, never the process working directory, so a
	// manifest means the same thing wherever it is invoked from.
	Path string `json:"path"`
}

// Resolver resolves local directories.
//
// AllowAbsolute must be enabled explicitly for a manifest to name an absolute
// path. A manifest that reaches outside its own directory is not portable and
// usually is not intended, so it is opt-in rather than merely discouraged.
type Resolver struct {
	AllowAbsolute bool
}

var _ source.Resolver = (*Resolver)(nil)

// New returns a path resolver.
func New() *Resolver { return &Resolver{} }

// Type is the manifest source type this resolver handles.
func (r *Resolver) Type() string { return bundle.SourceTypePath }

// Identity describes the resolver in provenance, so evidence records which
// implementation produced a resolution rather than only what it resolved to.
func (r *Resolver) Identity() source.Identity { return identity }

// Resolve snapshots the configured directory.
func (r *Resolver) Resolve(ctx context.Context, req source.ResolveRequest) (_ source.Snapshot, retErr error) {
	var config Config
	if err := bundle.DecodeConfig(req.Config, &config); err != nil {
		return nil, err
	}
	if config.Path == "" {
		return nil, fault.New(fault.CodeInvalidInput, op, "path source has no path").
			WithSource(req.Name)
	}

	resolved, resolveErr := r.resolveDirectory(config.Path, req.BaseDir)
	if resolveErr != nil {
		return nil, resolveErr.WithSource(req.Name)
	}

	patterns, err := bundle.NewPatternSet(req.Include, req.Exclude)
	if err != nil {
		return nil, err
	}

	snapshot, err := safefs.SnapshotDir(ctx, resolved, safefs.SnapshotOptions{
		Patterns: patterns,
		Limits:   req.Limits,
		TempRoot: req.TempRoot,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = fault.Wrap(fault.CodeSourceResolution, op, "resolving path source",
				retErr).WithSource(req.Name)
			if closeErr := snapshot.Close(); closeErr != nil {
				retErr = fmt.Errorf("%w (and cleanup failed: %w)", retErr, closeErr)
			}
		}
	}()

	records := snapshot.Records()
	if len(records) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, op,
			"path source selected no files; check the include and exclude patterns")
	}

	treeDigest, err := canonical.TreeDigest(records)
	if err != nil {
		return nil, err
	}

	// The label is what the manifest wrote, never the absolute path it
	// resolved to. An absolute path in a lock or in published provenance
	// discloses workstation or build-agent structure and proves nothing the
	// tree digest does not already prove (DP-025).
	material := source.Material{
		Type:       bundle.SourceTypePath,
		Resolver:   identity,
		Requested:  map[string]any{"path": config.Path},
		Resolved:   map[string]any{"treeDigest": treeDigest.String()},
		TreeDigest: treeDigest,
	}

	if req.Locked != nil {
		if err := verifyAgainstLock(req.Locked, material, req.Name); err != nil {
			return nil, err
		}
	}

	return &pathSnapshot{inner: snapshot, material: material}, nil
}

// resolveDirectory turns a configured path into an absolute directory.
func (r *Resolver) resolveDirectory(configured, baseDir string) (string, *fault.Error) {
	if filepath.IsAbs(configured) {
		if !r.AllowAbsolute {
			return "", fault.New(fault.CodeInvalidInput, op,
				"path source names an absolute path; enable absolute local sources to allow it")
		}
		return filepath.Clean(configured), nil
	}
	if baseDir == "" {
		return "", fault.New(fault.CodeInvalidInput, op,
			"a relative path source needs the manifest directory to resolve against")
	}
	return filepath.Join(baseDir, filepath.FromSlash(configured)), nil
}

// verifyAgainstLock reports a stale lock when resolved material differs.
//
// The comparison is on the tree digest, not on the configured path: moving a
// checkout does not invalidate a lock, but changing a byte inside it does.
// That is what makes a lock a statement about content rather than about
// where someone happened to run a build.
func verifyAgainstLock(locked *bundle.LockedSource, material source.Material, name string) error {
	if locked.TreeDigest != material.TreeDigest.String() {
		return fault.New(fault.CodeStaleLock, op,
			fmt.Sprintf("source content no longer matches the lock: the lock records %s "+
				"but the directory now produces %s", locked.TreeDigest, material.TreeDigest)).
			WithSource(name)
	}
	if locked.Resolver != material.Resolver.Name {
		return fault.New(fault.CodeStaleLock, op,
			fmt.Sprintf("the lock was produced by resolver %q, this build uses %q",
				locked.Resolver, material.Resolver.Name)).WithSource(name)
	}
	return nil
}

// pathSnapshot adapts a filesystem snapshot to the source contract.
type pathSnapshot struct {
	inner    *safefs.Snapshot
	material source.Material
}

func (s *pathSnapshot) Material() source.Material       { return s.material }
func (s *pathSnapshot) Records() []canonical.FileRecord { return s.inner.Records() }
func (s *pathSnapshot) Close() error                    { return s.inner.Close() }

func (s *pathSnapshot) Open(ctx context.Context, p canonical.Path) (io.ReadCloser, error) {
	return s.inner.Open(ctx, p)
}

// DirectSpec synthesizes a one-source manifest for a direct path build.
//
// Direct mode is convenience syntax over the manifest pipeline, not a second
// implementation: the same loader, resolver, composer, and packager run
// either way, so there is no path through which the two could diverge.
func DirectSpec(name, dir, mountPath string, include, exclude []string) (*bundle.Spec, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", fault.Wrap(fault.CodeInvalidInput, op, "resolving source directory", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, "", fault.Wrap(fault.CodeSourceResolution, op, "reading source directory", err)
	}
	if !info.IsDir() {
		return nil, "", fault.New(fault.CodeInvalidInput, op, "source path is not a directory")
	}

	// The synthesized manifest names the directory by its base name and
	// resolves it against its own parent, so the generated lock records a
	// relative label rather than the absolute path (DP-025).
	baseDir := filepath.Dir(abs)
	spec := &bundle.Spec{
		APIVersion: bundle.APIVersionV1Alpha1,
		Kind:       bundle.KindBundle,
		Metadata:   bundle.SpecMetadata{Name: name},
		Spec: bundle.SpecBody{
			Sources: []bundle.SourceSpec{{
				Name:      name,
				Type:      bundle.SourceTypePath,
				MountPath: mountPath,
				Include:   include,
				Exclude:   exclude,
				Config:    map[string]any{"path": filepath.Base(abs)},
			}},
		},
	}
	if err := spec.Validate(); err != nil {
		return nil, "", err
	}
	return spec, baseDir, nil
}
