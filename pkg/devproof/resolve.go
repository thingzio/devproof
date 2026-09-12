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

package devproof

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/compose"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/source"
)

const resolveOp = "resolve"

// resolution is everything a manifest resolved to, ready to compose.
type resolution struct {
	spec           *bundle.Spec
	manifestDigest canonical.Digest
	sources        []compose.Source
	materials      map[string]source.Material
	composed       *compose.Result
}

// close releases every snapshot the resolution owns.
func (r *resolution) close() error {
	var errs []error
	for _, src := range r.sources {
		if err := src.Snapshot.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return joinNonNil(errs)
}

// resolveSpec resolves every source in a manifest and composes the result.
//
// Sources resolve concurrently under a bound, because a manifest naming
// several Git repositories should not clone them one at a time. Concurrency
// is invisible in the output: results are collected by name and sorted before
// composition, so completion order cannot reach the bundle (DP-012).
func (c *Client) resolveSpec(
	ctx context.Context,
	spec *bundle.Spec,
	baseDir string,
	lock *bundle.Lock,
	limits bundle.Limits,
) (_ *resolution, retErr error) {

	manifestDigest, _, err := canonical.JSONDigest(spec.Normalized())
	if err != nil {
		return nil, err
	}

	if lock != nil && lock.ManifestDigest != manifestDigest.String() {
		return nil, fault.New(fault.CodeStaleLock, resolveOp,
			fmt.Sprintf("the lock was made for a different manifest: it records %s, "+
				"this manifest is %s", lock.ManifestDigest, manifestDigest))
	}

	result := &resolution{
		spec:           spec,
		manifestDigest: manifestDigest,
		materials:      make(map[string]source.Material, len(spec.Spec.Sources)),
	}
	defer func() {
		if retErr != nil {
			retErr = joinNonNil([]error{retErr, result.close()})
		}
	}()

	snapshots, err := c.resolveSources(ctx, spec, baseDir, lock, limits)
	if err != nil {
		return nil, err
	}

	// Assemble in manifest order after the fact, not in completion order.
	for i := range spec.Spec.Sources {
		declared := &spec.Spec.Sources[i]
		snapshot := snapshots[declared.Name]
		result.sources = append(result.sources, compose.Source{
			Name:      declared.Name,
			MountPath: declared.MountPath,
			Snapshot:  snapshot,
		})
		result.materials[declared.Name] = snapshot.Material()
	}

	composed, err := compose.Compose(result.sources, limits)
	if err != nil {
		return nil, err
	}
	result.composed = composed
	return result, nil
}

// resolveSources runs the resolvers under a concurrency bound.
//
// On the first failure the group cancels the rest, so a manifest with one bad
// source does not finish cloning the others before reporting. Partial work is
// discarded: there is no code path that produces a lock or an artifact from
// some of the sources (DP-011).
func (c *Client) resolveSources(
	ctx context.Context,
	spec *bundle.Spec,
	baseDir string,
	lock *bundle.Lock,
	limits bundle.Limits,
) (_ map[string]source.Snapshot, retErr error) {

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(int(limits.MaxParallelSources))

	var mu sync.Mutex
	snapshots := make(map[string]source.Snapshot, len(spec.Spec.Sources))

	defer func() {
		if retErr != nil {
			for _, snapshot := range snapshots {
				if closeErr := snapshot.Close(); closeErr != nil {
					retErr = joinNonNil([]error{retErr, closeErr})
				}
			}
		}
	}()

	for i := range spec.Spec.Sources {
		declared := spec.Spec.Sources[i]

		group.Go(func() error {
			resolver, ok := c.resolvers[declared.Type]
			if !ok {
				return fault.New(fault.CodeUnsupportedSource, resolveOp,
					fmt.Sprintf("no resolver is registered for source type %q", declared.Type)).
					WithSource(declared.Name)
			}

			var locked *bundle.LockedSource
			if lock != nil {
				entry, found := lock.SourceByName(declared.Name)
				if !found {
					return fault.New(fault.CodeStaleLock, resolveOp,
						"the manifest declares a source the lock does not record").
						WithSource(declared.Name)
				}
				locked = entry
			}

			snapshot, err := resolver.Resolve(groupCtx, source.ResolveRequest{
				Name:     declared.Name,
				Config:   declared.Config,
				Include:  declared.Include,
				Exclude:  declared.Exclude,
				BaseDir:  baseDir,
				Locked:   locked,
				Limits:   limits,
				TempRoot: c.tempRoot,
			})
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()
			snapshots[declared.Name] = snapshot
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	if lock != nil {
		for i := range lock.Sources {
			if _, declared := spec.SourceByName(lock.Sources[i].Name); !declared {
				return nil, fault.New(fault.CodeStaleLock, resolveOp,
					"the lock records a source the manifest no longer declares").
					WithSource(lock.Sources[i].Name)
			}
		}
	}
	return snapshots, nil
}

// buildLock assembles the lock describing a resolution.
func (r *resolution) buildLock(treeDigest canonical.Digest) (*bundle.Lock, error) {
	sources := make([]bundle.LockedSource, 0, len(r.sources))
	for i := range r.spec.Spec.Sources {
		declared := &r.spec.Spec.Sources[i]
		material := r.materials[declared.Name]

		mount, err := bundle.NormalizeMountPath(declared.MountPath)
		if err != nil {
			return nil, err
		}
		sources = append(sources, bundle.LockedSource{
			Name:       declared.Name,
			Type:       material.Type,
			Resolver:   material.Resolver.Name,
			Requested:  material.Requested,
			Resolved:   material.Resolved,
			TreeDigest: material.TreeDigest.String(),
			MountPath:  mount,
			Include:    declared.Include,
			Exclude:    declared.Exclude,
		})
	}

	files := make([]bundle.LockedFile, 0, len(r.composed.Records))
	for _, record := range r.composed.Records {
		owner := r.composed.Owners[record.Path]
		files = append(files, bundle.LockedFile{
			Path:       string(record.Path),
			Source:     owner.Source,
			SourcePath: string(owner.SourcePath),
			Mode:       record.Mode,
			Size:       record.Size,
			Digest:     record.Digest.String(),
		})
	}

	lock := bundle.NewLock(
		r.manifestDigest.String(), bundle.FormatV1, sources, files, treeDigest.String())
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	return lock, nil
}

// verifyAgainstLock checks a resolution reproduces a lock exactly.
//
// Per-source digests are checked by the resolvers; this catches what they
// cannot see: a mount path or filter that changed, or a final inventory that
// differs even though every source matched.
func (r *resolution) verifyAgainstLock(lock *bundle.Lock, treeDigest canonical.Digest) error {
	if lock.TreeDigest != treeDigest.String() {
		return fault.New(fault.CodeStaleLock, resolveOp,
			fmt.Sprintf("the composed tree no longer matches the lock: it records %s, "+
				"this build produces %s", lock.TreeDigest, treeDigest))
	}

	current, err := r.buildLock(treeDigest)
	if err != nil {
		return err
	}
	currentBytes, err := canonical.MarshalJSON(current)
	if err != nil {
		return err
	}
	lockBytes, err := canonical.MarshalJSON(lock)
	if err != nil {
		return err
	}
	if string(currentBytes) != string(lockBytes) {
		return fault.New(fault.CodeStaleLock, resolveOp,
			"the lock no longer describes this manifest's resolution; refresh it explicitly")
	}
	return nil
}

func joinNonNil(errs []error) error {
	filtered := errs[:0]
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	switch len(filtered) {
	case 0:
		return nil
	case 1:
		return filtered[0]
	default:
		messages := make([]string, 0, len(filtered))
		for _, err := range filtered {
			messages = append(messages, err.Error())
		}
		return fault.Wrap(fault.CodeOf(filtered[0]), resolveOp,
			strings.Join(messages[1:], "; "), filtered[0])
	}
}
