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

// Package compose merges several resolved sources into one canonical tree.
//
// Composition is closed-world: every final path has exactly one source owner,
// collisions fail rather than resolve, and the order sources appear in a
// manifest is not an input to the result (DP-011). There is no overlay, no
// precedence, and no last-one-wins.
package compose

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
	"github.com/thingzio/devproof/pkg/source"
)

const composeOp = "compose"

// Source is one resolved source awaiting placement.
type Source struct {
	// Name is the logical source name.
	Name string
	// MountPath places the source below a prefix. Empty mounts at the root.
	MountPath string
	// Snapshot holds the resolved, filtered material.
	Snapshot source.Snapshot
}

// Owner records which source a final path came from.
type Owner struct {
	// Source is the logical source name.
	Source string
	// SourcePath is the path within that source, before mounting.
	SourcePath canonical.Path
}

// Result is a composed tree.
type Result struct {
	// Records is the canonical inventory, sorted by final path.
	Records []canonical.FileRecord
	// Owners maps every final path to its single owner.
	Owners map[canonical.Path]Owner

	sources map[string]source.Snapshot
}

var _ canonical.ContentSource = (*Result)(nil)

// Open returns the content behind a composed path.
//
// It routes through the owning snapshot rather than holding content itself,
// so composition never copies bytes. The path must be one Compose produced;
// anything else is refused before a snapshot is consulted.
func (r *Result) Open(ctx context.Context, path canonical.Path) (io.ReadCloser, error) {
	owner, ok := r.Owners[path]
	if !ok {
		return nil, fault.New(fault.CodeInternal, composeOp,
			"path is not part of the composed tree").WithPath(string(path))
	}
	snapshot, ok := r.sources[owner.Source]
	if !ok {
		return nil, fault.New(fault.CodeInternal, composeOp,
			fmt.Sprintf("source %q is not available", owner.Source)).WithPath(string(path))
	}
	return snapshot.Open(ctx, owner.SourcePath)
}

// Compose merges sources into one canonical tree.
//
// Sources are sorted by name before anything else happens, so that the result
// — including which collision is reported when there are several — does not
// depend on the order they were resolved in. Resolution is concurrent, and
// concurrency must not be observable in the output (DP-012).
func Compose(sources []Source, limits bundle.Limits) (*Result, error) {
	if len(sources) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, composeOp, "no sources to compose")
	}
	limits = limits.WithDefaults()

	ordered := slices.Clone(sources)
	slices.SortFunc(ordered, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })

	result := &Result{
		Owners:  make(map[canonical.Path]Owner),
		sources: make(map[string]source.Snapshot, len(ordered)),
	}
	var paths canonical.PathSet
	var totalSize int64

	for _, src := range ordered {
		if _, duplicate := result.sources[src.Name]; duplicate {
			return nil, fault.New(fault.CodeInvalidInput, composeOp,
				fmt.Sprintf("two sources are named %q", src.Name))
		}
		result.sources[src.Name] = src.Snapshot

		mount, err := bundle.NormalizeMountPath(src.MountPath)
		if err != nil {
			return nil, err
		}

		records := src.Snapshot.Records()
		if len(records) == 0 {
			// A source that contributes nothing is almost always a filter
			// that does not match what the author expected, and silently
			// producing a smaller bundle is the worst outcome.
			return nil, fault.New(fault.CodeInvalidInput, composeOp,
				fmt.Sprintf("source %q selected no files", src.Name))
		}

		for _, record := range records {
			final, err := mountPath(mount, record.Path, limits)
			if err != nil {
				return nil, fault.Wrap(fault.CodeUnsafePath, composeOp,
					fmt.Sprintf("mounting source %q", src.Name), err).WithSource(src.Name)
			}
			// PathSet is what makes a collision an error rather than a
			// choice: duplicates, case-folding aliases, and file/directory
			// conflicts are all refused here.
			if err := paths.Add(final); err != nil {
				return nil, annotateCollision(err, src.Name, result.Owners, final)
			}

			result.Owners[final] = Owner{Source: src.Name, SourcePath: record.Path}
			record.Path = final
			result.Records = append(result.Records, record)

			totalSize += record.Size
			if totalSize > limits.MaxExpandedBytes {
				return nil, fault.New(fault.CodeLimitExceeded, composeOp,
					fmt.Sprintf("composed tree exceeds the total size limit of %d bytes",
						limits.MaxExpandedBytes))
			}
		}

		if int64(len(result.Records)) > limits.MaxFiles {
			return nil, fault.New(fault.CodeLimitExceeded, composeOp,
				fmt.Sprintf("composed tree contains more than %d files", limits.MaxFiles))
		}
	}

	slices.SortFunc(result.Records, func(a, b canonical.FileRecord) int {
		return strings.Compare(string(a.Path), string(b.Path))
	})
	return result, nil
}

// mountPath joins a mount prefix to a source-relative path and re-validates
// the result.
//
// Re-normalizing rather than concatenating matters: the joined path can
// exceed a depth or length limit that neither part did, and it must be
// rejected under the same rules as any other canonical path.
func mountPath(mount string, path canonical.Path, limits bundle.Limits) (canonical.Path, error) {
	joined := string(path)
	if mount != "" {
		joined = mount + canonical.Separator + joined
	}
	return canonical.NormalizePath(joined, canonical.PathLimits{
		MaxBytes:        int(limits.MaxPathBytes),
		MaxSegmentBytes: int(limits.MaxPathSegmentBytes),
		MaxDepth:        int(limits.MaxPathDepth),
	})
}

// annotateCollision names both sides of a collision.
//
// The bare error knows the paths involved but not who supplied them, and
// "two sources claim app/config.yaml" is not actionable without knowing which
// two.
func annotateCollision(err error, sourceName string, owners map[canonical.Path]Owner, final canonical.Path) error {
	typed, ok := fault.AsError(err)
	if !ok {
		return err
	}
	if existing, found := owners[final]; found {
		return fault.New(fault.CodePathCollision, composeOp,
			fmt.Sprintf("sources %q and %q both claim this path", existing.Source, sourceName)).
			WithPath(string(final)).
			WithSource(sourceName)
	}
	return typed.WithSource(sourceName)
}
