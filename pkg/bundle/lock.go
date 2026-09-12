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

package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/thingzio/devproof/pkg/fault"
)

const lockOp = "bundle.lock"

// Lock records the immutable resolution of a manifest.
//
// It is generated, never hand-written, and it is what makes a build
// reproducible: a locked build fails rather than quietly accepting material
// that has changed since the lock was made (DP-004).
//
// The struct has nowhere to record a timestamp, a hostname, a user, a
// registry destination, or a credential. That is deliberate. A lock is
// reviewed in a pull request and committed to a repository, so anything it
// can hold is something that leaks.
type Lock struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`

	// ManifestDigest binds this lock to one manifest. A manifest edit that
	// changes meaning invalidates the lock.
	ManifestDigest string `json:"manifestDigest"`
	// Format is the bundle format the lock was produced for.
	Format Format `json:"format"`

	Sources []LockedSource `json:"sources"`
	Files   []LockedFile   `json:"files"`

	// TreeDigest is the canonical payload identity the lock commits to.
	TreeDigest string `json:"treeDigest"`
}

// LockedSource records how one source resolved.
type LockedSource struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Resolver identifies the implementation and version that produced this
	// resolution, so a resolver whose behavior changed cannot silently
	// satisfy a lock made by an earlier one.
	Resolver string `json:"resolver"`

	// Requested is what the manifest asked for, which may be mutable.
	Requested map[string]any `json:"requested,omitempty"`
	// Resolved is what it resolved to, which must not be.
	Resolved map[string]any `json:"resolved,omitempty"`

	// TreeDigest is the canonical digest of this source's filtered
	// contribution, before its mount path is applied. It is the common
	// identity across source types: a Git commit and a local directory that
	// hold the same files have the same value here.
	TreeDigest string `json:"treeDigest"`

	MountPath string   `json:"mountPath,omitempty"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
}

// LockedFile records one file's final placement and identity.
type LockedFile struct {
	Path string `json:"path"`
	// Source names the single owner of this path. Every final path has
	// exactly one (DP-011).
	Source     string `json:"source"`
	SourcePath string `json:"sourcePath"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	Digest     string `json:"digest"`
}

// NewLock assembles a lock, canonicalizing its set-like fields.
func NewLock(manifestDigest string, format Format, sources []LockedSource, files []LockedFile, treeDigest string) *Lock {
	lock := &Lock{
		APIVersion:     APIVersionV1Alpha1,
		Kind:           KindBundleLock,
		ManifestDigest: manifestDigest,
		Format:         format,
		Sources:        slices.Clone(sources),
		Files:          slices.Clone(files),
		TreeDigest:     treeDigest,
	}
	lock.canonicalize()
	return lock
}

// canonicalize sorts the set-like collections.
//
// Sources sort by name and files by canonical path, so that the order
// resolvers finished in — which is concurrency-dependent — cannot reach the
// lock digest (DP-012).
func (l *Lock) canonicalize() {
	slices.SortFunc(l.Sources, func(a, b LockedSource) int {
		return strings.Compare(a.Name, b.Name)
	})
	slices.SortFunc(l.Files, func(a, b LockedFile) int {
		return strings.Compare(a.Path, b.Path)
	})
	for i := range l.Sources {
		l.Sources[i].Include = NormalizePatterns(l.Sources[i].Include)
		l.Sources[i].Exclude = NormalizePatterns(l.Sources[i].Exclude)
	}
}

// ParseLock decodes and validates a lock.
func ParseLock(data []byte) (*Lock, error) {
	if len(data) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, lockOp, "lock is empty")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, lockOp, "decoding lock", err)
	}
	if decoder.More() {
		return nil, fault.New(fault.CodeInvalidInput, lockOp,
			"lock contains trailing data after the JSON object")
	}
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	return &lock, nil
}

// Validate checks the lock's structure and internal consistency.
func (l *Lock) Validate() error {
	if l.APIVersion != APIVersionV1Alpha1 {
		return fault.New(fault.CodeUnsupportedVersion, lockOp,
			fmt.Sprintf("lock apiVersion %q is not supported", l.APIVersion))
	}
	if l.Kind != KindBundleLock {
		return fault.New(fault.CodeInvalidInput, lockOp,
			fmt.Sprintf("lock kind is %q, want %q", l.Kind, KindBundleLock))
	}
	if !Supported(l.Format) {
		return fault.New(fault.CodeUnsupportedVersion, lockOp,
			fmt.Sprintf("lock names bundle format %q, which is not supported", l.Format))
	}
	if _, err := ParseDigest(l.ManifestDigest); err != nil {
		return fault.Wrap(fault.CodeInvalidInput, lockOp, "lock manifest digest is invalid", err)
	}
	if _, err := ParseDigest(l.TreeDigest); err != nil {
		return fault.Wrap(fault.CodeInvalidInput, lockOp, "lock tree digest is invalid", err)
	}
	if len(l.Sources) == 0 {
		return fault.New(fault.CodeInvalidInput, lockOp, "lock records no sources")
	}

	owners := make(map[string]struct{}, len(l.Sources))
	for i := range l.Sources {
		source := &l.Sources[i]
		if err := ValidateName(source.Name, "locked source name"); err != nil {
			return err
		}
		if source.Resolver == "" {
			return fault.New(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("locked source %q records no resolver identity", source.Name))
		}
		if _, err := ParseDigest(source.TreeDigest); err != nil {
			return fault.Wrap(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("locked source %q has an invalid tree digest", source.Name), err)
		}
		if _, duplicate := owners[source.Name]; duplicate {
			return fault.New(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("lock records source %q twice", source.Name))
		}
		owners[source.Name] = struct{}{}
	}

	var previous string
	for i := range l.Files {
		file := &l.Files[i]
		if file.Path == "" {
			return fault.New(fault.CodeInvalidInput, lockOp, "lock records a file with no path")
		}
		if _, ok := owners[file.Source]; !ok {
			return fault.New(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("lock assigns %q to source %q, which it does not record",
					file.Path, file.Source)).WithPath(file.Path)
		}
		if file.Mode != ModeFile && file.Mode != ModeExecutable {
			return fault.New(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("lock records mode %#o, which is not normalized", file.Mode)).
				WithPath(file.Path)
		}
		if file.Size < 0 {
			return fault.New(fault.CodeInvalidInput, lockOp,
				"lock records a negative size").WithPath(file.Path)
		}
		if _, err := ParseDigest(file.Digest); err != nil {
			return fault.Wrap(fault.CodeInvalidInput, lockOp,
				"lock records an invalid file digest", err).WithPath(file.Path)
		}
		// Strictly increasing catches an unsorted lock and a duplicate path
		// in one comparison. A duplicate would mean two owners for one
		// destination, which DP-011 forbids.
		if i > 0 && file.Path <= previous {
			if file.Path == previous {
				return fault.New(fault.CodeInvalidInput, lockOp,
					"lock records a path twice").WithPath(file.Path)
			}
			return fault.New(fault.CodeInvalidInput, lockOp,
				fmt.Sprintf("lock is not sorted by path: %q follows %q", file.Path, previous)).
				WithPath(file.Path)
		}
		previous = file.Path
	}
	return nil
}

// SourceByName returns a locked source.
func (l *Lock) SourceByName(name string) (*LockedSource, bool) {
	for i := range l.Sources {
		if l.Sources[i].Name == name {
			return &l.Sources[i], true
		}
	}
	return nil, false
}
