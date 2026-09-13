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
	"sort"
	"strings"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
	sourcepath "github.com/thingzio/devproof/pkg/source/path"
)

const diffOp = "diff"

// Change classifies one difference between two inventories.
type Change string

const (
	// ChangeAdded means the path exists only on the right side.
	ChangeAdded Change = "added"
	// ChangeRemoved means the path exists only on the left side.
	ChangeRemoved Change = "removed"
	// ChangeModified means the content digest differs. It takes precedence
	// over a mode change on the same path: if the bytes are not the same
	// bytes, that is the fact worth leading with.
	ChangeModified Change = "modified"
	// ChangeModeChanged means the content is identical and only the
	// executable bit differs.
	ChangeModeChanged Change = "mode-changed"
)

// OperandKind is what a diff operand turned out to be.
type OperandKind string

const (
	// OperandBundle is an OCI subject, read from a registry or a layout.
	OperandBundle OperandKind = "bundle"
	// OperandDirectory is a local directory, canonicalized the same way a
	// build would canonicalize it.
	OperandDirectory OperandKind = "directory"
)

// DiffRequest asks what changed between two canonical trees.
//
// Each operand is either an OCI reference — anything carrying a "://" scheme —
// or a path to a local directory.
type DiffRequest struct {
	// From is the left side: the baseline.
	From string
	// To is the right side: what it is compared against.
	To string

	// Limits tightens the client's bounds for this operation.
	Limits Limits
}

// DiffSide describes one operand as it was resolved.
type DiffSide struct {
	// Reference is the operand exactly as supplied.
	Reference string `json:"reference"`
	// Kind is what it resolved to.
	Kind OperandKind `json:"kind"`
	// TreeDigest is the canonical payload identity.
	TreeDigest string `json:"treeDigest"`
	// Subject is the OCI subject digest, present only for a bundle.
	Subject string `json:"subject,omitempty"`
	// FileCount is how many files the side holds.
	FileCount int64 `json:"fileCount"`
}

// DiffEntry is one changed path.
type DiffEntry struct {
	Path   string `json:"path"`
	Change Change `json:"change"`

	// The zero value on either side means the path is absent there.
	OldMode   uint32 `json:"oldMode,omitempty"`
	NewMode   uint32 `json:"newMode,omitempty"`
	OldSize   int64  `json:"oldSize"`
	NewSize   int64  `json:"newSize"`
	OldDigest string `json:"oldDigest,omitempty"`
	NewDigest string `json:"newDigest,omitempty"`
}

// DiffResult is the complete comparison.
type DiffResult struct {
	From DiffSide `json:"from"`
	To   DiffSide `json:"to"`

	// Identical reports equal tree digests. When it is true, Changes is
	// empty: the tree digest is a function of exactly the paths, modes,
	// sizes, and content digests this comparison walks.
	Identical bool `json:"identical"`

	// Changes is sorted by canonical path.
	Changes []DiffEntry `json:"changes,omitempty"`

	Added       int `json:"added"`
	Removed     int `json:"removed"`
	Modified    int `json:"modified"`
	ModeChanged int `json:"modeChanged"`
}

// Diff compares two canonical trees and reports what changed.
//
// It answers the question a configuration pipeline actually has — what is
// different between what I published and what I have now — using only facts
// both sides already carry. A bundle's inventory comes from its config blob,
// which was verified against the layer on the way in; a directory is
// canonicalized through the same path a build would use, so "no differences"
// means a build of that directory would produce the subject it was compared
// against.
//
// Nothing is fetched beyond the manifest, config, and layer needed to verify
// integrity, and nothing is written.
func (c *Client) Diff(ctx context.Context, req DiffRequest) (_ *DiffResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if req.From == "" || req.To == "" {
		return nil, fault.New(fault.CodeInvalidInput, diffOp,
			"supply two operands to compare")
	}

	from, fromFiles, err := c.diffOperand(ctx, req.From, req.Limits)
	if err != nil {
		return nil, err
	}
	to, toFiles, err := c.diffOperand(ctx, req.To, req.Limits)
	if err != nil {
		return nil, err
	}

	result := &DiffResult{
		From:      *from,
		To:        *to,
		Identical: from.TreeDigest == to.TreeDigest,
	}
	result.Changes = compareInventories(fromFiles, toFiles)
	for _, change := range result.Changes {
		switch change.Change {
		case ChangeAdded:
			result.Added++
		case ChangeRemoved:
			result.Removed++
		case ChangeModified:
			result.Modified++
		case ChangeModeChanged:
			result.ModeChanged++
		}
	}
	return result, nil
}

// compareInventories walks two path-sorted inventories in one pass.
//
// Both sides are already sorted by canonical path bytes — a config blob is
// required to be, and a composed tree is produced that way — so a merge walk
// is enough and the output inherits that order without a second sort.
func compareInventories(from, to []bundle.ConfigFile) []DiffEntry {
	var changes []DiffEntry
	i, j := 0, 0

	for i < len(from) && j < len(to) {
		left, right := &from[i], &to[j]
		switch strings.Compare(left.Path, right.Path) {
		case 0:
			if entry, changed := comparePair(left, right); changed {
				changes = append(changes, entry)
			}
			i++
			j++
		case -1:
			changes = append(changes, removedEntry(left))
			i++
		default:
			changes = append(changes, addedEntry(right))
			j++
		}
	}
	for ; i < len(from); i++ {
		changes = append(changes, removedEntry(&from[i]))
	}
	for ; j < len(to); j++ {
		changes = append(changes, addedEntry(&to[j]))
	}
	return changes
}

func comparePair(left, right *bundle.ConfigFile) (DiffEntry, bool) {
	entry := DiffEntry{
		Path:      left.Path,
		OldMode:   left.Mode,
		NewMode:   right.Mode,
		OldSize:   left.Size,
		NewSize:   right.Size,
		OldDigest: left.Digest,
		NewDigest: right.Digest,
	}
	switch {
	case left.Digest != right.Digest:
		entry.Change = ChangeModified
	case left.Mode != right.Mode:
		entry.Change = ChangeModeChanged
	default:
		return DiffEntry{}, false
	}
	return entry, true
}

func removedEntry(file *bundle.ConfigFile) DiffEntry {
	return DiffEntry{
		Path: file.Path, Change: ChangeRemoved,
		OldMode: file.Mode, OldSize: file.Size, OldDigest: file.Digest,
	}
}

func addedEntry(file *bundle.ConfigFile) DiffEntry {
	return DiffEntry{
		Path: file.Path, Change: ChangeAdded,
		NewMode: file.Mode, NewSize: file.Size, NewDigest: file.Digest,
	}
}

// diffOperand resolves one operand to its canonical inventory.
func (c *Client) diffOperand(
	ctx context.Context,
	operand string,
	limits Limits,
) (*DiffSide, []bundle.ConfigFile, error) {

	if isReference(operand) {
		return c.diffFromBundle(ctx, operand, limits)
	}
	return c.diffFromDirectory(ctx, operand, limits)
}

// isReference decides how an operand is read.
//
// A scheme is the discriminator rather than a guess based on whether the path
// happens to exist: a mistyped directory must report that it could not be
// read, not be reinterpreted as a registry reference and produce a confusing
// authentication failure.
func isReference(operand string) bool {
	return strings.Contains(operand, "://")
}

func (c *Client) diffFromBundle(
	ctx context.Context,
	reference string,
	limits Limits,
) (*DiffSide, []bundle.ConfigFile, error) {

	// checkPayload, because "identical" is an integrity claim. Comparing
	// config inventories alone would compare what two artifacts say about
	// themselves, which is a weaker statement than the output implies.
	subject, pinned, err := c.loadSubject(ctx, VerifyRequest{
		Reference: reference,
		Limits:    limits,
	}, checkPayload)
	if err != nil {
		return nil, nil, err
	}

	return &DiffSide{
		Reference:  pinned.String(),
		Kind:       OperandBundle,
		TreeDigest: subject.TreeDigest.String(),
		Subject:    subject.ManifestDigest.String(),
		FileCount:  subject.Config.FileCount,
	}, subject.Config.Files, nil
}

func (c *Client) diffFromDirectory(
	ctx context.Context,
	dir string,
	limits Limits,
) (_ *DiffSide, _ []bundle.ConfigFile, retErr error) {

	spec, baseDir, err := sourcepath.DirectSpec(directSourceName, dir, "", nil, nil)
	if err != nil {
		return nil, nil, err
	}

	effective := c.effectiveLimits(limits)
	resolved, err := c.resolveSpec(ctx, spec, baseDir, nil, effective.Limits)
	if err != nil {
		return nil, nil, err
	}
	// The snapshot exists only to produce an inventory. Nothing is read from
	// it afterwards, so it is released here rather than held for the caller.
	defer func() {
		if closeErr := resolved.close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	records := resolved.composed.Records
	treeDigest, err := canonical.TreeDigest(records)
	if err != nil {
		return nil, nil, err
	}

	files := make([]bundle.ConfigFile, len(records))
	for i := range records {
		files[i] = bundle.ConfigFile{
			Path:   string(records[i].Path),
			Mode:   records[i].Mode,
			Size:   records[i].Size,
			Digest: records[i].Digest.String(),
		}
	}
	// Compose sorts by canonical path, and the merge walk depends on it.
	// Asserting rather than assuming costs one pass over an already-sorted
	// slice and turns a silently wrong diff into a loud one.
	if !sort.SliceIsSorted(files, func(a, b int) bool { return files[a].Path < files[b].Path }) {
		return nil, nil, fault.New(fault.CodeInternal, diffOp,
			"composed inventory is not sorted by path")
	}

	return &DiffSide{
		Reference:  dir,
		Kind:       OperandDirectory,
		TreeDigest: treeDigest.String(),
		FileCount:  int64(len(files)),
	}, files, nil
}
