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

package canonical

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const treeOp = "canonical.tree"

// Digest and its helpers live in bundle: format v1 mandates SHA-256, which
// makes a digest a format concept rather than an encoding detail. They are
// aliased here so that this package's own API reads without a qualifier.
type Digest = bundle.Digest

// DigestSize is the length of a SHA-256 digest in bytes.
const DigestSize = bundle.DigestSize

// DigestOf returns the SHA-256 of b.
func DigestOf(b []byte) Digest { return bundle.DigestOf(b) }

// ParseDigest accepts the OCI "sha256:<64 lowercase hex>" form.
func ParseDigest(s string) (Digest, error) { return bundle.ParseDigest(s) }

// FileRecord is one entry of the canonical inventory: everything about a file
// that contributes to identity, and nothing that does not.
//
// Ownership, timestamps, and link targets are absent by construction rather
// than normalized away later, so there is no code path where one could reach
// the tree digest.
type FileRecord struct {
	// Path is the canonical bundle-relative path.
	Path Path
	// Mode is the normalized mode: bundle.ModeFile or bundle.ModeExecutable.
	Mode uint32
	// Size is the file's length in bytes.
	Size int64
	// Digest is the SHA-256 of the file's exact content bytes.
	Digest Digest
}

// WriteTreeRecords writes the normative v1 tree record stream to w.
//
// The encoding is fixed by docs/bundle-format.md:
//
//	"devproof-tree-v1\x00"
//	uint64be  record count
//	per record, in canonical path order:
//	  uint32be  path byte length
//	  bytes     canonical UTF-8 path
//	  uint32be  normalized mode
//	  uint64be  file byte length
//	  [32]byte  raw SHA-256 content digest
//
// There is no padding, delimiter, or terminator beyond those fields.
func WriteTreeRecords(w io.Writer, records []FileRecord) error {
	if err := validateRecords(records); err != nil {
		return err
	}

	if _, err := io.WriteString(w, bundle.TreeDigestDomainV1); err != nil {
		return fault.Wrap(fault.CodeInternal, treeOp, "writing tree domain prefix", err)
	}

	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], uint64(len(records)))
	if _, err := w.Write(scratch[:]); err != nil {
		return fault.Wrap(fault.CodeInternal, treeOp, "writing tree record count", err)
	}

	for _, rec := range records {
		path := string(rec.Path)

		pathLen, err := toUint32(len(path))
		if err != nil {
			return fault.Wrap(fault.CodeLimitExceeded, treeOp,
				"path does not fit the record encoding", err).WithPath(path)
		}
		size, err := toUint64(rec.Size)
		if err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp,
				"size does not fit the record encoding", err).WithPath(path)
		}

		binary.BigEndian.PutUint32(scratch[:4], pathLen)
		if _, err := w.Write(scratch[:4]); err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp, "writing path length", err)
		}
		if _, err := io.WriteString(w, path); err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp, "writing path", err)
		}

		binary.BigEndian.PutUint32(scratch[:4], rec.Mode)
		if _, err := w.Write(scratch[:4]); err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp, "writing mode", err)
		}

		binary.BigEndian.PutUint64(scratch[:], size)
		if _, err := w.Write(scratch[:]); err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp, "writing size", err)
		}

		if _, err := w.Write(rec.Digest[:]); err != nil {
			return fault.Wrap(fault.CodeInternal, treeOp, "writing content digest", err)
		}
	}
	return nil
}

// TreeDigest returns the v1 tree digest for records.
//
// It hashes incrementally rather than materializing the record stream: a
// bundle at the default file limit would otherwise build a buffer far larger
// than the inventory it describes.
func TreeDigest(records []FileRecord) (Digest, error) {
	h := sha256.New()
	if err := WriteTreeRecords(h, records); err != nil {
		return Digest{}, err
	}
	return digestFrom(h), nil
}

// toUint32 and toUint64 make the width conversions in the encoder provably
// safe at the point of use. validateRecords already rejects out-of-range
// values, but a silent wrap here would produce a well-formed record stream
// describing a file that does not exist, which is the one failure mode this
// package must never have.
func toUint32(n int) (uint32, error) {
	if n < 0 || int64(n) > int64(^uint32(0)) {
		return 0, fmt.Errorf("value %d is out of range for uint32", n)
	}
	return uint32(n), nil
}

func toUint64(n int64) (uint64, error) {
	if n < 0 {
		return 0, fmt.Errorf("value %d is negative", n)
	}
	return uint64(n), nil
}

func digestFrom(h hash.Hash) Digest {
	var d Digest
	h.Sum(d[:0])
	return d
}

// validateRecords is the last gate before identity, so it re-checks
// invariants an earlier stage should already have established. A record set
// that reaches here malformed would otherwise mint a digest for a tree no
// consumer can reproduce.
func validateRecords(records []FileRecord) error {
	// The path-length field is uint32, and the count field is uint64. Neither
	// can overflow with the documented limits in force, but the encoder must
	// not depend on a caller having applied them.
	if int64(len(records)) < 0 {
		return fault.New(fault.CodeInternal, treeOp, "record count is negative")
	}

	var previous Path
	for i, rec := range records {
		switch {
		case rec.Path == "":
			return fault.New(fault.CodeInternal, treeOp,
				fmt.Sprintf("record %d has an empty path", i))
		case rec.Mode != bundle.ModeFile && rec.Mode != bundle.ModeExecutable:
			return fault.New(fault.CodeInternal, treeOp,
				fmt.Sprintf("record %d has mode %#o; v1 normalizes to %#o or %#o",
					i, rec.Mode, bundle.ModeFile, bundle.ModeExecutable)).
				WithPath(string(rec.Path))
		case rec.Size < 0:
			return fault.New(fault.CodeInternal, treeOp,
				fmt.Sprintf("record %d has a negative size", i)).WithPath(string(rec.Path))
		case uint64(len(rec.Path)) > uint64(^uint32(0)):
			return fault.New(fault.CodeLimitExceeded, treeOp,
				fmt.Sprintf("record %d has a path longer than the encoding allows", i))
		}

		if i > 0 && rec.Path <= previous {
			// Strictly increasing, so this catches an unsorted set and a
			// duplicate with one comparison. Both would produce a digest
			// that an independent verifier, which sorts, cannot reproduce.
			if rec.Path == previous {
				return fault.New(fault.CodeInternal, treeOp,
					"records contain a duplicate path").WithPath(string(rec.Path))
			}
			return fault.New(fault.CodeInternal, treeOp,
				fmt.Sprintf("records are not sorted: %q follows %q", rec.Path, previous)).
				WithPath(string(rec.Path))
		}
		previous = rec.Path
	}
	return nil
}
