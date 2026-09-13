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

package conformance

import (
	"bytes"
	"fmt"
	"io/fs"
	"strings"
)

// Vector names one published byte vector.
type Vector string

// The published vectors for format v1.
//
// They live in vectors/format/v1 at the repository root rather than under a
// testdata directory, because an implementation in another language has to be
// able to read them. Regenerating them is correct only when introducing a new
// format version.
const (
	VectorManifest      Vector = "manifest.json"
	VectorConfig        Vector = "config.json"
	VectorLayer         Vector = "layer.tar.gz"
	VectorLayerTar      Vector = "layer.tar"
	VectorTreeRecords   Vector = "tree-records.bin"
	VectorTreeDigest    Vector = "tree-digest.txt"
	VectorSubjectDigest Vector = "subject-digest.txt"
	VectorGzipSample    Vector = "gzip-sample.gz"
)

// VerifyVectors checks a set of published byte vectors against each other and
// against this reader.
//
// This is [LevelBytes]. The manifest, config, and layer in the set are read as
// one artifact at [LevelCanonical], and the subject digest the set publishes is
// compared with the one recomputed from the manifest bytes. An implementation
// demonstrates byte conformance by producing files that pass this from the
// documented input tree: identical values are not enough, because two encoders
// that agree on every value and disagree on a spelling give one payload two
// identities.
//
// fsys is the directory holding the vector files, which lets the same check run
// against this repository's vectors/format/v1 and against another
// implementation's output.
func VerifyVectors(fsys fs.FS) (*Report, error) {
	blobs := map[string][]byte{}
	for _, name := range []Vector{VectorManifest, VectorConfig, VectorLayer} {
		data, err := fs.ReadFile(fsys, string(name))
		if err != nil {
			return nil, fmt.Errorf("reading the %s vector: %w", name, err)
		}
		blobs[digestOf(data)] = data
	}

	manifestBytes, err := fs.ReadFile(fsys, string(VectorManifest))
	if err != nil {
		return nil, fmt.Errorf("reading the %s vector: %w", VectorManifest, err)
	}

	report, err := VerifyManifest(manifestBytes, func(digest string) ([]byte, error) {
		data, ok := blobs[digest]
		if !ok {
			return nil, fmt.Errorf("the vector set has no blob %s", digest)
		}
		return data, nil
	}, LevelCanonical)
	if err != nil {
		return nil, err
	}

	if digestErr := compareDigestVector(fsys, VectorSubjectDigest, report.ManifestDigest); digestErr != nil {
		return nil, digestErr
	}
	if digestErr := compareDigestVector(fsys, VectorTreeDigest, report.TreeDigest); digestErr != nil {
		return nil, digestErr
	}

	// The uncompressed layer is published too, so an implementation can tell a
	// tar disagreement from a DEFLATE one. Checking that it is the same bytes
	// keeps the set internally consistent.
	plain, err := fs.ReadFile(fsys, string(VectorLayerTar))
	if err != nil {
		return nil, fmt.Errorf("reading the %s vector: %w", VectorLayerTar, err)
	}
	if compareErr := compareCompressed(blobs, plain); compareErr != nil {
		return nil, compareErr
	}

	report.Level = LevelBytes
	return report, nil
}

// compareDigestVector checks a published digest file against a recomputed one.
func compareDigestVector(fsys fs.FS, name Vector, got string) error {
	data, err := fs.ReadFile(fsys, string(name))
	if err != nil {
		return fmt.Errorf("reading the %s vector: %w", name, err)
	}
	if want := strings.TrimSpace(string(data)); want != got {
		return fmt.Errorf("the %s vector is %s, and the artifact hashes to %s", name, want, got)
	}
	return nil
}

// compareCompressed checks that the uncompressed layer vector is what the
// compressed one holds.
func compareCompressed(blobs map[string][]byte, plain []byte) error {
	for _, data := range blobs {
		if !bytes.HasPrefix(data, gzipHeaderV1) {
			continue
		}
		decompressed, err := decompress(data)
		if err != nil {
			return fmt.Errorf("decompressing the layer vector: %w", err)
		}
		if !bytes.Equal(decompressed, plain) {
			return fmt.Errorf("the %s vector is %d bytes and the compressed layer holds %d",
				VectorLayerTar, len(plain), len(decompressed))
		}
		return nil
	}
	return fmt.Errorf("the vector set holds no gzip layer")
}
