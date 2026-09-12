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

// Package conformance is an independent reader for the DevProof bundle
// format.
//
// It exists to answer one question: does the format specification, read on its
// own, describe the artifacts DevProof actually produces? A test that checks a
// writer against its own reader proves only that the two agree. If both share
// a constant, a sort order, or an encoding helper, they share its bugs, and a
// round trip passes while the artifact is unreadable by anyone else.
//
// So this package is deliberately built from nothing but the standard library
// and docs/bundle-format.md. It imports no other DevProof package — not the
// media-type constants, not the canonical encoders, not the digest helpers.
// Every value it compares against is written out here from the specification
// text, and every structure it parses it parses again from scratch. Where this
// package and the main implementation disagree, one of them is wrong, and
// finding out which is the entire point.
//
// It is intentionally simple and unoptimized. It buffers what a streaming
// reader would not, because being obviously correct matters more here than
// being fast, and a second implementation that is clever enough to be wrong in
// the same way as the first has no value.
package conformance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Media types and format identifiers, transcribed from the specification
// rather than imported. A shared constant would make a typo in the spec
// invisible to this check.
const (
	mediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeArtifact = "application/vnd.thingz.devproof.bundle.v1"
	mediaTypeConfig   = "application/vnd.thingz.devproof.config.v1+json"
	mediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"

	formatV1      = "devproof-bundle-v1"
	schemaVersion = 1

	// treePrefix is the tree digest domain separator: the ASCII bytes
	// "devproof-tree-v1" followed by a NUL.
	treePrefix = "devproof-tree-v1\x00"

	// The only two modes a canonical file record may carry.
	modeFile       = 0o644
	modeExecutable = 0o755
	modeDirectory  = 0o755
)

// Report is what an independent read established.
type Report struct {
	// ManifestDigest is the subject identity: sha256 over the manifest bytes.
	ManifestDigest string
	// TreeDigest is recomputed here from the layer, not read from the config.
	TreeDigest string
	// ConfigTreeDigest is what the config claimed.
	ConfigTreeDigest string
	FileCount        int64
	TotalSize        int64
	// Files is the inventory as recomputed from the layer.
	Files []FileRecord
}

// FileRecord is one canonical file.
type FileRecord struct {
	Path   string
	Mode   uint32
	Size   int64
	Digest string
}

// descriptor is the OCI descriptor subset this reader needs.
type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
	Subject       *descriptor  `json:"subject,omitempty"`
}

type configBlob struct {
	SchemaVersion int          `json:"schemaVersion"`
	Format        string       `json:"format"`
	TreeDigest    string       `json:"treeDigest"`
	FileCount     int64        `json:"fileCount"`
	TotalSize     int64        `json:"totalSize"`
	Files         []configFile `json:"files"`
}

type configFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type index struct {
	SchemaVersion int `json:"schemaVersion"`
	Manifests     []struct {
		descriptor
		Annotations map[string]string `json:"annotations"`
	} `json:"manifests"`
}

// VerifyLayout reads a bundle from an OCI image layout and checks it against
// the format specification.
//
// reference selects the subject: a tag matched against
// org.opencontainers.image.ref.name, or a "sha256:..." digest. An empty
// reference is accepted only when the layout holds exactly one manifest,
// because guessing which of several a caller meant is how the wrong artifact
// gets verified.
func VerifyLayout(dir, reference string) (*Report, error) {
	if err := checkLayoutMarker(dir); err != nil {
		return nil, err
	}

	manifestDigest, err := resolve(dir, reference)
	if err != nil {
		return nil, err
	}

	manifestBytes, err := readBlob(dir, manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	return VerifyManifest(manifestBytes, func(digest string) ([]byte, error) {
		return readBlob(dir, digest)
	})
}

// BlobFetcher supplies a blob by digest.
//
// The digest is the caller's to verify or not; this package verifies every
// blob it receives regardless, which is what lets the same code check a
// layout on disk and a response from a registry.
type BlobFetcher func(digest string) ([]byte, error)

// VerifyManifest checks a manifest and everything it references.
func VerifyManifest(manifestBytes []byte, fetch BlobFetcher) (*Report, error) {
	manifestDigest := digestOf(manifestBytes)

	// Decoding is strict: a field this reader does not know is a field it
	// would not enforce, and a manifest carrying one is not a v1 manifest.
	var m manifest
	if err := strictJSON(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("decoding the manifest: %w", err)
	}

	if m.SchemaVersion != 2 {
		return nil, fmt.Errorf("manifest schemaVersion is %d, want 2", m.SchemaVersion)
	}
	if m.MediaType != mediaTypeManifest {
		return nil, fmt.Errorf("manifest mediaType is %q, want %q", m.MediaType, mediaTypeManifest)
	}
	if m.ArtifactType != mediaTypeArtifact {
		return nil, fmt.Errorf("manifest artifactType is %q, want %q", m.ArtifactType, mediaTypeArtifact)
	}
	if m.Config.MediaType != mediaTypeConfig {
		return nil, fmt.Errorf("config mediaType is %q, want %q", m.Config.MediaType, mediaTypeConfig)
	}
	// Exactly one layer. The format is one payload, and a reader that
	// tolerated a second would have to decide which one was the payload.
	if len(m.Layers) != 1 {
		return nil, fmt.Errorf("manifest has %d layers, want exactly 1", len(m.Layers))
	}
	if m.Layers[0].MediaType != mediaTypeLayer {
		return nil, fmt.Errorf("layer mediaType is %q, want %q", m.Layers[0].MediaType, mediaTypeLayer)
	}

	configBytes, err := fetchVerified(fetch, m.Config)
	if err != nil {
		return nil, fmt.Errorf("config blob: %w", err)
	}
	config, err := parseConfig(configBytes)
	if err != nil {
		return nil, err
	}

	layerBytes, err := fetchVerified(fetch, m.Layers[0])
	if err != nil {
		return nil, fmt.Errorf("layer blob: %w", err)
	}

	files, err := readLayer(layerBytes)
	if err != nil {
		return nil, err
	}

	if err := matchInventory(config, files); err != nil {
		return nil, err
	}

	// The tree digest is recomputed from what the layer actually contained,
	// then compared to the config's claim. Computing it from the config
	// instead would check that the config agrees with itself.
	treeDigest := computeTreeDigest(files)
	if treeDigest != config.TreeDigest {
		return nil, fmt.Errorf(
			"recomputed tree digest %s does not match the config's %s",
			treeDigest, config.TreeDigest)
	}

	return &Report{
		ManifestDigest:   manifestDigest,
		TreeDigest:       treeDigest,
		ConfigTreeDigest: config.TreeDigest,
		FileCount:        config.FileCount,
		TotalSize:        config.TotalSize,
		Files:            files,
	}, nil
}

// computeTreeDigest implements the v1 tree digest from the specification.
//
//	ASCII bytes: "devproof-tree-v1\x00"
//	uint64be:    number of file records
//	for each record, sorted by canonical UTF-8 path bytes:
//	  uint32be:  path byte length
//	  bytes:     canonical UTF-8 path
//	  uint32be:  normalized mode
//	  uint64be:  file byte length
//	  bytes[32]: raw SHA-256 content digest
//
// No padding, no delimiters, no terminal record. Directories do not appear:
// they are derived from file paths.
func computeTreeDigest(files []FileRecord) string {
	sorted := slices.Clone(files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	h := sha256.New()
	h.Write([]byte(treePrefix))

	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], uint64(len(sorted)))
	h.Write(scratch[:])

	for _, file := range sorted {
		// The widths are checked rather than assumed. A silent wrap would
		// produce a well-formed record stream describing a file that does not
		// exist, and this reader's whole job is to not do that. Both are
		// unreachable for any artifact that passed the earlier limits; being
		// unreachable is not a reason to convert unchecked.
		if file.Size < 0 {
			panic("conformance: negative file size")
		}
		pathLen, ok := toUint32(len(file.Path))
		if !ok {
			panic("conformance: path length exceeds uint32")
		}

		binary.BigEndian.PutUint32(scratch[:4], pathLen)
		h.Write(scratch[:4])
		h.Write([]byte(file.Path))

		binary.BigEndian.PutUint32(scratch[:4], file.Mode)
		h.Write(scratch[:4])

		binary.BigEndian.PutUint64(scratch[:], uint64(file.Size))
		h.Write(scratch[:])

		raw, err := hex.DecodeString(strings.TrimPrefix(file.Digest, "sha256:"))
		if err != nil {
			// Unreachable: every digest here was produced by this package.
			panic("conformance: malformed digest in a recomputed record: " + file.Digest)
		}
		h.Write(raw)
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// toUint32 narrows a length, reporting whether it fit.
func toUint32(n int) (uint32, bool) {
	if n < 0 || n > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

// readLayer decompresses and walks the tar, returning the file inventory.
//
// Directories are checked for canonical mode but are not returned: the tree
// digest is over files alone.
func readLayer(compressed []byte) ([]FileRecord, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("opening the gzip stream: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// A gzip member carrying a name or timestamp would make the encoded
	// artifact depend on when and where it was built.
	if zr.Name != "" {
		return nil, fmt.Errorf("the gzip header carries a name %q", zr.Name)
	}
	if !zr.ModTime.IsZero() && zr.ModTime.Unix() != 0 {
		return nil, fmt.Errorf("the gzip header carries a modification time %s", zr.ModTime)
	}

	tr := tar.NewReader(zr)
	var (
		files    []FileRecord
		seen     = map[string]bool{}
		haveDirs = map[string]bool{}
		needDirs = map[string]bool{}
		// Entry order is: every required directory in sorted order, then
		// every file in sorted order. Tracked as two independently ascending
		// runs, with any directory after the first file being an error.
		lastDir  string
		lastFile string
		inFiles  bool
	)

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the tar stream: %w", err)
		}

		name := header.Name
		isDir := strings.HasSuffix(name, "/") || header.Typeflag == tar.TypeDir
		clean := strings.TrimSuffix(name, "/")

		if err := checkPath(clean); err != nil {
			return nil, err
		}
		if seen[clean] {
			return nil, fmt.Errorf("duplicate tar entry %q", clean)
		}
		seen[clean] = true

		// Ordering is checked because a non-deterministic encoder would let
		// two identical trees produce two different layer digests.
		if isDir {
			if inFiles {
				return nil, fmt.Errorf(
					"directory %q is emitted after a file; every directory precedes every file",
					clean)
			}
			if lastDir != "" && clean <= lastDir {
				return nil, fmt.Errorf("directories are out of order: %q follows %q", clean, lastDir)
			}
			lastDir = clean
		} else {
			if lastFile != "" && clean <= lastFile {
				return nil, fmt.Errorf("files are out of order: %q follows %q", clean, lastFile)
			}
			lastFile, inFiles = clean, true
		}

		if header.ModTime.Unix() != 0 {
			return nil, fmt.Errorf("entry %q has modification time %s, want the epoch",
				clean, header.ModTime)
		}
		if header.Uid != 0 || header.Gid != 0 {
			return nil, fmt.Errorf("entry %q has uid/gid %d/%d, want 0/0",
				clean, header.Uid, header.Gid)
		}
		if header.Uname != "" || header.Gname != "" {
			return nil, fmt.Errorf("entry %q carries user or group names", clean)
		}

		switch {
		case isDir:
			if header.Typeflag != tar.TypeDir {
				return nil, fmt.Errorf("entry %q ends in / but is type %q",
					clean, string(header.Typeflag))
			}
			if mode := header.FileInfo().Mode().Perm(); mode != modeDirectory {
				return nil, fmt.Errorf("directory %q has mode %04o, want %04o",
					clean, mode, modeDirectory)
			}
			haveDirs[clean] = true

		case header.Typeflag == tar.TypeReg:
			mode := uint32(header.FileInfo().Mode().Perm())
			if mode != modeFile && mode != modeExecutable {
				return nil, fmt.Errorf("file %q has mode %04o, want %04o or %04o",
					clean, mode, modeFile, modeExecutable)
			}

			content, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading %q: %w", clean, err)
			}
			if int64(len(content)) != header.Size {
				return nil, fmt.Errorf("entry %q declares %d bytes but carries %d",
					clean, header.Size, len(content))
			}

			for parent := path.Dir(clean); parent != "." && parent != "/"; parent = path.Dir(parent) {
				needDirs[parent] = true
			}

			files = append(files, FileRecord{
				Path:   clean,
				Mode:   mode,
				Size:   header.Size,
				Digest: digestOf(content),
			})

		default:
			// Symlinks, devices, FIFOs, and hard links are not representable
			// in v1. A reader that skipped them would expand a different tree
			// than the one whose digest it verified.
			return nil, fmt.Errorf("entry %q has unsupported type %q",
				clean, string(header.Typeflag))
		}
	}

	for dir := range needDirs {
		if !haveDirs[dir] {
			return nil, fmt.Errorf("the layer is missing the parent directory %q", dir)
		}
	}
	for dir := range haveDirs {
		if !needDirs[dir] {
			return nil, fmt.Errorf("the layer carries directory %q, which no file needs", dir)
		}
	}

	return files, nil
}

// checkPath applies the canonical path rules.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("an entry has an empty path")
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("path %q is absolute", p)
	case p != path.Clean(p):
		return fmt.Errorf("path %q is not clean", p)
	case strings.Contains(p, `\`):
		return fmt.Errorf("path %q contains a backslash", p)
	}
	for _, element := range strings.Split(p, "/") {
		if element == "" || element == "." || element == ".." {
			return fmt.Errorf("path %q contains the element %q", p, element)
		}
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("path %q contains a NUL", p)
	}
	return nil
}

// matchInventory checks the config against what the layer actually held.
//
// Both directions matter. A file in the config but not the layer is a missing
// payload; a file in the layer but not the config is content that was never
// covered by the tree digest.
func matchInventory(config *configBlob, files []FileRecord) error {
	if int64(len(files)) != config.FileCount {
		return fmt.Errorf("the layer holds %d files but the config declares %d",
			len(files), config.FileCount)
	}
	if int64(len(config.Files)) != config.FileCount {
		return fmt.Errorf("the config lists %d files but declares %d",
			len(config.Files), config.FileCount)
	}

	byPath := make(map[string]FileRecord, len(files))
	var total int64
	for _, file := range files {
		byPath[file.Path] = file
		total += file.Size
	}
	if total != config.TotalSize {
		return fmt.Errorf("the layer holds %d bytes but the config declares %d",
			total, config.TotalSize)
	}

	for i, want := range config.Files {
		if i > 0 && config.Files[i-1].Path >= want.Path {
			return fmt.Errorf("config entries are not sorted: %q follows %q",
				want.Path, config.Files[i-1].Path)
		}
		got, ok := byPath[want.Path]
		if !ok {
			return fmt.Errorf("the config lists %q, which the layer does not contain", want.Path)
		}
		if got.Mode != want.Mode {
			return fmt.Errorf("%q has mode %04o in the layer and %04o in the config",
				want.Path, got.Mode, want.Mode)
		}
		if got.Size != want.Size {
			return fmt.Errorf("%q is %d bytes in the layer and %d in the config",
				want.Path, got.Size, want.Size)
		}
		if got.Digest != want.Digest {
			return fmt.Errorf("%q hashes to %s in the layer and %s in the config",
				want.Path, got.Digest, want.Digest)
		}
		delete(byPath, want.Path)
	}
	for leftover := range byPath {
		return fmt.Errorf("the layer contains %q, which the config does not list", leftover)
	}
	return nil
}

func parseConfig(data []byte) (*configBlob, error) {
	var config configBlob
	if err := strictJSON(data, &config); err != nil {
		return nil, fmt.Errorf("decoding the config: %w", err)
	}
	if config.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("config schemaVersion is %d, want %d",
			config.SchemaVersion, schemaVersion)
	}
	if config.Format != formatV1 {
		return nil, fmt.Errorf("config format is %q, want %q", config.Format, formatV1)
	}
	if err := checkDigest(config.TreeDigest); err != nil {
		return nil, fmt.Errorf("config treeDigest: %w", err)
	}

	// RFC 8785 output has no insignificant whitespace, so a config that was
	// canonicalized survives a re-encode unchanged. This catches a writer
	// that emitted indented or reordered JSON, which would give two identical
	// payloads two different config digests.
	compact := &bytes.Buffer{}
	if err := json.Compact(compact, data); err != nil {
		return nil, fmt.Errorf("compacting the config: %w", err)
	}
	if !bytes.Equal(compact.Bytes(), data) {
		return nil, errors.New("the config blob is not canonical JSON: it contains insignificant whitespace")
	}
	return &config, nil
}

// fetchVerified retrieves a blob and checks it against its descriptor.
func fetchVerified(fetch BlobFetcher, want descriptor) ([]byte, error) {
	data, err := fetch(want.Digest)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != want.Size {
		return nil, fmt.Errorf("descriptor declares %d bytes, got %d", want.Size, len(data))
	}
	if got := digestOf(data); got != want.Digest {
		return nil, fmt.Errorf("descriptor declares %s, content hashes to %s", want.Digest, got)
	}
	return data, nil
}

// resolve finds the manifest digest for a reference.
func resolve(dir, reference string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return "", fmt.Errorf("reading index.json: %w", err)
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return "", fmt.Errorf("decoding index.json: %w", err)
	}

	if strings.HasPrefix(reference, "sha256:") {
		for _, entry := range idx.Manifests {
			if entry.Digest == reference {
				return reference, nil
			}
		}
		return "", fmt.Errorf("no manifest in the index has digest %s", reference)
	}

	if reference != "" {
		for _, entry := range idx.Manifests {
			if entry.Annotations["org.opencontainers.image.ref.name"] == reference {
				return entry.Digest, nil
			}
		}
		return "", fmt.Errorf("no manifest in the index is tagged %q", reference)
	}

	// Guessing which of several manifests the caller meant is how the wrong
	// artifact gets verified.
	var candidates []string
	for _, entry := range idx.Manifests {
		if entry.MediaType == mediaTypeManifest {
			candidates = append(candidates, entry.Digest)
		}
	}
	candidates = slices.Compact(candidates)
	if len(candidates) != 1 {
		return "", fmt.Errorf("the layout holds %d manifests; name one by tag or digest",
			len(candidates))
	}
	return candidates[0], nil
}

func checkLayoutMarker(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "oci-layout"))
	if err != nil {
		return fmt.Errorf("reading the oci-layout marker: %w", err)
	}
	var marker struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("decoding the oci-layout marker: %w", err)
	}
	if marker.Version != "1.0.0" {
		return fmt.Errorf("imageLayoutVersion is %q, want 1.0.0", marker.Version)
	}
	return nil
}

// readBlob loads a blob from a layout by digest.
func readBlob(dir, digest string) ([]byte, error) {
	if err := checkDigest(digest); err != nil {
		return nil, err
	}
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return os.ReadFile(filepath.Join(dir, "blobs", "sha256", hexPart))
}

func checkDigest(digest string) error {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return fmt.Errorf("digest %q is not sha256-prefixed", digest)
	}
	if len(hexPart) != 64 {
		return fmt.Errorf("digest %q is not 64 hex characters", digest)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("digest %q is not hexadecimal", digest)
	}
	// Lowercase hex only: two spellings of one digest would be two identities
	// for one artifact.
	if hexPart != strings.ToLower(hexPart) {
		return fmt.Errorf("digest %q is not lowercase", digest)
	}
	return nil
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// strictJSON decodes and rejects unknown fields.
func strictJSON(data []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}
