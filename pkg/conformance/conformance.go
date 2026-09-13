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
// So this package is deliberately built from docs/bundle-format.md and nothing
// else. It imports no other DevProof package — not the media-type constants,
// not the canonical encoders, not the digest helpers. Every value it compares
// against is written out here from the specification text, and every structure
// it parses it parses again from scratch. Where this package and the main
// implementation disagree, one of them is wrong, and finding out which is the
// entire point.
//
// It reads raw tar blocks rather than using archive/tar. That package is
// lenient by design: it accepts GNU and base-256 encodings, silently joins the
// USTAR prefix field onto the name, and hides how a value was spelled. Every
// one of those kindnesses conceals exactly the deviation this package exists
// to find, and a reader built on it accepted archives no conforming writer
// produces. The one outside dependency is a Unicode normalizer, because NFC is
// a specification rule and its tables are not in the standard library.
//
// It is intentionally simple and unoptimized. It buffers what a streaming
// reader would not, because being obviously correct matters more here than
// being fast, and a second implementation that is clever enough to be wrong in
// the same way as the first has no value.
package conformance

import (
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
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
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

	// The manifest's digest is the subject's identity, so its spelling is part
	// of the format and not a detail of whoever encoded it.
	if err := CheckCanonicalJSON(manifestBytes); err != nil {
		return nil, fmt.Errorf("the manifest is not canonical JSON: %w", err)
	}

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

// gzipHeaderV1 is the complete fixed gzip header format v1 emits.
//
// Transcribed from the specification's frozen settings: magic 1f 8b, DEFLATE,
// no flags, mtime 0, XFL 2 for maximum compression, OS 255 for unknown. Every
// one of those is a field that would otherwise record when and where the
// artifact was built, so the bytes are checked rather than the parsed values --
// compress/gzip silently tolerates an OS byte it has no opinion about.
var gzipHeaderV1 = []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff}

// readLayer decompresses and walks the tar, returning the file inventory.
//
// Directories are checked for canonical mode but are not returned: the tree
// digest is over files alone.
func readLayer(compressed []byte) ([]FileRecord, error) {
	if len(compressed) < len(gzipHeaderV1) ||
		!bytes.Equal(compressed[:len(gzipHeaderV1)], gzipHeaderV1) {

		got := compressed
		if len(got) > len(gzipHeaderV1) {
			got = got[:len(gzipHeaderV1)]
		}
		return nil, fmt.Errorf("the gzip header is %x, want the frozen v1 header %x",
			got, gzipHeaderV1)
	}

	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("opening the gzip stream: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// The header bytes above already exclude a name, comment, extra field, and
	// timestamp, because every one of them requires a flag bit this reader
	// refuses. Reading the whole member still matters: it is what checks the
	// trailing CRC and length.
	plain, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decompressing the layer: %w", err)
	}

	entries, err := readTar(plain)
	if err != nil {
		return nil, err
	}

	var (
		files    []FileRecord
		seen     = map[string]bool{}
		folded   = map[string]string{}
		haveDirs = map[string]bool{}
		needDirs = map[string]bool{}
		// Entry order is: every required directory in sorted order, then
		// every file in sorted order. Tracked as two independently ascending
		// runs, with any directory after the first file being an error.
		lastDir  string
		lastFile string
		inFiles  bool
	)

	for _, entry := range entries {
		name := entry.name
		isDir := entry.typeflag == typeDirectory
		clean := strings.TrimSuffix(name, "/")

		// A trailing slash is how a directory is spelled and the only place one
		// is legal. A regular file wearing one would name a path no reader
		// could open.
		if strings.HasSuffix(name, "/") != isDir {
			return nil, fmt.Errorf("entry %q has type %q; only a directory ends in a slash",
				name, string(entry.typeflag))
		}

		if err := checkPath(clean); err != nil {
			return nil, err
		}
		if seen[clean] {
			return nil, fmt.Errorf("duplicate tar entry %q", clean)
		}
		seen[clean] = true

		// Case-fold uniqueness is enforced across the complete tree, because a
		// case-insensitive filesystem would otherwise expand two entries onto
		// one path and silently keep whichever came last.
		key := strings.ToLower(clean)
		if other, collides := folded[key]; collides {
			return nil, fmt.Errorf("paths %q and %q differ only by case", other, clean)
		}
		folded[key] = clean

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

		switch {
		case isDir:
			if entry.mode != modeDirectory {
				return nil, fmt.Errorf("directory %q has mode %04o, want %04o",
					clean, entry.mode, modeDirectory)
			}
			haveDirs[clean] = true

		default:
			if entry.mode != modeFile && entry.mode != modeExecutable {
				return nil, fmt.Errorf("file %q has mode %04o, want %04o or %04o",
					clean, entry.mode, modeFile, modeExecutable)
			}

			for parent := path.Dir(clean); parent != "." && parent != "/"; parent = path.Dir(parent) {
				needDirs[parent] = true
			}

			files = append(files, FileRecord{
				Path:   clean,
				Mode:   entry.mode,
				Size:   entry.size,
				Digest: digestOf(entry.content),
			})
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

// reservedNames are the device names a portable path may not use, in any
// case, with or without an extension.
//
// They are not Windows trivia: a path that cannot be created on a supported
// platform is one that expands correctly on the machine that built it and
// fails on the machine that consumes it, which is the failure this format
// exists to prevent.
var reservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// reservedRunes may not appear in a path segment.
const reservedRunes = `<>:"\\|?*`

// checkPath applies the canonical path rules from the specification.
//
// Every numbered rule in the path-normalization section is checked here. A
// reader that enforced only the obvious ones would accept archives that no
// conforming writer produces and that some consumer cannot expand, which is
// the same as having no rule.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("an entry has an empty path")
	case !utf8.ValidString(p):
		return fmt.Errorf("path %q is not valid UTF-8", p)
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("path %q is absolute", p)
	case p != path.Clean(p):
		return fmt.Errorf("path %q is not clean", p)
	case !norm.NFC.IsNormalString(p):
		return fmt.Errorf("path %q is not Unicode NFC", p)
	}

	for _, r := range p {
		if r == 0 {
			return fmt.Errorf("path %q contains a NUL", p)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path %q contains the control character U+%04X", p, r)
		}
	}

	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("path %q contains the element %q", p, segment)
		}
		if strings.HasSuffix(segment, " ") || strings.HasSuffix(segment, ".") {
			return fmt.Errorf("path %q has a segment ending in a space or period", p)
		}
		if i := strings.IndexAny(segment, reservedRunes); i >= 0 {
			return fmt.Errorf("path %q contains the reserved character %q", p, segment[i])
		}
		// Reserved with an extension too: CON.txt names the console on the
		// platforms that reserve CON.
		stem, _, _ := strings.Cut(segment, ".")
		if reservedNames[strings.ToLower(stem)] {
			return fmt.Errorf("path %q uses the reserved device name %q", p, stem)
		}
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

	if err := CheckCanonicalJSON(data); err != nil {
		return nil, fmt.Errorf("the config blob is not canonical JSON: %w", err)
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
