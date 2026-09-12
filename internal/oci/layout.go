// Package oci stores and retrieves DevProof subjects as OCI objects.
//
// The local image layout implemented here is the Phase 1 transport: it is a
// real, spec-shaped OCI layout that other tooling can read, which makes the
// hardest guarantees — canonical bytes and safe expansion — testable without a
// registry in the picture.
package oci

import (
	"crypto/sha256"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
)

const layoutOp = "oci.layout"

// OCI image layout file names and values, from the image-spec.
const (
	layoutMarkerFile   = "oci-layout"
	indexFile          = "index.json"
	blobsDir           = "blobs"
	sha256Dir          = "sha256"
	imageLayoutVersion = "1.0.0"

	// MediaTypeImageIndex is the OCI index media type.
	MediaTypeImageIndex = "application/vnd.oci.image.index.v1+json"

	// AnnotationRefName is the conventional annotation carrying a tag.
	// It lives on the index, never on the subject manifest: an annotation on
	// the subject would change its digest (DP-002).
	AnnotationRefName = "org.opencontainers.image.ref.name"
)

// layoutMarker is the content of the oci-layout file.
type layoutMarker struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// Index is the layout's index.json.
type Index struct {
	SchemaVersion int         `json:"schemaVersion"`
	MediaType     string      `json:"mediaType"`
	Manifests     []IndexItem `json:"manifests"`
}

// IndexItem references a manifest in the layout.
//
// Unlike a subject manifest, an index entry may carry annotations: the index
// is a local directory listing, not content anybody addresses by digest, so a
// tag recorded here cannot change what the subject is.
type IndexItem struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	// Subject names the manifest this one is a referrer for. A layout has no
	// referrers API, so the index is where that relationship is recorded.
	Subject string `json:"subject,omitempty"`
}

// Descriptor returns the item as a plain descriptor.
func (i IndexItem) Descriptor() artifact.Descriptor {
	return artifact.Descriptor{MediaType: i.MediaType, Digest: i.Digest, Size: i.Size}
}

// Ref returns the item's tag, if it has one.
func (i IndexItem) Ref() string { return i.Annotations[AnnotationRefName] }

// Layout is an OCI image layout directory.
//
// Every operation goes through an [os.Root] held on the layout directory, so
// a blob path derived from a digest cannot escape it even if the digest
// string were somehow attacker-controlled.
type Layout struct {
	path string
	root *os.Root
}

// Create makes a new OCI image layout at dir.
//
// The directory must not already be a layout. Writing into an existing one
// would mean inheriting blobs and an index that this process never verified.
func Create(dir string) (_ *Layout, retErr error) {
	if dir == "" {
		return nil, fault.New(fault.CodeInvalidInput, layoutOp, "layout path must not be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, layoutOp, "resolving layout path", err)
	}

	if mkdirErr := os.MkdirAll(abs, 0o755); mkdirErr != nil {
		return nil, fault.Wrap(fault.CodeInternal, layoutOp, "creating layout directory", mkdirErr)
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, layoutOp, "opening layout directory", err)
	}
	layout := &Layout{path: abs, root: root}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, layout.Close())
		}
	}()

	if mkdirErr := root.MkdirAll(filepath.Join(blobsDir, sha256Dir), 0o755); mkdirErr != nil {
		return nil, fault.Wrap(fault.CodeInternal, layoutOp, "creating blob directory", mkdirErr)
	}

	marker, markerErr := json.Marshal(layoutMarker{ImageLayoutVersion: imageLayoutVersion})
	if markerErr != nil {
		return nil, fault.Wrap(fault.CodeInternal, layoutOp, "encoding the layout marker", markerErr)
	}
	if err := layout.writeFileAtomic(layoutMarkerFile, marker); err != nil {
		return nil, err
	}
	if err := layout.SetIndex(nil); err != nil {
		return nil, err
	}
	return layout, nil
}

// Open opens an existing OCI image layout.
func Open(dir string) (_ *Layout, retErr error) {
	if dir == "" {
		return nil, fault.New(fault.CodeInvalidInput, layoutOp, "layout path must not be empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, layoutOp, "resolving layout path", err)
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, layoutOp, "opening layout directory", err)
	}
	layout := &Layout{path: abs, root: root}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, layout.Close())
		}
	}()

	marker, err := layout.readFile(layoutMarkerFile, 1<<10)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, layoutOp,
			"directory is not an OCI image layout", err)
	}
	var parsed layoutMarker
	if decodeErr := json.Unmarshal(marker, &parsed); decodeErr != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "reading the layout marker", decodeErr)
	}
	if parsed.ImageLayoutVersion != imageLayoutVersion {
		return nil, fault.New(fault.CodeUnsupportedVersion, layoutOp,
			fmt.Sprintf("image layout version %q is not supported", parsed.ImageLayoutVersion))
	}
	return layout, nil
}

// Path returns the layout's absolute path.
func (l *Layout) Path() string { return l.path }

// Close releases the layout's directory handle.
func (l *Layout) Close() error {
	if l.root == nil {
		return nil
	}
	err := l.root.Close()
	l.root = nil
	if err != nil {
		return fault.Wrap(fault.CodeInternal, layoutOp, "closing layout", err)
	}
	return nil
}

// blobPath returns the layout-relative path for a digest.
func blobPath(d canonical.Digest) string {
	return filepath.Join(blobsDir, sha256Dir, d.Hex())
}

// PutBlob stores content under its digest.
//
// The digest is recomputed from the bytes rather than trusted from the
// caller, because a blob filed under the wrong name is a blob that will later
// verify against a descriptor it does not match. Writing is atomic: content
// lands at a temporary name, is synced, and is renamed into place, so a
// crash never leaves a truncated blob at a digest-shaped path where a reader
// would take its name as proof of its content.
func (l *Layout) PutBlob(content []byte) (canonical.Digest, error) {
	digest := canonical.DigestOf(content)

	target := blobPath(digest)
	if _, statErr := l.root.Stat(target); statErr == nil {
		// Content-addressed: an existing blob at this digest already holds
		// these bytes.
		return digest, nil
	}

	if err := l.writeFileAtomic(target, content); err != nil {
		return canonical.Digest{}, err
	}
	return digest, nil
}

// GetBlob reads a blob, verifying it against its digest.
//
// limit bounds the read so that a layout directory someone else can write
// cannot force an unbounded allocation.
func (l *Layout) GetBlob(digest canonical.Digest, limit int64) ([]byte, error) {
	content, err := l.readFile(blobPath(digest), limit)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "reading blob", err).
			WithPath(digest.String())
	}
	// Re-verify on read. A layout is an ordinary directory that anything can
	// edit between the write and the read, so its file names are a lookup
	// key, never evidence.
	if got := canonical.DigestOf(content); got != digest {
		return nil, fault.New(fault.CodeDigestMismatch, layoutOp,
			fmt.Sprintf("blob content is %s but it is filed under %s", got, digest))
	}
	return content, nil
}

// OpenBlob returns a streaming reader over a blob.
//
// The caller is responsible for verifying the digest as it reads; this exists
// for the layer, which is too large to hold in memory just to check it once.
func (l *Layout) OpenBlob(digest canonical.Digest) (io.ReadCloser, int64, error) {
	path := blobPath(digest)

	info, err := l.root.Stat(path)
	if err != nil {
		return nil, 0, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "reading blob", err).
			WithPath(digest.String())
	}
	file, err := l.root.Open(path)
	if err != nil {
		return nil, 0, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "opening blob", err).
			WithPath(digest.String())
	}
	return file, info.Size(), nil
}

// SetIndex replaces index.json.
func (l *Layout) SetIndex(items []IndexItem) error {
	index := Index{
		SchemaVersion: artifact.ManifestSchemaVersion,
		MediaType:     MediaTypeImageIndex,
		Manifests:     items,
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, layoutOp, "encoding the index", err)
	}
	return l.writeFileAtomic(indexFile, encoded)
}

// Index reads index.json.
func (l *Layout) Index() (*Index, error) {
	content, err := l.readFile(indexFile, 1<<20)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "reading the index", err)
	}
	var index Index
	if err := json.Unmarshal(content, &index); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, layoutOp, "decoding the index", err)
	}
	return &index, nil
}

// AddManifest records a subject in the index, optionally under a tag.
//
// A tag is written only after the manifest it names is already present, which
// is the local equivalent of the publication barrier a registry push observes
// (DP-007): a name never points at content that has not landed.
func (l *Layout) AddManifest(descriptor artifact.Descriptor, artifactType, tag string) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	digest, err := descriptor.ParsedDigest()
	if err != nil {
		return err
	}
	if _, statErr := l.root.Stat(blobPath(digest)); statErr != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, layoutOp,
			"cannot reference a manifest that is not in the layout", statErr).WithPath(descriptor.Digest)
	}

	index, err := l.Index()
	if err != nil {
		return err
	}

	item := IndexItem{
		MediaType:    descriptor.MediaType,
		Digest:       descriptor.Digest,
		Size:         descriptor.Size,
		ArtifactType: artifactType,
	}
	if tag != "" {
		if err := validateTag(tag); err != nil {
			return err
		}
		item.Annotations = map[string]string{AnnotationRefName: tag}
	}

	// A tag names one subject. Re-tagging drops the old entry rather than
	// leaving two entries with one name, which a reader would resolve
	// arbitrarily.
	kept := make([]IndexItem, 0, len(index.Manifests)+1)
	for _, existing := range index.Manifests {
		if existing.Digest == item.Digest && existing.Ref() == item.Ref() {
			continue
		}
		if tag != "" && existing.Ref() == tag {
			continue
		}
		kept = append(kept, existing)
	}
	kept = append(kept, item)

	return l.SetIndex(kept)
}

// FindManifest resolves a reference, which may be a digest or a tag.
//
// A tag is resolved to a digest here and the digest is what every later step
// uses, so a tag that moves mid-operation cannot change what was verified
// (DP-007).
func (l *Layout) FindManifest(reference string) (IndexItem, error) {
	index, err := l.Index()
	if err != nil {
		return IndexItem{}, err
	}

	if digest, err := bundle.ParseDigest(reference); err == nil {
		for _, item := range index.Manifests {
			if item.Digest == digest.String() {
				return item, nil
			}
		}
		return IndexItem{}, fault.New(fault.CodeInvalidArtifact, layoutOp,
			"no manifest in the layout has that digest").WithPath(reference)
	}

	var matches []IndexItem
	for _, item := range index.Manifests {
		if item.Ref() == reference {
			matches = append(matches, item)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return IndexItem{}, fault.New(fault.CodeInvalidArtifact, layoutOp,
			fmt.Sprintf("no manifest in the layout is tagged %q", reference))
	default:
		return IndexItem{}, fault.New(fault.CodeInvalidArtifact, layoutOp,
			fmt.Sprintf("tag %q resolves to %d manifests", reference, len(matches)))
	}
}

// validateTag applies the OCI tag grammar.
func validateTag(tag string) error {
	const maxTagLength = 128

	if len(tag) > maxTagLength {
		return fault.New(fault.CodeInvalidInput, layoutOp,
			fmt.Sprintf("tag is %d characters, the maximum is %d", len(tag), maxTagLength))
	}
	if tag == "" {
		return fault.New(fault.CodeInvalidInput, layoutOp, "tag must not be empty")
	}
	first := tag[0]
	if !isAlphanumeric(first) && first != '_' {
		return fault.New(fault.CodeInvalidInput, layoutOp,
			"a tag must begin with an alphanumeric character or underscore")
	}
	for i := range len(tag) {
		c := tag[i]
		if !isAlphanumeric(c) && c != '_' && c != '.' && c != '-' {
			return fault.New(fault.CodeInvalidInput, layoutOp,
				fmt.Sprintf("tag contains the character %q", string(c)))
		}
	}
	return nil
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// writeFileAtomic writes content to name via a temporary file and a rename.
func (l *Layout) writeFileAtomic(name string, content []byte) (retErr error) {
	dir := filepath.Dir(name)
	if dir != "." {
		if err := l.root.MkdirAll(dir, 0o755); err != nil {
			return fault.Wrap(fault.CodeInternal, layoutOp, "creating directory", err).WithPath(name)
		}
	}

	temp := name + ".tmp-" + randomSuffix(content)
	file, err := l.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, layoutOp, "creating file", err).WithPath(name)
	}

	cleanup := func() {
		if retErr != nil {
			_ = l.root.Remove(temp)
		}
	}
	defer cleanup()

	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return fault.Wrap(fault.CodeInternal, layoutOp, "writing file", err).WithPath(name)
	}
	// Sync before the rename: without it a crash can leave the rename
	// durable while the content is not, which is a zero-length blob at a
	// digest-shaped name.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fault.Wrap(fault.CodeInternal, layoutOp, "syncing file", err).WithPath(name)
	}
	if err := file.Close(); err != nil {
		return fault.Wrap(fault.CodeInternal, layoutOp, "closing file", err).WithPath(name)
	}
	if err := l.root.Rename(temp, name); err != nil {
		return fault.Wrap(fault.CodeInternal, layoutOp, "publishing file", err).WithPath(name)
	}
	return nil
}

// randomSuffix derives a temporary-name suffix from the content digest.
//
// Content-derived rather than random: two concurrent writers of the same blob
// pick the same temporary name and the loser's rename is a harmless no-op,
// whereas random names would leave orphaned temporaries behind.
func randomSuffix(content []byte) string {
	sum := sha256.Sum256(content)
	return strings.ToLower(fmt.Sprintf("%x", sum[:8]))
}

// readFile reads a layout file, refusing anything larger than limit.
func (l *Layout) readFile(name string, limit int64) (_ []byte, retErr error) {
	file, err := l.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	// Read one byte past the limit so that hitting it exactly is
	// distinguishable from exceeding it.
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fault.New(fault.CodeLimitExceeded, layoutOp,
			fmt.Sprintf("file exceeds the limit of %d bytes", limit)).WithPath(name)
	}
	return content, nil
}

// AddReferrer records an evidence manifest against its subject.
//
// Unlike AddManifest this never carries a tag and never replaces an existing
// entry with a different digest: a subject may have several pieces of
// evidence, and attaching one must not remove another (DP-003).
func (l *Layout) AddReferrer(descriptor artifact.Descriptor, artifactType, subjectDigest string) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if subjectDigest == "" {
		return fault.New(fault.CodeInvalidArtifact, layoutOp, "a referrer must name a subject")
	}
	digest, err := descriptor.ParsedDigest()
	if err != nil {
		return err
	}
	if _, statErr := l.root.Stat(blobPath(digest)); statErr != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, layoutOp,
			"cannot reference a manifest that is not in the layout", statErr).
			WithPath(descriptor.Digest)
	}

	index, err := l.Index()
	if err != nil {
		return err
	}
	for _, existing := range index.Manifests {
		if existing.Digest == descriptor.Digest && existing.Subject == subjectDigest {
			// Already recorded. Content-addressed, so this is the same
			// evidence, and re-attaching it is a no-op rather than an error.
			return nil
		}
	}

	index.Manifests = append(index.Manifests, IndexItem{
		MediaType:    descriptor.MediaType,
		Digest:       descriptor.Digest,
		Size:         descriptor.Size,
		ArtifactType: artifactType,
		Subject:      subjectDigest,
	})
	return l.SetIndex(index.Manifests)
}
