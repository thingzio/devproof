package oci

import (
	stderrors "errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
)

func newLayout(t *testing.T) *Layout {
	t.Helper()

	layout, err := Create(filepath.Join(t.TempDir(), "layout"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = layout.Close() })
	return layout
}

func TestCreateAndOpen(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "layout")

	created, err := Create(dir)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	opened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = opened.Close(); _ = opened.Close() }() // Close is idempotent.

	index, err := opened.Index()
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(index.Manifests) != 0 {
		t.Errorf("a fresh layout lists %d manifests", len(index.Manifests))
	}
}

func TestOpenRejectsNonLayout(t *testing.T) {
	t.Parallel()

	if _, err := Open(t.TempDir()); !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("opening a missing directory succeeded")
	}
	if _, err := Open(""); !stderrors.Is(err, fault.CodeInvalidInput) {
		t.Errorf("empty path: code = %q", fault.CodeOf(err))
	}
}

func TestPutAndGetBlob(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	content := []byte("blob content")

	digest, err := layout.PutBlob(content)
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if digest != canonical.DigestOf(content) {
		t.Error("PutBlob reported a digest that does not describe the content")
	}

	got, err := layout.GetBlob(digest, 1<<20)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("GetBlob returned %q", got)
	}

	// Content-addressed: storing the same bytes twice is a no-op.
	again, err := layout.PutBlob(content)
	if err != nil {
		t.Fatalf("second PutBlob: %v", err)
	}
	if again != digest {
		t.Error("storing identical content produced a different digest")
	}
}

// A layout is an ordinary directory that anything can edit. Its file names
// are a lookup key, never evidence of what the file contains.
func TestGetBlobDetectsTamperedContent(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	digest, err := layout.PutBlob([]byte("original"))
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	path := filepath.Join(layout.Path(), "blobs", "sha256", digest.Hex())
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tampering: %v", err)
	}

	if _, err := layout.GetBlob(digest, 1<<20); !stderrors.Is(err, fault.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeDigestMismatch)
	}
}

// A bounded read stops a layout directory someone else can write from
// forcing an unbounded allocation.
func TestGetBlobHonorsLimit(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	digest, err := layout.PutBlob(make([]byte, 4096))
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	if _, err := layout.GetBlob(digest, 100); !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
	}
	// Exactly at the limit is allowed; one byte over is not.
	if _, err := layout.GetBlob(digest, 4096); err != nil {
		t.Errorf("a blob exactly at the limit was rejected: %v", err)
	}
}

func TestOpenBlobStreams(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	content := []byte("streamed content")
	digest, err := layout.PutBlob(content)
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	reader, size, err := layout.OpenBlob(digest)
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("read %q", got)
	}

	if _, _, err := layout.OpenBlob(canonical.DigestOf([]byte("absent"))); err == nil {
		t.Error("opening a missing blob succeeded")
	}
}

func addManifest(t *testing.T, layout *Layout, content, tag string) artifact.Descriptor {
	t.Helper()

	if _, err := layout.PutBlob([]byte(content)); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, []byte(content))
	if err := layout.AddManifest(descriptor, bundle.MediaTypeArtifactV1, tag); err != nil {
		t.Fatalf("AddManifest: %v", err)
	}
	return descriptor
}

// A name must never point at content that is not present. This is the local
// equivalent of a registry's publication barrier.
func TestAddManifestRequiresTheBlobToBePresent(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, []byte("never stored"))

	err := layout.AddManifest(descriptor, bundle.MediaTypeArtifactV1, "v1")
	if !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
}

func TestFindManifestByDigestAndTag(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	descriptor := addManifest(t, layout, "manifest one", "v1")

	byDigest, err := layout.FindManifest(descriptor.Digest)
	if err != nil {
		t.Fatalf("FindManifest by digest: %v", err)
	}
	if byDigest.Digest != descriptor.Digest {
		t.Errorf("resolved %s", byDigest.Digest)
	}

	byTag, err := layout.FindManifest("v1")
	if err != nil {
		t.Fatalf("FindManifest by tag: %v", err)
	}
	if byTag.Digest != descriptor.Digest {
		t.Errorf("tag resolved to %s, want %s", byTag.Digest, descriptor.Digest)
	}

	if _, err := layout.FindManifest("absent"); err == nil {
		t.Error("an unknown tag resolved")
	}
	if _, err := layout.FindManifest(canonical.DigestOf([]byte("absent")).String()); err == nil {
		t.Error("an unknown digest resolved")
	}
}

// A tag names one subject. Re-tagging must move the name rather than leave
// two entries a reader would resolve arbitrarily.
func TestRetaggingMovesTheName(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	addManifest(t, layout, "manifest one", "latest")
	second := addManifest(t, layout, "manifest two", "latest")

	resolved, err := layout.FindManifest("latest")
	if err != nil {
		t.Fatalf("FindManifest: %v", err)
	}
	if resolved.Digest != second.Digest {
		t.Errorf("tag resolves to %s, want the newly tagged %s", resolved.Digest, second.Digest)
	}

	index, err := layout.Index()
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	tagged := 0
	for _, item := range index.Manifests {
		if item.Ref() == "latest" {
			tagged++
		}
	}
	if tagged != 1 {
		t.Errorf("%d index entries carry the tag, want 1", tagged)
	}
}

// The tag annotation lives on the index entry, never on the subject manifest:
// an annotation on the subject would change its digest (DP-002).
func TestTagIsRecordedOnTheIndexNotTheSubject(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	descriptor := addManifest(t, layout, "manifest body", "v1")

	item, err := layout.FindManifest("v1")
	if err != nil {
		t.Fatalf("FindManifest: %v", err)
	}
	if item.Annotations[AnnotationRefName] != "v1" {
		t.Errorf("index annotation = %q", item.Annotations[AnnotationRefName])
	}

	digest, err := descriptor.ParsedDigest()
	if err != nil {
		t.Fatalf("ParsedDigest: %v", err)
	}
	stored, err := layout.GetBlob(digest, 1<<20)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if string(stored) != "manifest body" {
		t.Error("the stored manifest was modified by tagging")
	}
}

func TestInvalidTagsAreRejected(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	content := "manifest body"
	if _, err := layout.PutBlob([]byte(content)); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	descriptor := artifact.DescriptorFor(artifact.MediaTypeImageManifest, []byte(content))

	for _, tag := range []string{
		".leading-dot", "-leading-dash", "has space", "has/slash", "has:colon",
		string(make([]byte, 129)),
	} {
		if err := layout.AddManifest(descriptor, bundle.MediaTypeArtifactV1, tag); err == nil {
			t.Errorf("tag %q was accepted", tag)
		}
	}

	for _, tag := range []string{"v1", "latest", "_build", "1.2.3-rc.1", "A_b.c-d"} {
		if err := layout.AddManifest(descriptor, bundle.MediaTypeArtifactV1, tag); err != nil {
			t.Errorf("valid tag %q was rejected: %v", tag, err)
		}
	}
}

// A crash must never leave a truncated blob at a digest-shaped name, where a
// reader would take the name as proof of the content.
func TestWritesLeaveNoTemporaryFiles(t *testing.T) {
	t.Parallel()

	layout := newLayout(t)
	if _, err := layout.PutBlob([]byte("content")); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(layout.Path(), "blobs", "sha256"))
	if err != nil {
		t.Fatalf("reading blob directory: %v", err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != "" {
			t.Errorf("a temporary file survived: %s", entry.Name())
		}
	}
}
