package devproof_test

import (
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thingzio/devproof"
	"github.com/thingzio/devproof/policy"
)

func newClient(t *testing.T, opts ...devproof.Option) *devproof.Client {
	t.Helper()

	client, err := devproof.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing client: %v", err)
		}
	})
	return client
}

func writeSource(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %s: %v", full, err)
		}
	}
	return dir
}

func defaultSource(t *testing.T) string {
	t.Helper()
	return writeSource(t, map[string]string{
		"README.md":               "hello\n",
		"app/config/service.yaml": "a: 1\n",
		"nested/deep/file.txt":    "content",
	})
}

// The whole Phase 1 contract, exercised through the public API: a directory
// becomes an artifact, the artifact verifies, it expands back to a directory,
// and rebuilding from that directory reproduces the same subject digest.
func TestBuildVerifyExpandRoundTrip(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	source := defaultSource(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: source,
		LayoutPath: layoutPath,
		Tag:        "v1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.FileCount != 3 {
		t.Errorf("built %d files, want 3", built.FileCount)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		LayoutPath: layoutPath,
		Reference:  built.SubjectDigest,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Integrity != policy.StatusPass {
		t.Errorf("integrity = %q, want %q", report.Integrity, policy.StatusPass)
	}
	// Without a policy, trust must report not-evaluated rather than pass.
	// Reporting pass here would be the single most misleading thing DevProof
	// could do.
	if report.Trust != policy.StatusNotEvaluated {
		t.Errorf("trust = %q, want %q", report.Trust, policy.StatusNotEvaluated)
	}
	if report.Semantics != policy.StatusNotEvaluated {
		t.Errorf("semantics = %q, want %q", report.Semantics, policy.StatusNotEvaluated)
	}
	if !report.OK() {
		t.Error("a well-formed artifact did not report OK")
	}

	destination := filepath.Join(t.TempDir(), "expanded")
	expanded, err := client.Expand(t.Context(), devproof.ExpandRequest{
		LayoutPath:  layoutPath,
		Reference:   built.SubjectDigest,
		Destination: destination,
	})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if expanded.SubjectDigest != built.SubjectDigest {
		t.Errorf("expanded a different subject: %s", expanded.SubjectDigest)
	}

	rebuilt, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: destination,
		LayoutPath: filepath.Join(t.TempDir(), "layout2"),
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if rebuilt.SubjectDigest != built.SubjectDigest {
		t.Errorf("subject digest changed across the round trip:\n  first: %s\n second: %s",
			built.SubjectDigest, rebuilt.SubjectDigest)
	}
	if rebuilt.TreeDigest != built.TreeDigest {
		t.Errorf("tree digest changed: %s then %s", built.TreeDigest, rebuilt.TreeDigest)
	}
	if rebuilt.LayerDigest != built.LayerDigest {
		t.Errorf("layer digest changed: %s then %s", built.LayerDigest, rebuilt.LayerDigest)
	}
	if rebuilt.ConfigDigest != built.ConfigDigest {
		t.Errorf("config digest changed: %s then %s", built.ConfigDigest, rebuilt.ConfigDigest)
	}
}

// The layout must be a real OCI image layout, not a private format, so other
// tooling can read what DevProof writes.
func TestBuildProducesAConformantLayout(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		LayoutPath: layoutPath,
		Tag:        "v1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	marker, err := os.ReadFile(filepath.Join(layoutPath, "oci-layout"))
	if err != nil {
		t.Fatalf("reading oci-layout: %v", err)
	}
	var markerDoc struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(marker, &markerDoc); err != nil {
		t.Fatalf("decoding oci-layout: %v", err)
	}
	if markerDoc.ImageLayoutVersion != "1.0.0" {
		t.Errorf("imageLayoutVersion = %q", markerDoc.ImageLayoutVersion)
	}

	indexBytes, err := os.ReadFile(filepath.Join(layoutPath, "index.json"))
	if err != nil {
		t.Fatalf("reading index.json: %v", err)
	}
	var index struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			MediaType    string            `json:"mediaType"`
			Digest       string            `json:"digest"`
			ArtifactType string            `json:"artifactType"`
			Annotations  map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("decoding index.json: %v", err)
	}
	if index.SchemaVersion != 2 {
		t.Errorf("index schemaVersion = %d, want 2", index.SchemaVersion)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("index lists %d manifests, want 1", len(index.Manifests))
	}
	entry := index.Manifests[0]
	if entry.Digest != built.SubjectDigest {
		t.Errorf("index names %s, the build produced %s", entry.Digest, built.SubjectDigest)
	}
	if entry.ArtifactType != "application/vnd.thingz.devproof.bundle.v1" {
		t.Errorf("artifactType = %q", entry.ArtifactType)
	}
	if entry.Annotations["org.opencontainers.image.ref.name"] != "v1" {
		t.Errorf("tag annotation = %q", entry.Annotations["org.opencontainers.image.ref.name"])
	}

	// Every blob is filed under its own digest.
	for _, digest := range []string{built.SubjectDigest, built.ConfigDigest, built.LayerDigest} {
		hex := digest[len("sha256:"):]
		if _, err := os.Stat(filepath.Join(layoutPath, "blobs", "sha256", hex)); err != nil {
			t.Errorf("blob %s missing: %v", digest, err)
		}
	}
}

func TestVerifyResolvesTagToDigest(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		LayoutPath: layoutPath,
		Tag:        "release",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		LayoutPath: layoutPath,
		Reference:  "release",
	})
	if err != nil {
		t.Fatalf("Verify by tag: %v", err)
	}
	// The result identifies the subject by digest even though a tag was
	// supplied (DP-007).
	if report.SubjectDigest != built.SubjectDigest {
		t.Errorf("resolved to %s, want %s", report.SubjectDigest, built.SubjectDigest)
	}
}

func TestVerifyRequireDigestRejectsTag(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		LayoutPath: layoutPath,
		Tag:        "release",
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err := client.Verify(t.Context(), devproof.VerifyRequest{
		LayoutPath:    layoutPath,
		Reference:     "release",
		RequireDigest: true,
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

// A layout is an ordinary directory. Editing a blob in place must be caught,
// because the file name is a lookup key and never evidence of content.
func TestVerifyDetectsTamperedBlob(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		LayoutPath: layoutPath,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	configBlob := filepath.Join(layoutPath, "blobs", "sha256", built.ConfigDigest[len("sha256:"):])
	original, err := os.ReadFile(configBlob) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("reading config blob: %v", err)
	}
	tampered := append([]byte{}, original...)
	tampered[len(tampered)-2] = ' ' // keeps the length, changes the bytes
	if err := os.WriteFile(configBlob, tampered, 0o644); err != nil {
		t.Fatalf("tampering: %v", err)
	}

	_, err = client.Verify(t.Context(), devproof.VerifyRequest{
		LayoutPath: layoutPath,
		Reference:  built.SubjectDigest,
	})
	if !stderrors.Is(err, devproof.CodeDigestMismatch) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeDigestMismatch)
	}
}

func TestExpandRefusesExistingDestination(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	layoutPath := filepath.Join(t.TempDir(), "layout")

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		LayoutPath: layoutPath,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatalf("creating destination: %v", err)
	}

	_, err = client.Expand(t.Context(), devproof.ExpandRequest{
		LayoutPath:  layoutPath,
		Reference:   built.SubjectDigest,
		Destination: destination,
	})
	if !stderrors.Is(err, devproof.CodeDestinationExists) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeDestinationExists)
	}
}

func TestBuildRejectsEmptySource(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: t.TempDir(),
		LayoutPath: filepath.Join(t.TempDir(), "layout"),
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

// A mount path changes where content lands, and therefore the identity of the
// bundle, without changing the content itself.
func TestBuildMountPathChangesSubjectDigest(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	source := defaultSource(t)

	atRoot, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: source,
		LayoutPath: filepath.Join(t.TempDir(), "a"),
	})
	if err != nil {
		t.Fatalf("Build at root: %v", err)
	}
	mounted, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: source,
		MountPath:  "environment",
		LayoutPath: filepath.Join(t.TempDir(), "b"),
	})
	if err != nil {
		t.Fatalf("Build mounted: %v", err)
	}

	if atRoot.SubjectDigest == mounted.SubjectDigest {
		t.Error("mounting content elsewhere did not change the subject digest")
	}
	if atRoot.FileCount != mounted.FileCount {
		t.Error("mounting changed the file count")
	}
}

// Limits from the client and from the request intersect; neither can relax
// the other (DP-021).
func TestLimitsIntersectAcrossClientAndRequest(t *testing.T) {
	t.Parallel()

	client := newClient(t, devproof.WithLimits(devproof.Limits{MaxFiles: 2}))

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t), // three files
		LayoutPath: filepath.Join(t.TempDir(), "layout"),
		Limits:     devproof.Limits{MaxFiles: 1000},
	})
	if !stderrors.Is(err, devproof.CodeLimitExceeded) {
		t.Errorf("a request limit relaxed the client's: code = %q", codeOf(err))
	}
}

func TestClientRejectsUseAfterClose(t *testing.T) {
	t.Parallel()

	client, err := devproof.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := client.Build(t.Context(), devproof.BuildRequest{}); !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

func TestNewRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	if _, err := devproof.New(devproof.WithLimits(devproof.Limits{MaxFiles: -1})); err == nil {
		t.Error("a negative limit was accepted")
	}
	if _, err := devproof.New(devproof.WithLogger(nil)); err == nil {
		t.Error("a nil logger was accepted")
	}
	if _, err := devproof.New(nil); err == nil {
		t.Error("a nil option was accepted")
	}
}

// codeOf extracts a DevProof code for a test message.
func codeOf(err error) devproof.Code {
	var typed *devproof.Error
	if stderrors.As(err, &typed) {
		return typed.Code
	}
	return "<untyped>"
}
