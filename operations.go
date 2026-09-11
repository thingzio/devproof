package devproof

import (
	"context"
	stderrors "errors"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/oci"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/policy"
)

// BuildRequest describes a bundle to build.
//
// Phase 1 supports a direct local-path source and a local OCI layout
// destination. Manifest-driven multi-source builds and registry destinations
// arrive in later phases behind the same operation boundary.
type BuildRequest struct {
	// SourcePath is the local directory to package.
	SourcePath string
	// MountPath places the source below a prefix in the bundle. Empty mounts
	// at the root.
	MountPath string
	// LayoutPath is the OCI image layout to write. It is created if absent.
	LayoutPath string
	// Tag optionally names the subject in the layout index.
	Tag string
	// Limits tightens the client's bounds for this operation.
	Limits Limits
}

// BuildResult describes what was built.
//
// Every identifier is a digest. A tag is reported separately and never stands
// in for one (DP-007).
type BuildResult struct {
	SubjectDigest string
	TreeDigest    string
	ConfigDigest  string
	LayerDigest   string
	Format        string
	FileCount     int64
	TotalBytes    int64
	LayerBytes    int64
	LayoutPath    string
	Tag           string
}

// Build packages a source tree into an OCI image layout.
//
// Content is snapshotted into private storage before anything is encoded, so
// the artifact describes one frozen moment rather than a directory that may
// be changing underneath it. Blobs are written before the manifest, and the
// tag is assigned last, so a name never points at content that is not
// completely present.
func (c *Client) Build(ctx context.Context, req BuildRequest) (_ *BuildResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if req.SourcePath == "" {
		return nil, fault.New(fault.CodeInvalidInput, "build", "a source path is required")
	}
	if req.LayoutPath == "" {
		return nil, fault.New(fault.CodeInvalidInput, "build", "a destination layout path is required")
	}

	limits := c.effectiveLimits(req.Limits)

	snapshot, err := safefs.SnapshotDir(ctx, req.SourcePath, safefs.SnapshotOptions{
		MountPath: req.MountPath,
		Limits:    limits.Limits,
		TempRoot:  c.tempRoot,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := snapshot.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	records := snapshot.Records()
	if len(records) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, "build",
			"source selected no files; a bundle must contain at least one")
	}

	layout, err := openOrCreateLayout(req.LayoutPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := layout.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	// The layer is buffered rather than streamed straight into the layout
	// because a content-addressed store cannot name a blob until it knows
	// its digest. Phase 3 replaces this with a staged blob write for
	// registry-sized payloads.
	var layerBuffer sizedBuffer
	subject, err := canonical.Package(ctx, records, snapshot, &layerBuffer)
	if err != nil {
		return nil, err
	}

	if _, err := layout.PutBlob(layerBuffer.Bytes()); err != nil {
		return nil, err
	}
	if _, err := layout.PutBlob(subject.ConfigBytes); err != nil {
		return nil, err
	}
	if _, err := layout.PutBlob(subject.ManifestBytes); err != nil {
		return nil, err
	}

	// The index entry, and any tag, only after every blob is durable.
	artifactType, _ := subject.Config.Format.ArtifactType()
	if err := layout.AddManifest(subject.Descriptor(), artifactType, req.Tag); err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "built bundle",
		"subject", subject.ManifestDigest.String(),
		"files", subject.Config.FileCount,
		"layout", layout.Path())

	return &BuildResult{
		SubjectDigest: subject.ManifestDigest.String(),
		TreeDigest:    subject.TreeDigest.String(),
		ConfigDigest:  subject.ConfigDigest.String(),
		LayerDigest:   subject.LayerDigest.String(),
		Format:        subject.Config.Format.String(),
		FileCount:     subject.Config.FileCount,
		TotalBytes:    subject.Config.TotalSize,
		LayerBytes:    subject.LayerSize,
		LayoutPath:    layout.Path(),
		Tag:           req.Tag,
	}, nil
}

// VerifyRequest describes a subject to verify.
type VerifyRequest struct {
	// LayoutPath is the OCI image layout to read.
	LayoutPath string
	// Reference is a digest or a tag. A tag is resolved once, and the
	// resolved digest is what the rest of the operation uses.
	Reference string
	// RequireDigest rejects a tag before any content is fetched.
	RequireDigest bool
	// Limits tightens the client's bounds for this operation.
	Limits Limits
}

// Verify checks a subject's integrity.
//
// Trust and semantics report not-evaluated in Phase 1: no policy evaluator
// and no validator exist yet. They are reported rather than omitted, because
// a caller needs to be able to see that they were not assessed (DP-010).
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (_ *policy.Report, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	subject, layout, err := c.loadSubject(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := layout.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	report := &policy.Report{
		Integrity:     policy.StatusPass,
		Trust:         policy.StatusNotEvaluated,
		Semantics:     policy.StatusNotEvaluated,
		SubjectDigest: subject.ManifestDigest.String(),
		TreeDigest:    subject.TreeDigest.String(),
		Format:        subject.Config.Format.String(),
		FileCount:     subject.Config.FileCount,
		TotalBytes:    subject.Config.TotalSize,
	}
	report.AddFinding(policy.Finding{
		Code:     policy.FindingPolicyNotSupplied,
		Severity: policy.SeverityWarning,
		Message: "no verification policy was supplied, so trust was not evaluated; " +
			"integrity alone does not establish that this artifact came from anyone in particular",
	})
	return report, nil
}

// ExpandRequest describes an expansion.
type ExpandRequest struct {
	LayoutPath string
	Reference  string
	// Destination must not exist. v1 has no overwrite or merge option.
	Destination   string
	RequireDigest bool
	Limits        Limits
}

// ExpandResult describes a published expansion.
type ExpandResult struct {
	Destination   string
	SubjectDigest string
	TreeDigest    string
	FileCount     int64
	TotalBytes    int64
	Verification  *policy.Report
}

// Expand verifies a subject and materializes its payload.
//
// Integrity verification is mandatory and has no flag that disables it. The
// result is returned only after the destination has been published, so a
// non-nil result means the files are there, complete, and verified.
func (c *Client) Expand(ctx context.Context, req ExpandRequest) (_ *ExpandResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if req.Destination == "" {
		return nil, fault.New(fault.CodeInvalidInput, "expand", "a destination is required")
	}

	limits := c.effectiveLimits(req.Limits)

	subject, layout, err := c.loadSubject(ctx, VerifyRequest{
		LayoutPath:    req.LayoutPath,
		Reference:     req.Reference,
		RequireDigest: req.RequireDigest,
		Limits:        req.Limits,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := layout.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	layer, _, err := layout.OpenBlob(subject.LayerDigest)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := layer.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, "expand", "closing the layer blob", closeErr)
		}
	}()

	result, err := safefs.Extract(ctx, layer, safefs.ExtractOptions{
		Destination: req.Destination,
		Config:      subject.Config,
		Limits:      limits.Limits,
	})
	if err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "expanded bundle",
		"subject", subject.ManifestDigest.String(),
		"destination", result.Destination,
		"files", result.FileCount)

	return &ExpandResult{
		Destination:   result.Destination,
		SubjectDigest: subject.ManifestDigest.String(),
		TreeDigest:    subject.TreeDigest.String(),
		FileCount:     result.FileCount,
		TotalBytes:    result.TotalBytes,
		Verification: &policy.Report{
			Integrity:     policy.StatusPass,
			Trust:         policy.StatusNotEvaluated,
			Semantics:     policy.StatusNotEvaluated,
			SubjectDigest: subject.ManifestDigest.String(),
			TreeDigest:    subject.TreeDigest.String(),
			Format:        subject.Config.Format.String(),
			FileCount:     subject.Config.FileCount,
			TotalBytes:    subject.Config.TotalSize,
		},
	}, nil
}

// loadSubject resolves a reference and verifies the subject's integrity.
//
// The returned layout is open and belongs to the caller to close. On any
// failure it is closed here, so an error path never leaks a handle.
func (c *Client) loadSubject(ctx context.Context, req VerifyRequest) (_ *canonical.Subject, _ *oci.Layout, retErr error) {
	if req.LayoutPath == "" {
		return nil, nil, fault.New(fault.CodeInvalidInput, "verify", "a layout path is required")
	}
	if req.Reference == "" {
		return nil, nil, fault.New(fault.CodeInvalidInput, "verify", "a reference is required")
	}
	if req.RequireDigest {
		if _, err := bundle.ParseDigest(req.Reference); err != nil {
			return nil, nil, fault.New(fault.CodeInvalidInput, "verify",
				"a digest reference is required, but a tag was supplied")
		}
	}
	if err := fault.FromContext(ctx, "verify", "verification canceled"); err != nil {
		return nil, nil, err
	}

	limits := c.effectiveLimits(req.Limits)

	layout, err := oci.Open(req.LayoutPath)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if retErr != nil {
			retErr = stderrors.Join(retErr, layout.Close())
		}
	}()

	item, err := layout.FindManifest(req.Reference)
	if err != nil {
		return nil, nil, err
	}
	manifestDigest, err := bundle.ParseDigest(item.Digest)
	if err != nil {
		return nil, nil, err
	}

	manifestBytes, err := layout.GetBlob(manifestDigest, limits.Limits.MaxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := canonical.ParseManifest(manifestBytes)
	if err != nil {
		return nil, nil, err
	}

	configDigest, err := manifest.Config.ParsedDigest()
	if err != nil {
		return nil, nil, err
	}
	configBytes, err := layout.GetBlob(configDigest, limits.Limits.MaxConfigBytes)
	if err != nil {
		return nil, nil, err
	}

	layerDescriptor, err := manifest.Layer()
	if err != nil {
		return nil, nil, err
	}
	layerDigest, err := layerDescriptor.ParsedDigest()
	if err != nil {
		return nil, nil, err
	}

	subject, err := canonical.VerifySubject(manifestBytes, configBytes, layerDescriptor.Size, layerDigest)
	if err != nil {
		return nil, nil, err
	}
	return subject, layout, nil
}

func openOrCreateLayout(path string) (*oci.Layout, error) {
	layout, err := oci.Open(path)
	if err == nil {
		return layout, nil
	}
	// Open fails for a path that is not yet a layout, which for a build
	// destination is the ordinary case rather than an error.
	return oci.Create(path)
}

// sizedBuffer accumulates the encoded layer.
type sizedBuffer struct{ b []byte }

func (s *sizedBuffer) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *sizedBuffer) Bytes() []byte { return s.b }
