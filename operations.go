package devproof

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/oci"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/policy"
	sourcepath "github.com/thingzio/devproof/source/path"
)

// BuildRequest describes a bundle to build.
//
// A build is driven by either a manifest or a single direct source, never
// both. Direct mode synthesizes a one-source manifest and runs the identical
// pipeline, so there is no second implementation whose behavior could drift.
type BuildRequest struct {
	// SpecPath is a manifest file to build from.
	SpecPath string
	// Spec is a manifest supplied in memory. SpecDir gives the directory
	// relative source paths resolve against.
	Spec    *bundle.Spec
	SpecDir string

	// SourcePath builds a single local directory directly, without a
	// manifest. Mutually exclusive with SpecPath and Spec.
	SourcePath string
	// MountPath places a direct source below a prefix.
	MountPath string
	// Include and Exclude filter a direct source.
	Include []string
	Exclude []string

	// LockPath is the lock to enforce. When a manifest build finds a lock
	// beside the manifest, it is enforced by default (DP-004).
	LockPath string
	// Lock is a lock supplied in memory.
	Lock *bundle.Lock
	// UpdateLock resolves afresh and writes a new lock rather than enforcing
	// the existing one. Never implied: a build does not silently relock.
	UpdateLock bool
	// SkipLock builds without a lock at all.
	SkipLock bool

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
	SubjectDigest  string
	TreeDigest     string
	ConfigDigest   string
	LayerDigest    string
	ManifestDigest string
	LockDigest     string
	Format         string
	FileCount      int64
	TotalBytes     int64
	LayerBytes     int64
	LayoutPath     string
	Tag            string

	// Lock is the resolution this build used, whether loaded or generated.
	Lock *bundle.Lock
	// LockBytes is its canonical encoding, for a caller that wants to
	// persist it.
	LockBytes []byte
}

// Build packages one or more sources into an OCI image layout.
//
// Sources are resolved into private snapshots before anything is encoded, so
// the artifact describes one frozen moment rather than directories that may
// be changing underneath it. Blobs are written before the manifest, and the
// tag is assigned last, so a name never points at content that is not
// completely present.
func (c *Client) Build(ctx context.Context, req BuildRequest) (_ *BuildResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if req.LayoutPath == "" {
		return nil, fault.New(fault.CodeInvalidInput, "build", "a destination layout path is required")
	}

	spec, baseDir, err := c.loadSpec(req)
	if err != nil {
		return nil, err
	}

	lock, haveLock, err := c.loadLock(req, baseDir)
	if err != nil {
		return nil, err
	}

	limits := c.effectiveLimits(req.Limits)

	resolved, err := c.resolveSpec(ctx, spec, baseDir, lock, limits.Limits)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resolved.close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	records := resolved.composed.Records
	if len(records) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, "build",
			"the manifest selected no files; a bundle must contain at least one")
	}

	treeDigest, err := canonical.TreeDigest(records)
	if err != nil {
		return nil, err
	}

	// A locked build compares before it packages, so a stale lock costs a
	// resolution rather than a published artifact.
	if haveLock {
		if lockErr := resolved.verifyAgainstLock(lock, treeDigest); lockErr != nil {
			return nil, lockErr
		}
	} else {
		lock, err = resolved.buildLock(treeDigest)
		if err != nil {
			return nil, err
		}
	}

	lockDigest, lockBytes, err := canonical.JSONDigest(lock)
	if err != nil {
		return nil, err
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
	subject, err := canonical.Package(ctx, records, resolved.composed, &layerBuffer)
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
		"sources", len(spec.Spec.Sources),
		"files", subject.Config.FileCount,
		"layout", layout.Path())

	return &BuildResult{
		SubjectDigest:  subject.ManifestDigest.String(),
		TreeDigest:     subject.TreeDigest.String(),
		ConfigDigest:   subject.ConfigDigest.String(),
		LayerDigest:    subject.LayerDigest.String(),
		ManifestDigest: resolved.manifestDigest.String(),
		LockDigest:     lockDigest.String(),
		Format:         subject.Config.Format.String(),
		FileCount:      subject.Config.FileCount,
		TotalBytes:     subject.Config.TotalSize,
		LayerBytes:     subject.LayerSize,
		LayoutPath:     layout.Path(),
		Tag:            req.Tag,
		Lock:           lock,
		LockBytes:      lockBytes,
	}, nil
}

// LockRequest describes a lock to produce.
//
// It has no destination and no signing mode: locking resolves sources and
// records what they resolved to, and mixing publication into that would make
// "what does this manifest mean" a question you cannot answer without a
// registry.
type LockRequest struct {
	SpecPath string
	Spec     *bundle.Spec
	SpecDir  string

	// OutputPath is where to write the lock. Empty defaults to
	// devproof.lock.json beside the manifest.
	OutputPath string
	// Check verifies an existing lock without writing anything.
	Check bool
	// ExistingLock is compared against when Check is set. Empty loads from
	// OutputPath.
	ExistingLock *bundle.Lock

	Limits Limits
}

// LockResult describes a lock.
type LockResult struct {
	Lock           *bundle.Lock
	LockBytes      []byte
	LockDigest     string
	ManifestDigest string
	TreeDigest     string
	SourceCount    int
	FileCount      int
	OutputPath     string
	// Matched reports whether an existing lock already described this
	// resolution. Under Check, a false value is a failure.
	Matched bool
}

// Lock resolves a manifest and records the resolution.
//
// Writing is atomic and all-or-nothing: a manifest whose sources partly fail
// produces no lock at all, because a lock describing some of a manifest is
// worse than none (DP-011).
func (c *Client) Lock(ctx context.Context, req LockRequest) (_ *LockResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}

	spec, baseDir, err := c.loadSpec(BuildRequest{
		SpecPath: req.SpecPath, Spec: req.Spec, SpecDir: req.SpecDir,
	})
	if err != nil {
		return nil, err
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(baseDir, DefaultLockName)
	}

	limits := c.effectiveLimits(req.Limits)

	// Resolved without a lock: locking is how a lock comes into existence,
	// so enforcing one here would be circular.
	resolved, err := c.resolveSpec(ctx, spec, baseDir, nil, limits.Limits)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resolved.close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()

	treeDigest, err := canonical.TreeDigest(resolved.composed.Records)
	if err != nil {
		return nil, err
	}
	lock, err := resolved.buildLock(treeDigest)
	if err != nil {
		return nil, err
	}
	lockDigest, lockBytes, err := canonical.JSONDigest(lock)
	if err != nil {
		return nil, err
	}

	result := &LockResult{
		Lock:           lock,
		LockBytes:      lockBytes,
		LockDigest:     lockDigest.String(),
		ManifestDigest: resolved.manifestDigest.String(),
		TreeDigest:     treeDigest.String(),
		SourceCount:    len(lock.Sources),
		FileCount:      len(lock.Files),
		OutputPath:     outputPath,
	}

	if req.Check {
		existing := req.ExistingLock
		if existing == nil {
			loaded, loadErr := loadLockFile(outputPath)
			if loadErr != nil {
				return nil, loadErr
			}
			existing = loaded
		}
		_, existingBytes, encodeErr := canonical.JSONDigest(existing)
		if encodeErr != nil {
			return nil, encodeErr
		}
		result.Matched = string(existingBytes) == string(lockBytes)
		if !result.Matched {
			return result, fault.New(fault.CodeStaleLock, "lock",
				"the existing lock does not match the current resolution")
		}
		return result, nil
	}

	if err := writeFileAtomic(outputPath, lockBytes); err != nil {
		return nil, err
	}
	c.logger.InfoContext(ctx, "wrote lock",
		"path", outputPath, "digest", lockDigest.String(), "sources", len(lock.Sources))
	return result, nil
}

// DefaultLockName is the lock file written beside a manifest.
const DefaultLockName = "devproof.lock.json"

// loadSpec resolves the manifest a request names, or synthesizes one for a
// direct source.
func (c *Client) loadSpec(req BuildRequest) (*bundle.Spec, string, error) {
	supplied := 0
	for _, present := range []bool{req.SpecPath != "", req.Spec != nil, req.SourcePath != ""} {
		if present {
			supplied++
		}
	}
	switch supplied {
	case 0:
		return nil, "", fault.New(fault.CodeInvalidInput, "build",
			"supply a manifest path, a manifest, or a direct source path")
	case 1:
	default:
		return nil, "", fault.New(fault.CodeInvalidInput, "build",
			"a manifest and a direct source path are mutually exclusive")
	}

	switch {
	case req.SourcePath != "":
		return sourcepath.DirectSpec(
			directSourceName, req.SourcePath, req.MountPath, req.Include, req.Exclude)

	case req.Spec != nil:
		if err := req.Spec.Validate(); err != nil {
			return nil, "", err
		}
		return req.Spec, req.SpecDir, nil

	default:
		data, err := os.ReadFile(req.SpecPath) //nolint:gosec // caller-supplied manifest path
		if err != nil {
			return nil, "", fault.Wrap(fault.CodeInvalidInput, "build", "reading manifest", err)
		}
		spec, err := bundle.ParseSpec(data)
		if err != nil {
			return nil, "", err
		}
		abs, err := filepath.Abs(req.SpecPath)
		if err != nil {
			return nil, "", fault.Wrap(fault.CodeInvalidInput, "build", "resolving manifest path", err)
		}
		return spec, filepath.Dir(abs), nil
	}
}

// directSourceName is the logical name a direct build's single source gets.
// It does not affect identity; it appears in diagnostics and in the lock.
const directSourceName = "source"

// loadLock resolves which lock a build should enforce.
//
// A lock sitting beside a manifest is enforced by default. That is the whole
// point of committing one: a build that ignored it unless asked would make
// reproducibility opt-in (DP-004).
func (c *Client) loadLock(req BuildRequest, baseDir string) (_ *bundle.Lock, found bool, _ error) {
	switch {
	case req.SkipLock && req.UpdateLock:
		return nil, false, fault.New(fault.CodeInvalidInput, "build",
			"skipping the lock and updating it are mutually exclusive")
	case req.SkipLock, req.UpdateLock:
		return nil, false, nil
	case req.Lock != nil:
		return req.Lock, true, req.Lock.Validate()
	case req.LockPath != "":
		lock, err := loadLockFile(req.LockPath)
		return lock, err == nil, err
	case req.SourcePath != "":
		// A direct build has no manifest directory to look beside.
		return nil, false, nil
	}

	beside := filepath.Join(baseDir, DefaultLockName)
	if _, statErr := os.Lstat(beside); statErr != nil {
		// An absent lock is the ordinary case for a manifest that has not
		// been locked yet, not a failure.
		return nil, false, nil
	}
	lock, err := loadLockFile(beside)
	return lock, err == nil, err
}

func loadLockFile(path string) (*bundle.Lock, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-supplied lock path
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, "build", "reading lock", err)
	}
	return bundle.ParseLock(data)
}

// writeFileAtomic writes content via a temporary file and a rename, so a
// reader never sees a half-written lock.
func writeFileAtomic(path string, content []byte) (retErr error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".devproof-lock-*")
	if err != nil {
		return fault.Wrap(fault.CodeInternal, "lock", "creating a temporary lock file", err)
	}
	defer func() {
		if retErr != nil {
			_ = os.Remove(temp.Name())
		}
	}()

	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return fault.Wrap(fault.CodeInternal, "lock", "writing lock", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fault.Wrap(fault.CodeInternal, "lock", "syncing lock", err)
	}
	if err := temp.Close(); err != nil {
		return fault.Wrap(fault.CodeInternal, "lock", "closing lock", err)
	}
	// Created private by CreateTemp, then relaxed: a lock is committed to a
	// repository and read by everyone, but it must not be world-readable
	// while it is still partially written.
	if err := os.Chmod(temp.Name(), 0o644); err != nil {
		return fault.Wrap(fault.CodeInternal, "lock", "setting lock permissions", err)
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return fault.Wrap(fault.CodeInternal, "lock", "publishing lock", err)
	}
	return nil
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
