package devproof

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
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

	// Destination is where to publish: "oci-layout://./artifact" for a local
	// layout, or "oci://registry.example.com/team/config" for a registry.
	// A bare reference is treated as a registry reference.
	Destination string
	// Tag optionally names the subject at the destination. It is assigned
	// last, after the published manifest has been read back and compared.
	Tag string

	// Attest signs provenance and attaches it to the published subject.
	// Requires an attester; see WithSigstore or WithAttester.
	Attest bool

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
	// Reference is the canonical digest reference of what was published.
	// A result always names its subject by digest, never by the tag it may
	// also carry (DP-007).
	Reference string
	Tag       string

	// Lock is the resolution this build used, whether loaded or generated.
	Lock *bundle.Lock
	// LockBytes is its canonical encoding, for a caller that wants to
	// persist it.
	LockBytes []byte
	// Evidence describes the provenance attached, when signing was asked
	// for. Attaching it never changed the subject digest above (DP-003).
	Evidence *EvidenceResult
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
	if req.Destination == "" {
		return nil, fault.New(fault.CodeInvalidInput, "build", "a destination is required")
	}
	destination, err := artifact.ParseReference(req.Destination)
	if err != nil {
		return nil, err
	}
	if destination.IsDigest() {
		return nil, fault.New(fault.CodeInvalidInput, "build",
			"a build destination names a repository, not a digest")
	}
	if req.Tag != "" && destination.Tag != "" && req.Tag != destination.Tag {
		return nil, fault.New(fault.CodeInvalidInput, "build",
			"the destination and the tag option disagree about the tag to assign")
	}
	tag := req.Tag
	if tag == "" {
		tag = destination.Tag
	}
	transport, err := c.transportFor(destination)
	if err != nil {
		return nil, err
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

	// The layer is buffered because content-addressed storage cannot name a
	// blob until it knows its digest, and the digest is only known once the
	// last byte has been written.
	var layerBuffer sizedBuffer
	subject, err := canonical.Package(ctx, records, resolved.composed, &layerBuffer)
	if err != nil {
		return nil, err
	}
	if subject.LayerSize > limits.Limits.MaxCompressedBytes {
		return nil, fault.New(fault.CodeLimitExceeded, "build",
			fmt.Sprintf("layer is %d bytes, the limit is %d",
				subject.LayerSize, limits.Limits.MaxCompressedBytes))
	}

	published, err := c.publish(ctx, transport, destination, subject, layerBuffer.Bytes(), tag)
	if err != nil {
		return nil, err
	}

	// Evidence is attached after the subject is published and verified.
	// Signing first would mean attesting to something that might never land;
	// attaching after is also what makes the failure mode benign — a
	// published subject with no evidence is a subject a policy will refuse,
	// not a subject nobody can find.
	var attached *EvidenceResult
	if req.Attest {
		attached, err = c.attachEvidence(ctx, transport, destination, subject,
			buildPredicate(resolved, subject, lock), spec.Metadata.Name)
		if err != nil {
			return nil, err
		}
	}

	c.logger.InfoContext(ctx, "built bundle",
		"subject", subject.ManifestDigest.String(),
		"sources", len(spec.Spec.Sources),
		"files", subject.Config.FileCount,
		"destination", published.String())

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
		Reference:      published.String(),
		Tag:            tag,
		Lock:           lock,
		LockBytes:      lockBytes,
		Evidence:       attached,
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
	// Reference is the subject to verify: a registry or layout reference,
	// by tag or by digest. A tag is resolved once and the resolved digest is
	// what every later step uses.
	Reference string
	// RequireDigest rejects a tag before any content is fetched.
	RequireDigest bool

	// Policy is the verification policy to apply. Without one, trust reports
	// not-evaluated rather than pass.
	Policy *policy.Document
	// PolicyPath loads a policy from a file. Mutually exclusive with Policy.
	PolicyPath string

	// Limits tightens the client's bounds for this operation.
	Limits Limits
}

// Verify checks a subject's integrity and, when a policy is supplied, its
// trust.
//
// Integrity is always evaluated and has no flag that disables it. Trust is
// evaluated only when a policy is given, and its absence reports
// not-evaluated rather than pass — a consumer whose trust configuration never
// took effect has no other way to notice (DP-010).
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*policy.Report, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}

	doc, havePolicy, err := c.loadPolicy(req)
	if err != nil {
		return nil, err
	}
	if havePolicy && doc.Spec.Subject.RequireDigestReference {
		req.RequireDigest = true
	}

	subject, pinned, err := c.loadSubject(ctx, req)
	if err != nil {
		return nil, err
	}

	if !havePolicy {
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

	return c.evaluatePolicy(ctx, doc, subject, pinned, req)
}

// loadPolicy resolves which policy a request supplies.
//
// found distinguishes "no policy was asked for" — which is legitimate and
// reports trust as not-evaluated — from "a policy was asked for and could not
// be loaded", which is a failure.
func (c *Client) loadPolicy(req VerifyRequest) (_ *policy.Document, found bool, _ error) {
	switch {
	case req.Policy != nil && req.PolicyPath != "":
		return nil, false, fault.New(fault.CodeInvalidInput, "verify",
			"a policy and a policy path are mutually exclusive")
	case req.Policy != nil:
		return req.Policy, true, req.Policy.Validate()
	case req.PolicyPath != "":
		data, err := os.ReadFile(req.PolicyPath) //nolint:gosec // caller-supplied policy path
		if err != nil {
			return nil, false, fault.Wrap(fault.CodeInvalidInput, "verify", "reading the policy", err)
		}
		doc, err := policy.ParseDocument(data)
		return doc, err == nil, err
	default:
		return nil, false, nil
	}
}

// evaluatePolicy discovers evidence, verifies it, and applies the policy.
func (c *Client) evaluatePolicy(
	ctx context.Context,
	doc *policy.Document,
	subject *canonical.Subject,
	pinned artifact.Reference,
	req VerifyRequest,
) (*policy.Report, error) {

	transport, err := c.transportFor(pinned)
	if err != nil {
		return nil, err
	}

	// Policy limits intersect with the client's and the request's; a policy
	// may tighten a bound and never relax one (DP-021).
	limits := c.effectiveLimitsWithPolicy(req.Limits, doc.Spec.Limits)

	verified, rejected, storage, err := c.discoverEvidence(ctx, transport, pinned, subject, limits.Limits)
	if err != nil {
		return nil, err
	}

	// One time for every time-dependent rule, captured here and recorded in
	// the result, so two rules in one evaluation cannot disagree about now.
	evaluatedAt := c.now()

	input := policy.Input{
		SubjectDigest:           subject.ManifestDigest.String(),
		Format:                  subject.Config.Format,
		SuppliedDigestReference: referenceWasDigest(req.Reference),
		FileCount:               subject.Config.FileCount,
		TotalBytes:              subject.Config.TotalSize,
		EvaluatedAt:             evaluatedAt,
	}
	for _, item := range verified {
		input.Evidence = append(input.Evidence, policy.VerifiedEvidence{
			Digest:                  item.digest,
			Statement:               item.statement,
			Identities:              item.identities,
			TransparencyLogVerified: item.logVerified,
			IntegratedTime:          item.integratedTime,
			ViaTagFallback:          item.viaTagFallback,
		})
	}
	for _, item := range rejected {
		input.Rejected = append(input.Rejected, policy.RejectedEvidence{
			Digest:              item.digest,
			Reason:              item.reason,
			MatchedRequiredType: item.matchedRequiredType,
		})
	}

	report := policy.Evaluate(doc, input)
	report.TreeDigest = subject.TreeDigest.String()
	report.PolicyName = doc.Metadata.Name
	report.EvaluatedAt = evaluatedAt.UTC().Format(time.RFC3339)
	report.EvidenceStorage = storage
	if digest, _, err := canonical.JSONDigest(doc); err == nil {
		report.PolicyDigest = digest.String()
	}
	for _, item := range rejected {
		report.RejectedEvidence = append(report.RejectedEvidence, item.digest+": "+item.reason)
	}
	return report, nil
}

// referenceWasDigest reports whether the caller named a digest.
func referenceWasDigest(raw string) bool {
	ref, err := artifact.ParseReference(raw)
	return err == nil && ref.IsDigest()
}

// ExpandRequest describes an expansion.
type ExpandRequest struct {
	Reference string
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

	subject, pinned, err := c.loadSubject(ctx, VerifyRequest{
		Reference:     req.Reference,
		RequireDigest: req.RequireDigest,
		Limits:        req.Limits,
	})
	if err != nil {
		return nil, err
	}

	transport, err := c.transportFor(pinned)
	if err != nil {
		return nil, err
	}

	// The layer streams rather than being buffered: it is the one blob that
	// can be far larger than memory, and the extractor verifies it entry by
	// entry as it arrives.
	layer, err := transport.Fetch(ctx, pinned, subject.LayerDescriptor())
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
// The returned reference is pinned to a digest, so every caller works from
// content rather than from a name that could change underneath it.
func (c *Client) loadSubject(ctx context.Context, req VerifyRequest) (*canonical.Subject, artifact.Reference, error) {
	if req.Reference == "" {
		return nil, artifact.Reference{}, fault.New(fault.CodeInvalidInput, "verify",
			"a reference is required")
	}

	ref, err := artifact.ParseReference(req.Reference)
	if err != nil {
		return nil, artifact.Reference{}, err
	}
	if req.RequireDigest && !ref.IsDigest() {
		// Refused before anything is fetched, so a policy that demands a
		// digest never spends a request on a tag.
		return nil, ref, fault.New(fault.CodeInvalidInput, "verify",
			"a digest reference is required, but a tag was supplied")
	}
	if ref.Target() == "" {
		return nil, ref, fault.New(fault.CodeInvalidInput, "verify",
			"reference names neither a tag nor a digest")
	}

	transport, err := c.transportFor(ref)
	if err != nil {
		return nil, ref, err
	}

	limits := c.effectiveLimits(req.Limits)
	return c.fetchSubject(ctx, transport, ref, limits.Limits)
}

// sizedBuffer accumulates the encoded layer.
type sizedBuffer struct{ b []byte }

func (s *sizedBuffer) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *sizedBuffer) Bytes() []byte { return s.b }

// CopyRequest describes a subject to copy between locations.
type CopyRequest struct {
	// Source is the subject to copy, by tag or by digest.
	Source string
	// Destination is where to write it.
	Destination string
	// Tag optionally names the copy at the destination. It is assigned last.
	Tag string
	// RequireDigest rejects a source tag before anything is fetched.
	RequireDigest bool
	// Limits tightens the client's bounds for this operation.
	Limits Limits
}

// CopyResult describes a completed copy.
type CopyResult struct {
	SubjectDigest string
	Source        string
	Destination   string
	Tag           string
}

// Copy moves a subject between registries, layouts, or repositories.
//
// The subject's integrity is verified at the source and the copy is published
// under the same rules as a build, so a copy cannot launder a broken artifact
// into a destination that looks authoritative.
//
// The subject digest is unchanged by definition: identity is a function of
// content and format version, and a repository name is neither (DP-002).
// Evidence is not copied here; that arrives with the referrer work in phase 4,
// and until then a copy carries the payload only.
func (c *Client) Copy(ctx context.Context, req CopyRequest) (_ *CopyResult, retErr error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if req.Destination == "" {
		return nil, fault.New(fault.CodeInvalidInput, "copy", "a destination is required")
	}

	destination, err := artifact.ParseReference(req.Destination)
	if err != nil {
		return nil, err
	}
	if destination.IsDigest() {
		return nil, fault.New(fault.CodeInvalidInput, "copy",
			"a copy destination names a repository, not a digest")
	}
	tag := req.Tag
	if tag == "" {
		tag = destination.Tag
	}

	destinationTransport, err := c.transportFor(destination)
	if err != nil {
		return nil, err
	}

	subject, pinned, err := c.loadSubject(ctx, VerifyRequest{
		Reference:     req.Source,
		RequireDigest: req.RequireDigest,
		Limits:        req.Limits,
	})
	if err != nil {
		return nil, err
	}

	sourceTransport, err := c.transportFor(pinned)
	if err != nil {
		return nil, err
	}

	limits := c.effectiveLimits(req.Limits)
	layer, err := fetchBlob(ctx, sourceTransport, pinned, subject.LayerDescriptor(),
		limits.Limits.MaxCompressedBytes)
	if err != nil {
		return nil, err
	}

	published, err := c.publish(ctx, destinationTransport, destination, subject, layer, tag)
	if err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "copied bundle",
		"subject", subject.ManifestDigest.String(),
		"from", pinned.String(), "to", published.String())

	return &CopyResult{
		SubjectDigest: subject.ManifestDigest.String(),
		Source:        pinned.String(),
		Destination:   published.String(),
		Tag:           tag,
	}, nil
}
