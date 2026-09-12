package devproof

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/evidence"
	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/version"
)

const attestOp = "attest"

// buildTypeV1 identifies how DevProof builds, in SLSA terms.
const buildTypeV1 = "https://devproof.thingz.io/buildtype/v1"

// buildPredicate assembles provenance from a completed resolution.
//
// Everything here is derived from what was actually resolved, never from what
// a manifest asked for. A predicate that echoed the request would attest to
// intent rather than to outcome, which is the one thing provenance must not
// do.
func buildPredicate(res *resolution, subject *canonical.Subject, lock *bundle.Lock) evidence.Predicate {
	sources := make([]evidence.SourceProvenance, 0, len(lock.Sources))
	dependencies := make([]evidence.ResourceDescriptor, 0, len(lock.Sources))

	for i := range lock.Sources {
		locked := &lock.Sources[i]
		sources = append(sources, evidence.SourceProvenance{
			Name:       locked.Name,
			Type:       locked.Type,
			Resolver:   locked.Resolver,
			Requested:  locked.Requested,
			Resolved:   locked.Resolved,
			TreeDigest: locked.TreeDigest,
			MountPath:  locked.MountPath,
		})

		// The same facts in SLSA's vocabulary, so a consumer that reads only
		// resolvedDependencies still sees every input.
		dependency := evidence.ResourceDescriptor{
			Name:   locked.Name,
			Digest: map[string]string{"sha256": trimAlgorithm(locked.TreeDigest)},
		}
		if url, ok := locked.Requested["url"].(string); ok {
			dependency.URI = url
		}
		dependencies = append(dependencies, dependency)
	}

	return evidence.Predicate{
		BuildDefinition: evidence.BuildDefinition{
			BuildType: buildTypeV1,
			ExternalParameters: map[string]any{
				"manifestDigest": res.manifestDigest.String(),
			},
			ResolvedDependencies: dependencies,
		},
		RunDetails: evidence.RunDetails{
			Builder: evidence.Builder{
				ID:      "https://devproof.thingz.io/builder/v1",
				Version: map[string]string{"devproof": version.Version()},
			},
		},
		DevProof: evidence.DevProofProvenance{
			FormatVersion:  subject.Config.Format.String(),
			ManifestDigest: res.manifestDigest.String(),
			LockDigest:     lockDigestOf(lock),
			TreeDigest:     subject.TreeDigest.String(),
			Sources:        sources,
			ToolVersion:    version.Version(),
		},
	}
}

func trimAlgorithm(digest string) string {
	if len(digest) > len("sha256:") && digest[:len("sha256:")] == "sha256:" {
		return digest[len("sha256:"):]
	}
	return digest
}

func lockDigestOf(lock *bundle.Lock) string {
	digest, _, err := canonical.JSONDigest(lock)
	if err != nil {
		return ""
	}
	return digest.String()
}

// attachEvidence signs provenance and attaches it to a published subject.
//
// The statement is built here and handed to the attester as bytes to sign. An
// attester supplies identity and nothing else, so a registered one cannot
// attest to something other than what was built.
func (c *Client) attachEvidence(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	subject *canonical.Subject,
	predicate evidence.Predicate,
	name string,
) (*EvidenceResult, error) {

	referrers, ok := transport.(artifact.ReferrerTransport)
	if !ok {
		return nil, fault.New(fault.CodeUnsupportedSource, attestOp,
			"this destination cannot store evidence")
	}
	if c.attester == nil {
		return nil, fault.New(fault.CodeInvalidInput, attestOp,
			"signing was requested but no attester is configured")
	}

	statement := evidence.NewStatement(subject.ManifestDigest, name, predicate)

	// The exact payload bytes are what gets signed and what the envelope
	// carries. Re-serializing between those two steps is how a signature
	// ends up covering something other than what is stored.
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, attestOp, "encoding the statement", err)
	}

	blob, err := c.signEvidence(ctx, subject, statement, payload)
	if err != nil {
		return nil, err
	}

	descriptor := artifact.DescriptorFor(evidence.MediaTypeBundleV1, blob)
	manifestDescriptor, storage, err := referrers.Attach(
		ctx, ref, subject.Descriptor(), descriptor, bytes.NewReader(blob),
		evidence.MediaTypeEvidenceV1)
	if err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "attached evidence",
		"subject", subject.ManifestDigest.String(),
		"evidence", manifestDescriptor.Digest,
		"attester", c.attester.Name(),
		"storage", string(storage))

	return &EvidenceResult{
		Digest:        manifestDescriptor.Digest,
		BlobDigest:    descriptor.Digest,
		PredicateType: statement.PredicateType,
		Attester:      c.attester.Name(),
		Storage:       string(storage),
		SubjectDigest: subject.ManifestDigest.String(),
	}, nil
}

// signEvidence produces the stored evidence blob.
//
// A Sigstore attester returns a complete bundle — certificate, log entry,
// timestamps — and that whole object is stored. Any other attester returns
// signatures, which are wrapped in a bare DSSE envelope.
func (c *Client) signEvidence(
	ctx context.Context,
	subject *canonical.Subject,
	statement *evidence.Statement,
	payload []byte,
) ([]byte, error) {

	request := evidence.AttestRequest{
		Subject:     subject.ManifestDigest,
		Statement:   statement,
		PayloadType: evidence.PayloadType,
		Payload:     payload,
	}

	if sigstore, ok := c.attester.(*evidence.SigstoreAttester); ok {
		signed, err := sigstore.AttestBundle(ctx, request)
		if err != nil {
			return nil, err
		}
		return evidence.MarshalBundle(signed)
	}

	signatures, err := c.attester.Attest(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(signatures) == 0 {
		return nil, fault.New(fault.CodeInternal, attestOp,
			fmt.Sprintf("attester %q produced no signatures", c.attester.Name()))
	}

	envelope := evidence.Envelope{
		PayloadType: evidence.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  signatures,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, attestOp, "encoding the envelope", err)
	}
	return encoded, nil
}

// EvidenceResult describes one attached evidence object.
type EvidenceResult struct {
	// Digest identifies the referrer manifest.
	Digest string
	// BlobDigest identifies the evidence blob itself.
	BlobDigest string
	// PredicateType is what the statement asserts.
	PredicateType string
	// Attester names the implementation that signed.
	Attester string
	// Storage is "referrers" or "tag-fallback". The fallback replaces rather
	// than accumulates, so a caller needs to know which applied (DP-028).
	Storage string
	// SubjectDigest is what the evidence is bound to.
	SubjectDigest string
}

// discoverEvidence fetches and verifies evidence for a subject.
//
// Verification happens here, before anything reaches policy. Candidates that
// fail are reported separately rather than discarded, so that "nothing
// satisfied the policy" and "somebody attached junk" stay distinguishable —
// and so that a repository being an open attachment surface cannot make a
// valid subject unverifiable (DP-014).
func (c *Client) discoverEvidence(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	subject *canonical.Subject,
	limits bundle.Limits,
) (verified []policyEvidence, rejected []policyRejection, storage string, err error) {

	referrers, ok := transport.(artifact.ReferrerTransport)
	if !ok {
		return nil, nil, "", nil
	}

	descriptors, mode, err := referrers.Referrers(
		ctx, ref, subject.Descriptor(), evidence.MediaTypeEvidenceV1)
	if err != nil {
		return nil, nil, "", err
	}
	storage = string(mode)

	if int64(len(descriptors)) > limits.MaxReferrers {
		return nil, nil, storage, fault.New(fault.CodeLimitExceeded, attestOp,
			fmt.Sprintf("subject has %d referrers, the limit is %d",
				len(descriptors), limits.MaxReferrers))
	}

	for _, descriptor := range descriptors {
		item, reason := c.verifyOneEvidence(ctx, transport, ref, subject, descriptor, limits)
		if reason != "" {
			rejected = append(rejected, policyRejection{
				digest: descriptor.Digest,
				reason: reason,
				// It claimed the DevProof evidence type, which is what
				// discovery filtered on, so this is junk pretending to be
				// the thing the policy asked for.
				matchedRequiredType: true,
			})
			continue
		}
		item.viaTagFallback = mode == artifact.StorageTagFallback
		verified = append(verified, item)
	}
	return verified, rejected, storage, nil
}

// policyEvidence is verified evidence, before it is handed to policy.
type policyEvidence struct {
	digest         string
	statement      *evidence.Statement
	identities     []evidence.Identity
	logVerified    bool
	integratedTime *time.Time
	viaTagFallback bool
}

type policyRejection struct {
	digest              string
	reason              string
	matchedRequiredType bool
}

// verifyOneEvidence fetches and verifies a single candidate.
//
// It returns a reason rather than an error, because one bad candidate must
// not fail the operation: a repository is an open attachment surface, and
// anybody with write access can attach anything.
func (c *Client) verifyOneEvidence(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	subject *canonical.Subject,
	descriptor artifact.Descriptor,
	limits bundle.Limits,
) (policyEvidence, string) {

	manifestBytes, err := fetchBlob(ctx, transport, ref, descriptor, limits.MaxManifestBytes)
	if err != nil {
		return policyEvidence{}, "the referrer manifest could not be fetched: " + err.Error()
	}

	var manifest artifact.ReferrerManifest
	if decodeErr := json.Unmarshal(manifestBytes, &manifest); decodeErr != nil {
		return policyEvidence{}, "the referrer manifest is malformed"
	}
	if validateErr := manifest.Validate(); validateErr != nil {
		return policyEvidence{}, "the referrer manifest is invalid: " + validateErr.Error()
	}
	if manifest.Subject.Digest != subject.ManifestDigest.String() {
		return policyEvidence{}, "the referrer names a different subject"
	}

	blobDescriptor, err := manifest.EvidenceBlob()
	if err != nil {
		return policyEvidence{}, err.Error()
	}
	blob, err := fetchBlob(ctx, transport, ref, blobDescriptor, limits.MaxEvidenceBytes)
	if err != nil {
		return policyEvidence{}, "the evidence blob could not be fetched: " + err.Error()
	}

	envelope, payload, reason := decodeEvidence(blob)
	if reason != "" {
		return policyEvidence{}, reason
	}

	if c.verifier == nil {
		return policyEvidence{}, "no verifier is configured, so this evidence could not be checked"
	}
	result, err := c.verifier.Verify(ctx, evidence.VerifyRequest{
		Envelope:   envelope,
		Payload:    payload,
		BundleJSON: blob,
		TrustRoots: c.trustRoots,
	})
	if err != nil {
		return policyEvidence{}, "signature verification failed: " + err.Error()
	}
	if len(result.Identities) == 0 {
		return policyEvidence{}, "verification established no signing identity"
	}

	// The statement is parsed only now, after its signatures verified.
	statement, err := envelope.Statement()
	if err != nil {
		return policyEvidence{}, "the signed statement is invalid: " + err.Error()
	}
	// Signed by somebody real, but about something else. A signature proves
	// authorship, never aboutness.
	if !statement.BindsTo(subject.ManifestDigest) {
		return policyEvidence{}, "the signed statement is bound to a different subject"
	}

	item := policyEvidence{
		digest:      descriptor.Digest,
		statement:   statement,
		identities:  result.Identities,
		logVerified: result.TransparencyLogVerified,
	}
	if result.IntegratedTime != nil {
		at := time.Unix(*result.IntegratedTime, 0).UTC()
		item.integratedTime = &at
	}
	return item, ""
}

// decodeEvidence extracts the DSSE envelope from a stored blob.
//
// A blob is either a Sigstore bundle wrapping an envelope, or a bare
// envelope. Both are read the same way from this point on, because what gets
// verified is the envelope and what gets stored is whatever the attester
// produced.
func decodeEvidence(blob []byte) (*evidence.Envelope, []byte, string) {
	var wrapper struct {
		DSSEEnvelope *struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				Sig   string `json:"sig"`
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"dsseEnvelope"`
	}

	if err := json.Unmarshal(blob, &wrapper); err == nil && wrapper.DSSEEnvelope != nil {
		envelope := &evidence.Envelope{
			PayloadType: wrapper.DSSEEnvelope.PayloadType,
			Payload:     wrapper.DSSEEnvelope.Payload,
		}
		for _, signature := range wrapper.DSSEEnvelope.Signatures {
			envelope.Signatures = append(envelope.Signatures,
				evidence.Signature{Sig: signature.Sig, KeyID: signature.KeyID})
		}
		payload, decodeErr := envelope.DecodePayload()
		if decodeErr != nil {
			return nil, nil, "the evidence payload could not be decoded"
		}
		return envelope, payload, ""
	}

	var envelope evidence.Envelope
	if err := json.Unmarshal(blob, &envelope); err != nil {
		return nil, nil, "the evidence is neither a Sigstore bundle nor a DSSE envelope"
	}
	if validateErr := envelope.Validate(); validateErr != nil {
		return nil, nil, "the evidence envelope is invalid: " + validateErr.Error()
	}
	payload, err := envelope.DecodePayload()
	if err != nil {
		return nil, nil, "the evidence payload could not be decoded"
	}
	return &envelope, payload, ""
}
