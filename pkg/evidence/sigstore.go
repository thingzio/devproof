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

package evidence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/thingzio/devproof/pkg/fault"
)

const sigstoreOp = "evidence.sigstore"

// Public Sigstore service endpoints, used when nothing else is configured.
const (
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
	DefaultRekorURL  = "https://rekor.sigstore.dev"
)

// SigstoreOptions configures keyless signing and verification.
type SigstoreOptions struct {
	// FulcioURL issues the short-lived signing certificate. Empty uses the
	// public instance.
	FulcioURL string
	// RekorURL records the signature in a transparency log. Empty uses the
	// public instance.
	RekorURL string
	// IDToken is an OIDC identity token. Empty uses ambient detection.
	IDToken string
	// IDTokenProvider supplies a token on demand. Takes precedence over
	// IDToken, so a long-running process can refresh rather than hold one.
	IDTokenProvider func(ctx context.Context) (string, error)
	// TrustedRootJSON is a caller-supplied Sigstore trusted root. Empty
	// fetches and caches the public root over TUF.
	//
	// Supplying one is what makes offline verification possible: no network,
	// and trust material that came from somewhere the caller chose.
	TrustedRootJSON []byte
	// Timeout bounds a single network call to Fulcio or Rekor.
	Timeout time.Duration
}

const defaultSigstoreTimeout = 30 * time.Second

// SigstoreAttester signs keylessly against Fulcio and Rekor.
//
// An ephemeral key is generated per signature, certified by Fulcio against an
// OIDC identity, used once, and discarded. Nothing durable is held, which is
// the point: there is no signing key to protect, rotate, or leak, and the
// identity in the certificate is the thing policy matches on.
type SigstoreAttester struct {
	opts SigstoreOptions
}

var _ Attester = (*SigstoreAttester)(nil)

// NewSigstoreAttester returns a keyless attester.
func NewSigstoreAttester(opts SigstoreOptions) *SigstoreAttester {
	if opts.FulcioURL == "" {
		opts.FulcioURL = DefaultFulcioURL
	}
	if opts.RekorURL == "" {
		opts.RekorURL = DefaultRekorURL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultSigstoreTimeout
	}
	return &SigstoreAttester{opts: opts}
}

// Name identifies the attester in evidence and in verification reports.
func (a *SigstoreAttester) Name() string { return "devproof.thingz.io/sigstore/v1" }

// Attest signs the payload and returns the signature plus its certificate.
//
// The returned signature carries the Fulcio certificate, so a verifier can
// establish the OIDC identity without another round trip. The full Sigstore
// bundle, including the transparency-log entry, is what gets stored; see
// [SigstoreAttester.AttestBundle].
func (a *SigstoreAttester) Attest(ctx context.Context, req AttestRequest) ([]Signature, error) {
	signed, err := a.AttestBundle(ctx, req)
	if err != nil {
		return nil, err
	}

	envelope := signed.GetDsseEnvelope()
	if envelope == nil || len(envelope.GetSignatures()) == 0 {
		return nil, fault.New(fault.CodeInternal, sigstoreOp,
			"Sigstore returned a bundle with no DSSE signature")
	}

	certificate := ""
	if material := signed.GetVerificationMaterial(); material != nil {
		if cert := material.GetCertificate(); cert != nil {
			certificate = base64.StdEncoding.EncodeToString(cert.GetRawBytes())
		}
	}

	out := make([]Signature, 0, len(envelope.GetSignatures()))
	for _, signature := range envelope.GetSignatures() {
		out = append(out, Signature{
			Sig:         base64.StdEncoding.EncodeToString(signature.GetSig()),
			Certificate: certificate,
		})
	}
	return out, nil
}

// AttestBundle signs and returns the complete Sigstore bundle.
//
// This is what DevProof stores as evidence: it carries the certificate, the
// transparency-log entry, and the signed timestamp, none of which fit in a
// bare DSSE signature.
func (a *SigstoreAttester) AttestBundle(ctx context.Context, req AttestRequest) (*protobundle.Bundle, error) {
	if len(req.Payload) == 0 {
		return nil, fault.New(fault.CodeInternal, sigstoreOp, "nothing to sign")
	}

	token, err := a.identityToken(ctx)
	if err != nil {
		return nil, err
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, sigstoreOp, "generating an ephemeral key", err)
	}

	content := &sign.DSSEData{Data: req.Payload, PayloadType: req.PayloadType}

	rekor := sign.NewRekor(&sign.RekorOptions{
		BaseURL: a.opts.RekorURL,
		Timeout: a.opts.Timeout,
		Retries: 2,
	})

	signed, err := sign.Bundle(content, keypair, sign.BundleOptions{
		Context: ctx,
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: a.opts.FulcioURL,
			Timeout: a.opts.Timeout,
			Retries: 2,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: token},
		// The transparency log is not optional. A keyless signature whose
		// certificate has already expired is only checkable against a log
		// entry proving it was valid at signing time, so omitting the log
		// would produce evidence that stops verifying within the hour.
		TransparencyLogs: []sign.Transparency{rekor},
	})
	if err != nil {
		return nil, classifySigstoreError(err, "signing")
	}
	return signed, nil
}

// identityToken obtains an OIDC token.
//
// Ambient detection covers the case this exists for: a CI runner that already
// has an identity. Nothing here prompts, opens a browser, or reads a
// credential file — an SDK that did any of those would be unusable from a
// server, and the CLI is where interaction belongs.
func (a *SigstoreAttester) identityToken(ctx context.Context) (string, error) {
	if a.opts.IDTokenProvider != nil {
		token, err := a.opts.IDTokenProvider(ctx)
		if err != nil {
			return "", fault.Wrap(fault.CodeAuthentication, sigstoreOp,
				"obtaining an OIDC identity token", err)
		}
		if token == "" {
			return "", fault.New(fault.CodeAuthentication, sigstoreOp,
				"the identity token provider returned an empty token")
		}
		return token, nil
	}
	if a.opts.IDToken != "" {
		return a.opts.IDToken, nil
	}
	// Recognized by convention across Sigstore tooling.
	if token := os.Getenv("SIGSTORE_ID_TOKEN"); token != "" {
		return token, nil
	}
	return "", fault.New(fault.CodeAuthentication, sigstoreOp,
		"keyless signing needs an OIDC identity token; supply one, configure a token "+
			"provider, or set SIGSTORE_ID_TOKEN")
}

// SigstoreVerifier verifies Sigstore bundles.
type SigstoreVerifier struct {
	opts SigstoreOptions

	once    sync.Once
	trusted root.TrustedMaterial
	initErr error
}

var _ Verifier = (*SigstoreVerifier)(nil)

// NewSigstoreVerifier returns a keyless verifier.
func NewSigstoreVerifier(opts SigstoreOptions) *SigstoreVerifier {
	return &SigstoreVerifier{opts: opts}
}

// Name identifies the verifier in verification reports. It matches the
// attester it verifies, so a report says which scheme accepted the evidence.
func (v *SigstoreVerifier) Name() string { return "devproof.thingz.io/sigstore/v1" }

// trustedMaterial resolves the trust root once.
//
// A caller-supplied root is used verbatim and no network call is made, which
// is what allows verification with only an exported layout and trust material
// on hand. Otherwise the public root is fetched over TUF and cached.
func (v *SigstoreVerifier) trustedMaterial() (root.TrustedMaterial, error) {
	v.once.Do(func() {
		if len(v.opts.TrustedRootJSON) > 0 {
			trusted, err := root.NewTrustedRootFromJSON(v.opts.TrustedRootJSON)
			if err != nil {
				v.initErr = fault.Wrap(fault.CodeInvalidInput, sigstoreOp,
					"reading the supplied Sigstore trusted root", err)
				return
			}
			v.trusted = trusted
			return
		}
		trusted, err := root.FetchTrustedRoot()
		if err != nil {
			v.initErr = fault.Wrap(fault.CodeTransport, sigstoreOp,
				"fetching the Sigstore trusted root; supply one explicitly to verify offline", err)
			return
		}
		v.trusted = trusted
	})
	return v.trusted, v.initErr
}

// Verify checks a Sigstore bundle and reports the identity it establishes.
func (v *SigstoreVerifier) Verify(_ context.Context, req VerifyRequest) (*VerificationResult, error) {
	if req.Envelope == nil {
		return nil, fault.New(fault.CodeInternal, sigstoreOp, "no envelope to verify")
	}
	if len(req.BundleJSON) == 0 {
		return nil, fault.New(fault.CodeEvidenceInvalid, sigstoreOp,
			"this evidence carries no Sigstore bundle; it cannot be verified keylessly")
	}

	trusted, err := v.trustedMaterial()
	if err != nil {
		return nil, err
	}

	var protoBundle protobundle.Bundle
	if decodeErr := protojson.Unmarshal(req.BundleJSON, &protoBundle); decodeErr != nil {
		return nil, fault.Wrap(fault.CodeEvidenceInvalid, sigstoreOp,
			"this evidence is not a valid Sigstore bundle", decodeErr)
	}
	signed, bundleErr := sigbundle.NewBundle(&protoBundle)
	if bundleErr != nil {
		return nil, fault.Wrap(fault.CodeEvidenceInvalid, sigstoreOp,
			"this evidence is not a valid Sigstore bundle", bundleErr)
	}

	verifier, err := verify.NewVerifier(trusted,
		// One observer timestamp: the transparency-log entry. It is what
		// establishes that the short-lived certificate was valid when it
		// signed, so without it a keyless signature stops verifying as soon
		// as the certificate expires.
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, sigstoreOp, "building the Sigstore verifier", err)
	}

	// Identity matching is DevProof policy's job, not the bundle verifier's.
	// Asking Sigstore to check identities here would apply rules the caller
	// never wrote, and would hide from the report which rule matched.
	result, err := verifier.Verify(signed, verify.NewPolicy(
		verify.WithoutArtifactUnsafe(),
		verify.WithoutIdentitiesUnsafe(),
	))
	if err != nil {
		return nil, classifySigstoreError(err, "verifying evidence")
	}

	out := &VerificationResult{}

	// The identity is read out of the certificate only after the bundle has
	// verified. Before that the certificate is just bytes the evidence
	// carried, and reading an identity from it would be reading an
	// attacker-supplied claim.
	identity, err := identityFromEntity(signed)
	if err != nil {
		return nil, err
	}
	if !identity.IsZero() {
		out.Identities = append(out.Identities, identity)
	}

	for _, timestamp := range result.VerifiedTimestamps {
		if strings.EqualFold(timestamp.Type, "Tlog") {
			out.TransparencyLogVerified = true
			seconds := timestamp.Timestamp.Unix()
			out.IntegratedTime = &seconds
			break
		}
	}

	if len(out.Identities) == 0 {
		// "Verified, by nobody" is the shape of a bug that lets
		// unauthenticated claims reach policy. Refuse rather than return it.
		return nil, fault.New(fault.CodeEvidenceInvalid, sigstoreOp,
			"the Sigstore bundle verified but established no signing identity")
	}
	return out, nil
}

// identityFromEntity reads the OIDC identity out of a verified certificate.
//
// The issuer comes from the Fulcio OIDC-issuer extension rather than from the
// certificate's X.509 issuer, which names the CA. Policy rules are written
// against the identity provider, not against Fulcio.
func identityFromEntity(entity verify.SignedEntity) (Identity, error) {
	content, err := entity.VerificationContent()
	if err != nil {
		return Identity{}, fault.Wrap(fault.CodeEvidenceInvalid, sigstoreOp,
			"reading the evidence verification material", err)
	}
	cert := content.Certificate()
	if cert == nil {
		// A bundle verified against a bare public key rather than a
		// certificate. That is a key identity, not a keyless one.
		return Identity{}, nil
	}

	summary, summaryErr := certificate.SummarizeCertificate(cert)
	if summaryErr != nil {
		return Identity{}, fault.Wrap(fault.CodeEvidenceInvalid, sigstoreOp,
			"reading the signing certificate", summaryErr)
	}

	subject := summary.SubjectAlternativeName
	if subject == "" {
		// A CI platform records the workflow in an extension rather than in
		// the SAN.
		subject = summary.BuildSignerURI
	}
	// The issuer comes from the Fulcio OIDC-issuer extension, not from the
	// certificate's X.509 issuer, which names the CA.
	return Identity{Issuer: summary.Issuer, Subject: subject}, nil
}

// classifySigstoreError maps a Sigstore failure onto a typed code.
func classifySigstoreError(err error, what string) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "no identity token"),
		strings.Contains(message, "unauthorized"),
		strings.Contains(message, "401"):
		return fault.Wrap(fault.CodeAuthentication, sigstoreOp, what, err)
	case fault.IsNetwork(err):
		return fault.Wrap(fault.CodeTransport, sigstoreOp, what, err).AsTemporary()
	default:
		return fault.Wrap(fault.CodeEvidenceInvalid, sigstoreOp, what, err)
	}
}

// MarshalBundle renders a Sigstore bundle as the JSON DevProof stores.
func MarshalBundle(b *protobundle.Bundle) ([]byte, error) {
	encoded, err := protojson.Marshal(b)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, sigstoreOp, "encoding the Sigstore bundle", err)
	}
	// protojson deliberately randomizes whitespace between runs to stop
	// callers depending on its output being stable. Re-encoding through
	// encoding/json removes that, which matters because this blob is stored
	// under its own digest and two encodings of one bundle must not produce
	// two digests.
	var normalized any
	if decodeErr := json.Unmarshal(encoded, &normalized); decodeErr != nil {
		return nil, fault.Wrap(fault.CodeInternal, sigstoreOp, "normalizing the Sigstore bundle", decodeErr)
	}
	stable, err := json.Marshal(normalized)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, sigstoreOp, "normalizing the Sigstore bundle", err)
	}
	return stable, nil
}
