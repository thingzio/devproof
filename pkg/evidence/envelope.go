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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

const envelopeOp = "evidence.envelope"

// PayloadType is the DSSE payload type for an in-toto statement.
const PayloadType = "application/vnd.in-toto+json"

// MediaTypeEvidenceV1 is the OCI artifact type of a DevProof evidence
// referrer. It lets discovery filter before fetching anything (DP-027).
const MediaTypeEvidenceV1 = "application/vnd.thingz.devproof.evidence.v1"

// MediaTypeBundleV1 is the blob media type of an evidence object. It is the
// Sigstore bundle type so that generic Sigstore tooling can read what
// DevProof writes.
const MediaTypeBundleV1 = "application/vnd.dev.sigstore.bundle.v1+json"

// Envelope is a DSSE envelope.
//
// The payload is base64 of the serialized statement, and signatures are over
// the pre-authentication encoding rather than over the payload directly. That
// indirection is what stops a signature made for one payload type being
// replayed as though it were another.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature over an envelope's payload.
type Signature struct {
	// KeyID identifies the signing key or identity. Its meaning is the
	// attester's; policy matches on the verified identity, not on this.
	KeyID string `json:"keyid,omitempty"`
	// Sig is the base64 signature.
	Sig string `json:"sig"`
	// Certificate is the PEM signing certificate, when the attester uses
	// one. Present for keyless identities, absent for bare keys.
	Certificate string `json:"cert,omitempty"`
}

// PreAuthEncoding builds the DSSE pre-authentication encoding.
//
// The format is fixed by the DSSE specification:
//
//	"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
//
// Length-prefixing every field is what makes the encoding unambiguous: without
// it, a payload type and a payload could be chosen so that one signature
// validates two different (type, payload) pairs.
func PreAuthEncoding(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// DecodePayload returns the envelope's raw payload bytes.
func (e *Envelope) DecodePayload() ([]byte, error) {
	if e.PayloadType != PayloadType {
		return nil, fault.New(fault.CodeEvidenceInvalid, envelopeOp,
			fmt.Sprintf("envelope payload type is %q, want %q", e.PayloadType, PayloadType))
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fault.Wrap(fault.CodeEvidenceInvalid, envelopeOp,
			"envelope payload is not valid base64", err)
	}
	return payload, nil
}

// Statement decodes and validates the envelope's statement.
//
// Callers must not use this before the envelope's signatures have been
// verified. Parsing a claim is not the same as establishing it, and the
// verification pipeline is structured so that unverified statements never
// reach policy (DP-014).
func (e *Envelope) Statement() (*Statement, error) {
	payload, err := e.DecodePayload()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	var statement Statement
	if err := decoder.Decode(&statement); err != nil {
		return nil, fault.Wrap(fault.CodeEvidenceInvalid, envelopeOp,
			"envelope payload is not a valid in-toto statement", err)
	}
	if decoder.More() {
		return nil, fault.New(fault.CodeEvidenceInvalid, envelopeOp,
			"envelope payload contains trailing data")
	}
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	return &statement, nil
}

// Validate checks an envelope's structure.
func (e *Envelope) Validate() error {
	if e.PayloadType != PayloadType {
		return fault.New(fault.CodeEvidenceInvalid, envelopeOp,
			fmt.Sprintf("envelope payload type is %q, want %q", e.PayloadType, PayloadType))
	}
	if e.Payload == "" {
		return fault.New(fault.CodeEvidenceInvalid, envelopeOp, "envelope has no payload")
	}
	if len(e.Signatures) == 0 {
		// An unsigned envelope is a supported object — it records what a
		// build did — but it is never evidence of who did it, and a policy
		// requiring an authenticated identity can never be satisfied by one.
		return fault.New(fault.CodeEvidenceInvalid, envelopeOp, "envelope has no signatures")
	}
	for i, signature := range e.Signatures {
		if signature.Sig == "" {
			return fault.New(fault.CodeEvidenceInvalid, envelopeOp,
				fmt.Sprintf("signature %d has no value", i))
		}
		if _, err := base64.StdEncoding.DecodeString(signature.Sig); err != nil {
			return fault.Wrap(fault.CodeEvidenceInvalid, envelopeOp,
				fmt.Sprintf("signature %d is not valid base64", i), err)
		}
	}
	return nil
}

// AttestRequest is what an attester is asked to sign.
type AttestRequest struct {
	// Subject is the OCI manifest digest the statement is about.
	Subject bundle.Digest
	// Statement is the statement to sign. The service builds it; an attester
	// supplies identity and signatures, and must not alter the payload.
	Statement *Statement
	// PayloadType is the DSSE payload type to sign under.
	PayloadType string
	// Payload is the exact serialized statement to sign. Signing these
	// bytes rather than re-serializing the statement is what guarantees the
	// signature covers what the envelope carries.
	Payload []byte
}

// Attester signs a statement.
//
// An attester supplies identity and nothing else. It does not choose the
// subject, build the statement, or decide what the payload says; those are
// the evidence service's, so a registered attester cannot attest to something
// other than what was built.
type Attester interface {
	// Name identifies the attester in diagnostics and results.
	Name() string
	// Attest returns signatures over the request's payload.
	Attest(ctx context.Context, req AttestRequest) ([]Signature, error)
}

// Identity is who signed, once that has been established cryptographically.
//
// Exactly one of KeyID or the OIDC pair is meaningful, depending on the
// verifier. Policy matches on this rather than on anything in the envelope,
// because an envelope's own fields are attacker-controlled until a
// verification has checked them.
type Identity struct {
	// KeyID identifies a bare public key.
	KeyID string `json:"keyId,omitempty"`
	// Issuer is the OIDC issuer, for a keyless identity.
	Issuer string `json:"issuer,omitempty"`
	// Subject is the OIDC subject, for a keyless identity.
	Subject string `json:"subject,omitempty"`
}

// IsZero reports whether no identity was established.
func (i Identity) IsZero() bool {
	return i.KeyID == "" && i.Issuer == "" && i.Subject == ""
}

func (i Identity) String() string {
	switch {
	case i.Issuer != "" || i.Subject != "":
		return i.Subject + " (" + i.Issuer + ")"
	case i.KeyID != "":
		return "key " + i.KeyID
	default:
		return "unidentified"
	}
}

// VerifyRequest is what a verifier is asked to check.
type VerifyRequest struct {
	// Envelope is the DSSE envelope to verify.
	Envelope *Envelope
	// Payload is the decoded payload the signatures must cover.
	Payload []byte
	// BundleJSON is the stored evidence blob, when the object is a Sigstore
	// bundle. A keyless verifier needs the whole bundle — certificate,
	// transparency-log entry, timestamps — not just the envelope.
	BundleJSON []byte
	// TrustRoots is caller-supplied trust material. Its format is the
	// verifier's; the SDK never interprets it.
	TrustRoots [][]byte
}

// VerificationResult is what a verifier establishes.
type VerificationResult struct {
	// Identities are the signers whose signatures verified. An empty slice
	// with a nil error is a contradiction a verifier must not produce.
	Identities []Identity
	// TransparencyLogVerified reports whether inclusion in a transparency
	// log was proven. Policy may require it; absence is not an error here.
	TransparencyLogVerified bool
	// IntegratedTime is an authenticated signing time, when one was
	// established. A verifier must not populate it from the envelope or from
	// the local clock — an unauthenticated time cannot satisfy a rule that
	// requires one.
	IntegratedTime *int64
}

// Verifier establishes who signed an envelope.
//
// A verifier returns identities or an error, and never both an empty identity
// list and success: "verified, by nobody" is the shape of a bug that lets
// unauthenticated claims reach policy.
type Verifier interface {
	// Name identifies the verifier in diagnostics and results.
	Name() string
	// Verify checks an envelope's signatures.
	Verify(ctx context.Context, req VerifyRequest) (*VerificationResult, error)
}
