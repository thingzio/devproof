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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/thingzio/devproof/pkg/fault"
)

const keyOp = "evidence.key"

// KeyAttester signs with a local private key.
//
// This is the one attester the module ships. Keyless identity, transparency
// logs, and TUF trust roots are supplied by an embedding application as
// registered extensions, so that a caller who signs with a local key or does
// not sign at all is not made to carry that dependency tree (DP-029).
//
// Supported keys are ECDSA and Ed25519. RSA is omitted deliberately: it has
// no advantage here, and its parameter space — key size, PKCS#1 against PSS,
// hash choice — is surface that would have to be pinned and tested for a
// capability nobody has asked for.
type KeyAttester struct {
	signer crypto.Signer
	keyID  string
}

var _ Attester = (*KeyAttester)(nil)

// NewKeyAttester returns an attester signing with key.
func NewKeyAttester(key crypto.Signer) (*KeyAttester, error) {
	if key == nil {
		return nil, fault.New(fault.CodeInvalidInput, keyOp, "signing key must not be nil")
	}
	switch key.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, fault.New(fault.CodeInvalidInput, keyOp,
			fmt.Sprintf("signing key type %T is not supported; use ECDSA or Ed25519", key))
	}

	keyID, err := KeyID(key.Public())
	if err != nil {
		return nil, err
	}
	return &KeyAttester{signer: key, keyID: keyID}, nil
}

// Name identifies the attester in evidence and in verification reports.
func (a *KeyAttester) Name() string { return "devproof.thingz.io/key/v1" }

// KeyID returns this attester's public key identifier.
func (a *KeyAttester) KeyID() string { return a.keyID }

// Attest signs the request's payload.
func (a *KeyAttester) Attest(_ context.Context, req AttestRequest) ([]Signature, error) {
	if len(req.Payload) == 0 {
		return nil, fault.New(fault.CodeInternal, keyOp, "nothing to sign")
	}

	// Signed over the pre-authentication encoding, not the payload, so a
	// signature cannot be replayed under a different payload type.
	message := PreAuthEncoding(req.PayloadType, req.Payload)

	var (
		signature []byte
		err       error
	)
	switch key := a.signer.(type) {
	case ed25519.PrivateKey:
		// Ed25519 hashes internally and rejects a pre-hashed message.
		signature, err = key.Sign(rand.Reader, message, crypto.Hash(0))
	default:
		digest := sha256.Sum256(message)
		signature, err = a.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, keyOp, "signing the statement", err)
	}

	return []Signature{{
		KeyID: a.keyID,
		Sig:   base64.StdEncoding.EncodeToString(signature),
	}}, nil
}

// KeyVerifier verifies signatures against a set of trusted public keys.
type KeyVerifier struct {
	// keys maps a key identifier to its public key.
	keys map[string]crypto.PublicKey
}

var _ Verifier = (*KeyVerifier)(nil)

// NewKeyVerifier returns a verifier trusting the supplied public keys.
//
// An empty key set is refused rather than accepted as "trust nothing". A
// verifier that can never succeed is almost always a configuration mistake,
// and failing at construction says so at the point where it can be fixed.
func NewKeyVerifier(keys ...crypto.PublicKey) (*KeyVerifier, error) {
	if len(keys) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, keyOp,
			"a key verifier needs at least one trusted public key")
	}

	v := &KeyVerifier{keys: make(map[string]crypto.PublicKey, len(keys))}
	for _, key := range keys {
		id, err := KeyID(key)
		if err != nil {
			return nil, err
		}
		v.keys[id] = key
	}
	return v, nil
}

// Name identifies the verifier in verification reports. It matches the
// attester it verifies, so a report says which scheme accepted the evidence.
func (v *KeyVerifier) Name() string { return "devproof.thingz.io/key/v1" }

// Verify checks an envelope's signatures against the trusted keys.
//
// A signature is tried against every trusted key rather than only the one its
// keyid names, because the keyid is attacker-controlled: an envelope could
// name a key that is not trusted and the signature still be valid under one
// that is. What matters is that some trusted key verifies it.
func (v *KeyVerifier) Verify(_ context.Context, req VerifyRequest) (*VerificationResult, error) {
	if req.Envelope == nil {
		return nil, fault.New(fault.CodeInternal, keyOp, "no envelope to verify")
	}
	if err := req.Envelope.Validate(); err != nil {
		return nil, err
	}

	message := PreAuthEncoding(req.Envelope.PayloadType, req.Payload)
	digest := sha256.Sum256(message)

	var identities []Identity
	seen := make(map[string]struct{})

	for _, signature := range req.Envelope.Signatures {
		raw, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err != nil {
			continue
		}
		for id, key := range v.keys {
			if !verifyOne(key, message, digest[:], raw) {
				continue
			}
			if _, duplicate := seen[id]; duplicate {
				// One key signing twice is one identity. Counting it twice
				// would let a single signer satisfy a threshold meant to
				// require several.
				break
			}
			seen[id] = struct{}{}
			identities = append(identities, Identity{KeyID: id})
			break
		}
	}

	if len(identities) == 0 {
		return nil, fault.New(fault.CodeEvidenceInvalid, keyOp,
			"no signature on this evidence verifies against a trusted key")
	}
	return &VerificationResult{Identities: identities}, nil
}

func verifyOne(key crypto.PublicKey, message, digest, signature []byte) bool {
	switch typed := key.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(typed, digest, signature)
	case ed25519.PublicKey:
		return ed25519.Verify(typed, message, signature)
	default:
		return false
	}
}

// KeyID returns a stable identifier for a public key.
//
// It is the SHA-256 of the key's PKIX encoding, which is the same value
// whatever container the key arrived in — PEM, DER, or a certificate — so a
// policy that names a key does not have to name a file format.
func KeyID(key crypto.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fault.Wrap(fault.CodeInvalidInput, keyOp, "encoding the public key", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ParsePublicKeyPEM decodes a PEM-encoded public key.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fault.New(fault.CodeInvalidInput, keyOp, "no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, keyOp, "parsing the public key", err)
	}
	switch key.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		return key, nil
	default:
		return nil, fault.New(fault.CodeInvalidInput, keyOp,
			fmt.Sprintf("public key type %T is not supported; use ECDSA or Ed25519", key))
	}
}

// ParsePrivateKeyPEM decodes a PEM-encoded private key.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fault.New(fault.CodeInvalidInput, keyOp, "no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// An EC key may be in SEC 1 form rather than PKCS#8.
		if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ecKey, nil
		}
		return nil, fault.Wrap(fault.CodeInvalidInput, keyOp, "parsing the private key", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fault.New(fault.CodeInvalidInput, keyOp,
			fmt.Sprintf("private key type %T cannot sign", key))
	}
	switch signer.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		return signer, nil
	default:
		return nil, fault.New(fault.CodeInvalidInput, keyOp,
			fmt.Sprintf("private key type %T is not supported; use ECDSA or Ed25519", signer))
	}
}
