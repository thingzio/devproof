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

package policy

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

const documentOp = "policy.document"

// Document is a verification policy.
//
// A policy is trusted configuration supplied by the caller. It is never read
// from the artifact being evaluated, and nothing in an artifact can change
// how it is interpreted — otherwise an attacker who controls a bundle would
// control the rules it is judged by.
type Document struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

// Metadata names a policy for diagnostics.
type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

// Spec is a policy's rules.
type Spec struct {
	Subject    SubjectRules    `json:"subject,omitzero" yaml:"subject,omitempty"`
	Signatures SignatureRules  `json:"signatures,omitzero" yaml:"signatures,omitempty"`
	Provenance ProvenanceRules `json:"provenance,omitzero" yaml:"provenance,omitempty"`
	Evidence   EvidenceRules   `json:"evidence,omitzero" yaml:"evidence,omitempty"`
	Limits     bundle.Limits   `json:"limits,omitzero" yaml:"limits,omitempty"`
}

// SubjectRules constrain the artifact itself.
type SubjectRules struct {
	// RequireDigestReference rejects a tag before anything is fetched.
	RequireDigestReference bool `json:"requireDigestReference,omitempty" yaml:"requireDigestReference,omitempty"`
	// AllowedFormats restricts which bundle format versions are acceptable.
	// Empty means any supported format.
	AllowedFormats []string `json:"allowedFormats,omitempty" yaml:"allowedFormats,omitempty"`
	// MaxFiles and MaxExpandedBytes bound the payload. Zero means the
	// effective limits apply unchanged.
	MaxFiles         int64 `json:"maxFiles,omitempty" yaml:"maxFiles,omitempty"`
	MaxExpandedBytes int64 `json:"maxExpandedBytes,omitempty" yaml:"maxExpandedBytes,omitempty"`
}

// SignatureRules constrain who signed.
type SignatureRules struct {
	// Threshold is the number of distinct accepted identities required.
	// Zero with no identities means signatures are not required.
	Threshold int `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// Identities are the accepted signers. Any one of them satisfies a
	// single unit of the threshold.
	Identities []IdentityRule `json:"identities,omitempty" yaml:"identities,omitempty"`
	// RequireTransparencyLog demands a proven transparency-log inclusion.
	RequireTransparencyLog bool `json:"requireTransparencyLog,omitempty" yaml:"requireTransparencyLog,omitempty"`
}

// IdentityRule matches one accepted signer.
//
// Exactly one form may be given. A rule that named both a key and an OIDC
// identity would be ambiguous about which had to match, and "either" is
// spelled by writing two rules.
type IdentityRule struct {
	// KeyID accepts a bare public key by identifier.
	KeyID string `json:"keyId,omitempty" yaml:"keyId,omitempty"`
	// Issuer is the OIDC issuer, matched exactly.
	Issuer string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	// Subject is the OIDC subject, matched exactly.
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`
	// SubjectPattern is an anchored regular expression alternative to
	// Subject. It is compiled at load time so a malformed pattern fails
	// where it can be fixed rather than mid-verification.
	SubjectPattern string `json:"subjectPattern,omitempty" yaml:"subjectPattern,omitempty"`

	compiled *regexp.Regexp
}

// ProvenanceRules constrain what the evidence says.
type ProvenanceRules struct {
	// Required demands provenance evidence.
	Required bool `json:"required,omitempty" yaml:"required,omitempty"`
	// PredicateTypes restricts acceptable predicate types.
	PredicateTypes []string `json:"predicateTypes,omitempty" yaml:"predicateTypes,omitempty"`
	// RequireLockDigest demands that provenance records a lock digest, which
	// is what makes a build's inputs auditable after the fact.
	RequireLockDigest bool `json:"requireLockDigest,omitempty" yaml:"requireLockDigest,omitempty"`
	// AllowedBuilders restricts the builder identity.
	AllowedBuilders []string `json:"allowedBuilders,omitempty" yaml:"allowedBuilders,omitempty"`
	// Sources constrains where material came from.
	Sources SourceRules `json:"sources,omitzero" yaml:"sources,omitempty"`
}

// SourceRules constrain a build's inputs.
//
// These apply to what the provenance claims, not to the payload's identity.
// Two attestations may truthfully describe different source histories for one
// subject; policy chooses which history it is willing to trust.
type SourceRules struct {
	// AllowedTypes restricts source types, such as "git" or "path".
	AllowedTypes []string `json:"allowedTypes,omitempty" yaml:"allowedTypes,omitempty"`
	// AllowedHosts restricts the hosts remote sources may come from.
	AllowedHosts []string `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	// RequireImmutableResolution demands that every source resolved to
	// something immutable.
	RequireImmutableResolution bool `json:"requireImmutableResolution,omitempty" yaml:"requireImmutableResolution,omitempty"`
}

// EvidenceRules govern how candidate evidence is treated.
type EvidenceRules struct {
	// RejectInvalidMatchingEvidence makes malformed evidence that claims a
	// required type fatal on its own.
	//
	// A repository is an open attachment surface: anyone with write access
	// can attach anything. With this false, junk is ignored and the policy
	// still fails if what remains cannot satisfy it. With it true, the
	// presence of malformed evidence is itself a signal worth failing on.
	RejectInvalidMatchingEvidence bool `json:"rejectInvalidMatchingEvidence,omitempty" yaml:"rejectInvalidMatchingEvidence,omitempty"`
	// AllowTagFallback permits evidence stored under the fallback tag scheme
	// on registries without the referrers API (DP-028). Off by default,
	// because that mode cannot express a set and silently replaces.
	AllowTagFallback bool `json:"allowTagFallback,omitempty" yaml:"allowTagFallback,omitempty"`
}

// ParseDocument decodes and validates a policy from YAML or JSON.
//
// Decoding is strict. An unknown field in a policy is the dangerous case: a
// rule this build does not understand is a rule it would not enforce, and
// silently ignoring one turns a strict policy into a permissive one.
func ParseDocument(data []byte) (*Document, error) {
	if len(data) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, documentOp, "policy is empty")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var doc Document
	if err := decoder.Decode(&doc); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, documentOp, "decoding policy", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fault.New(fault.CodeInvalidInput, documentOp,
			"policy contains more than one document")
	}

	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Validate checks a policy's structure and rejects contradictions.
func (d *Document) Validate() error {
	if d.APIVersion != bundle.APIVersionV1Alpha1 {
		return fault.New(fault.CodeUnsupportedVersion, documentOp,
			fmt.Sprintf("policy apiVersion %q is not supported; this build reads %q",
				d.APIVersion, bundle.APIVersionV1Alpha1))
	}
	if d.Kind != bundle.KindVerificationPolicy {
		return fault.New(fault.CodeInvalidInput, documentOp,
			fmt.Sprintf("policy kind is %q, want %q", d.Kind, bundle.KindVerificationPolicy))
	}
	if err := bundle.ValidateName(d.Metadata.Name, "policy metadata.name"); err != nil {
		return err
	}

	for _, format := range d.Spec.Subject.AllowedFormats {
		if !bundle.Supported(bundle.Format(format)) {
			return fault.New(fault.CodeUnsupportedVersion, documentOp,
				fmt.Sprintf("policy allows bundle format %q, which this build cannot read", format))
		}
	}

	// A negative bound is refused rather than ignored. The evaluator applies
	// these only when they are positive, so a negative value loaded cleanly
	// and enforced nothing -- a policy that looks exactly like one that is
	// working while checking less than the caller wrote down. Zero keeps its
	// meaning everywhere in this project: unset, inherit the effective limit.
	for _, bound := range []struct {
		field string
		value int64
	}{
		{"subject.maxFiles", d.Spec.Subject.MaxFiles},
		{"subject.maxExpandedBytes", d.Spec.Subject.MaxExpandedBytes},
	} {
		if bound.value < 0 {
			return fault.New(fault.CodeInvalidInput, documentOp,
				fmt.Sprintf("%s is %d; a bound must not be negative, and zero means unset",
					bound.field, bound.value))
		}
	}

	if err := d.Spec.Signatures.validate(); err != nil {
		return err
	}
	if err := d.Spec.Limits.Validate(); err != nil {
		return err
	}
	return nil
}

func (r *SignatureRules) validate() error {
	// A positive threshold with no identities can never be satisfied.
	// Accepting it would produce a policy that always fails, which is
	// indistinguishable from a policy that is working — the worst kind of
	// configuration error.
	if r.Threshold > 0 && len(r.Identities) == 0 {
		return fault.New(fault.CodeInvalidInput, documentOp,
			"signature threshold is positive but no accepted identities are listed, "+
				"so no evidence could ever satisfy it")
	}
	if r.Threshold < 0 {
		return fault.New(fault.CodeInvalidInput, documentOp, "signature threshold must not be negative")
	}
	if r.Threshold > len(r.Identities) && len(r.Identities) > 0 {
		return fault.New(fault.CodeInvalidInput, documentOp,
			fmt.Sprintf("signature threshold is %d but only %d identities are listed, "+
				"so no evidence could ever satisfy it", r.Threshold, len(r.Identities)))
	}

	for i := range r.Identities {
		if err := r.Identities[i].validate(i); err != nil {
			return err
		}
	}
	return nil
}

func (r *IdentityRule) validate(index int) error {
	reject := func(msg string) error {
		return fault.New(fault.CodeInvalidInput, documentOp,
			fmt.Sprintf("policy identity %d %s", index, msg))
	}

	hasKey := r.KeyID != ""
	hasOIDC := r.Issuer != "" || r.Subject != "" || r.SubjectPattern != ""

	switch {
	case !hasKey && !hasOIDC:
		return reject("names neither a key nor an OIDC identity")
	case hasKey && hasOIDC:
		return reject("names both a key and an OIDC identity; write two rules instead")
	}

	if r.Subject != "" && r.SubjectPattern != "" {
		return reject("gives both an exact subject and a pattern")
	}
	if hasOIDC && r.Issuer == "" {
		// An identity rule with a subject and no issuer would accept that
		// subject from any issuer, which is almost never what someone means
		// and is trivially forgeable by standing up an issuer.
		return reject("names an OIDC subject with no issuer")
	}
	if r.SubjectPattern != "" {
		// Anchored on both ends, because an unanchored pattern matching a
		// substring is how an identity rule gets bypassed: a subject of
		// "evil.example.com/?trusted.example.com/build" would match an
		// unanchored "trusted\.example\.com/build".
		anchored := "^(?:" + r.SubjectPattern + ")$"
		compiled, err := regexp.Compile(anchored)
		if err != nil {
			return fault.Wrap(fault.CodeInvalidInput, documentOp,
				fmt.Sprintf("policy identity %d has a malformed subject pattern", index), err)
		}
		r.compiled = compiled
	}
	return nil
}

// Matches reports whether a verified identity satisfies this rule.
//
// The identity passed here must already have been established
// cryptographically. A rule never sees an envelope's self-declared fields.
func (r *IdentityRule) Matches(keyID, issuer, subject string) bool {
	if r.KeyID != "" {
		return strings.EqualFold(r.KeyID, keyID)
	}
	if r.Issuer != issuer {
		return false
	}
	switch {
	case r.compiled != nil:
		return r.compiled.MatchString(subject)
	case r.Subject != "":
		return r.Subject == subject
	default:
		// Issuer-only: any subject from that issuer.
		return true
	}
}

// RequiresSignatures reports whether the policy demands any signature.
func (d *Document) RequiresSignatures() bool {
	return d.Spec.Signatures.Threshold > 0 || d.Spec.Provenance.Required
}

// EffectiveThreshold returns how many distinct identities are required.
func (d *Document) EffectiveThreshold() int {
	if d.Spec.Signatures.Threshold > 0 {
		return d.Spec.Signatures.Threshold
	}
	// Provenance that must be present must also be signed by somebody;
	// unsigned provenance records what a build did but never who did it.
	if d.Spec.Provenance.Required {
		return 1
	}
	return 0
}
