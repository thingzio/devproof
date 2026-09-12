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

// Package artifact holds the OCI-facing types DevProof exchanges with
// registries and local layouts: descriptors, references, and the image
// manifest that is a bundle's subject.
//
// These types are deliberately minimal. They carry the OCI fields DevProof
// actually uses and no others, because every field present in a subject
// manifest is a field that contributes to its digest.
package artifact

import (
	"fmt"

	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/pkg/bundle"
)

const descriptorOp = "artifact.descriptor"

// MediaTypeImageManifest is the OCI image manifest media type. A bundle's
// subject is an ordinary OCI image manifest, so that registries and generic
// tooling handle it without knowing anything about DevProof.
const MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"

// Descriptor identifies content by digest, size, and media type.
//
// The digest is a string in OCI form rather than a parsed value because a
// descriptor is a wire type: it must round-trip byte-identically, including a
// digest this build might not be able to parse. Use ParsedDigest to get a
// validated value.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// ParsedDigest validates and returns the descriptor's digest.
func (d Descriptor) ParsedDigest() (bundle.Digest, error) {
	return bundle.ParseDigest(d.Digest)
}

// Validate checks that a descriptor is well formed.
func (d Descriptor) Validate() error {
	if d.MediaType == "" {
		return fault.New(fault.CodeInvalidArtifact, descriptorOp, "descriptor has no media type")
	}
	if d.Size < 0 {
		return fault.New(fault.CodeInvalidArtifact, descriptorOp,
			fmt.Sprintf("descriptor size is %d", d.Size))
	}
	if _, err := d.ParsedDigest(); err != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, descriptorOp, "descriptor digest is invalid", err)
	}
	return nil
}

// VerifyContent checks content against the descriptor's digest and size.
//
// Both are checked, and the size first: a descriptor whose size disagrees
// with its content is a signal on its own, and reporting "wrong length" is
// more useful than reporting a digest mismatch that a caller then has to
// diagnose.
func (d Descriptor) VerifyContent(content []byte) error {
	if int64(len(content)) != d.Size {
		return fault.New(fault.CodeDigestMismatch, descriptorOp,
			fmt.Sprintf("content is %d bytes, descriptor declares %d", len(content), d.Size))
	}

	want, err := d.ParsedDigest()
	if err != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, descriptorOp, "descriptor digest is invalid", err)
	}
	if got := bundle.DigestOf(content); got != want {
		return fault.New(fault.CodeDigestMismatch, descriptorOp,
			fmt.Sprintf("content digest is %s, descriptor declares %s", got, want))
	}
	return nil
}

// DescriptorFor builds a descriptor covering content.
func DescriptorFor(mediaType string, content []byte) Descriptor {
	return Descriptor{
		MediaType: mediaType,
		Digest:    bundle.DigestOf(content).String(),
		Size:      int64(len(content)),
	}
}
