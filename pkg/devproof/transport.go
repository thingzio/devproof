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

package devproof

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/thingzio/devproof/internal/canonical"
	"github.com/thingzio/devproof/internal/oci"
	"github.com/thingzio/devproof/internal/safefs"
	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/fault"
)

const transportOp = "transport"

// transportFor returns the transport registered for a reference's scheme.
func (c *Client) transportFor(ref artifact.Reference) (artifact.Transport, error) {
	transport, ok := c.transports[ref.Scheme]
	if !ok {
		return nil, fault.New(fault.CodeUnsupportedSource, transportOp,
			fmt.Sprintf("no transport is registered for %q references", ref.Scheme))
	}
	// Refused here, where the transport is chosen, rather than at each call
	// site. This is the one place every operation passes through to reach a
	// transport, so there is no path that acquires one without being asked
	// this question.
	if c.offline && !artifact.IsLocalOnly(transport) {
		return nil, fault.New(fault.CodeInvalidInput, transportOp,
			fmt.Sprintf("this client is offline, and %q references need the network",
				ref.Scheme))
	}
	return transport, nil
}

// publish writes a subject to a destination and, only then, names it.
//
// The order is the contract, and it is here rather than in each transport so
// that no transport can weaken it:
//
//  1. The layer and config blobs, so nothing the manifest points at is
//     missing.
//  2. The manifest.
//  3. A read-back of the stored manifest, compared byte for byte. A registry
//     that stored something other than what was sent is caught before its
//     digest is reported as published.
//  4. The tag, last. A name therefore never points at incomplete content,
//     and a failure before this step leaves no name at all (DP-007).
func (c *Client) publish(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	subject *canonical.Subject,
	layer layerSource,
	tag string,
) (artifact.Reference, error) {

	// The layer is opened lazily and streamed, so publishing a large bundle
	// does not require holding it in memory. The config is small and bounded
	// by its own limit, so it stays a slice.
	blobs := []struct {
		descriptor artifact.Descriptor
		open       func() (io.Reader, error)
	}{
		{subject.LayerDescriptor(), layer.Reader},
		{subject.ConfigDescriptor(), func() (io.Reader, error) {
			return bytes.NewReader(subject.ConfigBytes), nil
		}},
	}
	for _, blob := range blobs {
		if err := fault.FromContext(ctx, transportOp, "publication canceled"); err != nil {
			return ref, err
		}
		content, err := blob.open()
		if err != nil {
			return ref, err
		}
		if err := transport.Push(ctx, ref, blob.descriptor, content); err != nil {
			return ref, err
		}
	}

	manifestDescriptor := subject.Descriptor()
	if err := transport.Push(ctx, ref, manifestDescriptor, bytes.NewReader(subject.ManifestBytes)); err != nil {
		return ref, err
	}

	pinned := ref.WithDigest(manifestDescriptor.Digest)

	// A layout has no way to enumerate manifests other than its index, so an
	// untagged subject would be unreachable without an entry. Only when no
	// tag follows: tagging adds the entry itself, and doing both would leave
	// two entries naming one manifest.
	if tag == "" {
		if recorder, ok := transport.(interface {
			Record(artifact.Reference, artifact.Descriptor) error
		}); ok {
			if err := recorder.Record(ref, manifestDescriptor); err != nil {
				return pinned, err
			}
		}
	}

	if err := c.verifyPublished(ctx, transport, pinned, manifestDescriptor, subject.ManifestBytes); err != nil {
		return pinned, err
	}

	if tag != "" {
		if err := transport.Tag(ctx, ref, manifestDescriptor, tag); err != nil {
			return pinned, err
		}
	}
	return pinned, nil
}

// verifyPublished reads the stored manifest back and compares it.
//
// Publication is not complete because a write returned success; it is
// complete when the destination serves the same bytes. Without this a
// registry that silently rewrote or truncated a manifest would have its
// digest reported as published.
func (c *Client) verifyPublished(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	descriptor artifact.Descriptor,
	expected []byte,
) (retErr error) {

	reader, err := transport.Fetch(ctx, ref, descriptor)
	if err != nil {
		return fault.Wrap(fault.CodeTransport, transportOp,
			"reading back the published manifest", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, transportOp,
				"closing the published manifest", closeErr)
		}
	}()

	stored, err := io.ReadAll(io.LimitReader(reader, int64(len(expected))+1))
	if err != nil {
		return fault.Wrap(fault.CodeTransport, transportOp,
			"reading back the published manifest", err)
	}
	if !bytes.Equal(stored, expected) {
		return fault.New(fault.CodeDigestMismatch, transportOp,
			"the destination stored a manifest different from the one that was published")
	}
	return nil
}

// fetchSubject resolves a reference and verifies the subject's integrity.
//
// The reference is frozen to a digest before any content is fetched, and
// every later step uses the frozen descriptor. A tag that moves between the
// resolve and the fetch therefore cannot change what was verified (DP-007).
func (c *Client) fetchSubject(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	limits bundle.Limits,
	payload payloadCheck,
) (*canonical.Subject, artifact.Reference, error) {

	if err := fault.FromContext(ctx, transportOp, "verification canceled"); err != nil {
		return nil, ref, err
	}

	manifestDescriptor, err := transport.Resolve(ctx, ref)
	if err != nil {
		return nil, ref, err
	}
	pinned := ref.WithDigest(manifestDescriptor.Digest)

	manifestBytes, err := fetchBlob(ctx, transport, pinned, manifestDescriptor, limits.MaxManifestBytes)
	if err != nil {
		return nil, pinned, err
	}

	manifest, err := canonical.ParseManifest(manifestBytes)
	if err != nil {
		return nil, pinned, err
	}

	configBytes, err := fetchBlob(ctx, transport, pinned, manifest.Config, limits.MaxConfigBytes)
	if err != nil {
		return nil, pinned, err
	}

	layerDescriptor, err := manifest.Layer()
	if err != nil {
		return nil, pinned, err
	}
	if layerDescriptor.Size > limits.MaxCompressedBytes {
		return nil, pinned, fault.New(fault.CodeLimitExceeded, transportOp,
			fmt.Sprintf("layer is %d bytes, the limit is %d",
				layerDescriptor.Size, limits.MaxCompressedBytes))
	}
	layerDigest, err := layerDescriptor.ParsedDigest()
	if err != nil {
		return nil, pinned, err
	}

	subject, err := canonical.VerifySubject(manifestBytes, configBytes, layerDescriptor.Size, layerDigest)
	if err != nil {
		return nil, pinned, err
	}

	// VerifySubject establishes that the manifest and config agree with each
	// other and with the manifest's own layer descriptor. That is a claim
	// about metadata: every value it compares came out of the same manifest.
	// Until the layer itself is read, nothing here has looked at the payload,
	// and a subject whose layer is absent, altered, or differently encoded
	// satisfies all of it.
	if payload == checkPayload {
		if err := c.verifyPayload(ctx, transport, pinned, subject, limits); err != nil {
			return nil, pinned, err
		}
	}
	return subject, pinned, nil
}

// verifyPayload streams the layer and checks it against its descriptor and
// the config inventory.
//
// Streamed rather than buffered: the layer is the one blob that can exceed
// memory, and DP-033 makes independence from payload size a correctness
// property rather than a performance one.
func (c *Client) verifyPayload(
	ctx context.Context,
	transport artifact.Transport,
	pinned artifact.Reference,
	subject *canonical.Subject,
	limits bundle.Limits,
) (retErr error) {

	layer, err := transport.Fetch(ctx, pinned, subject.LayerDescriptor())
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := layer.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, transportOp, "closing the layer blob", closeErr)
		}
	}()

	_, err = safefs.VerifyLayer(ctx, layer, safefs.VerifyLayerOptions{
		Config:      subject.Config,
		Limits:      limits,
		LayerDigest: subject.LayerDigest,
		LayerSize:   subject.LayerSize,
	})
	return err
}

// fetchBlob reads a blob and verifies it against its descriptor.
//
// The read is bounded one byte past the declared size so that a destination
// serving more than it promised is reported rather than silently truncated,
// and the digest is checked before the bytes are used for anything.
func fetchBlob(
	ctx context.Context,
	transport artifact.Transport,
	ref artifact.Reference,
	descriptor artifact.Descriptor,
	limit int64,
) (_ []byte, retErr error) {

	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	if limit > 0 && descriptor.Size > limit {
		return nil, fault.New(fault.CodeLimitExceeded, transportOp,
			fmt.Sprintf("%s is %d bytes, the limit is %d",
				descriptor.MediaType, descriptor.Size, limit))
	}

	reader, err := transport.Fetch(ctx, ref, descriptor)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, transportOp, "closing fetched content", closeErr)
		}
	}()

	content, err := io.ReadAll(io.LimitReader(reader, descriptor.Size+1))
	if err != nil {
		return nil, fault.Wrap(fault.CodeTransport, transportOp, "reading content", err)
	}
	if err := descriptor.VerifyContent(content); err != nil {
		return nil, err
	}
	return content, nil
}

// defaultTransports returns the transports every client starts with.
func defaultTransports() map[string]artifact.Transport {
	return map[string]artifact.Transport{
		artifact.SchemeLayout:   oci.NewLayoutTransport(),
		artifact.SchemeRegistry: oci.NewRegistry(oci.RegistryOptions{}),
	}
}
