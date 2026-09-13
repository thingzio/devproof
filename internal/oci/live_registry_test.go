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

//go:build registry

// This file runs against a real OCI registry.
//
// Every other registry test in this package drives an in-process handler
// written here, which proves the client does what this repository believes the
// distribution specification says. That is a different claim from "it works
// against a registry somebody else wrote", and the difference is where
// interoperability bugs live: a status code chosen differently, a referrers
// response shaped differently, a tag listing paginated.
//
// It is behind a build tag because it needs a server. Run it with:
//
//	docker run --rm -p 5000:5000 ghcr.io/project-zot/zot-linux-amd64:latest
//	DEVPROOF_TEST_REGISTRY=localhost:5000 go test -tags registry ./internal/oci/
//
// Asking for the tag and not supplying a registry is a failure rather than a
// skip: somebody who typed -tags registry meant to run this.

package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/thingzio/devproof/pkg/artifact"
	"github.com/thingzio/devproof/pkg/bundle"
)

// liveRegistryEnv names the host:port of a running registry.
const liveRegistryEnv = "DEVPROOF_TEST_REGISTRY"

func liveRegistry(t *testing.T) (*Registry, string) {
	t.Helper()

	host := os.Getenv(liveRegistryEnv)
	if host == "" {
		t.Fatalf("set %s to a running registry, such as localhost:5000", liveRegistryEnv)
	}

	registry := NewRegistry(RegistryOptions{PlainHTTP: true})
	t.Cleanup(func() { _ = registry.Close() })
	return registry, host
}

// liveReference returns a reference into a repository unique to this run.
//
// A registry keeps what it is given, so two runs sharing a repository would
// see each other's referrers and one of them would pass for the wrong reason.
func liveReference(t *testing.T, host, target string) artifact.Reference {
	t.Helper()

	name := fmt.Sprintf("oci://%s/devproof-test/%d/%s", host, time.Now().UnixNano(), target)
	ref, err := artifact.ParseReference(name)
	if err != nil {
		t.Fatalf("ParseReference(%q): %v", name, err)
	}
	return ref
}

// TestLiveRegistryReferrerRoundTrip is the interoperability claim.
//
// Push a subject, attach evidence to it, list the referrers, and fetch what
// comes back. Each step is one the in-process handler also implements, and
// each is one a real registry may implement differently.
func TestLiveRegistryReferrerRoundTrip(t *testing.T) {
	registry, host := liveRegistry(t)
	ctx := t.Context()

	ref := liveReference(t, host, "config:v1")

	// A subject manifest with a config and one layer, the shape a bundle has.
	layer := []byte("payload bytes\n")
	layerDescriptor := artifact.DescriptorFor(bundle.MediaTypeLayerV1, layer)
	if err := registry.Push(ctx, ref, layerDescriptor, bytes.NewReader(layer)); err != nil {
		t.Fatalf("pushing the layer: %v", err)
	}

	config := []byte(`{"schemaVersion":1}`)
	configDescriptor := artifact.DescriptorFor(bundle.MediaTypeConfigV1, config)
	if err := registry.Push(ctx, ref, configDescriptor, bytes.NewReader(config)); err != nil {
		t.Fatalf("pushing the config: %v", err)
	}

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     artifact.MediaTypeImageManifest,
		"artifactType":  bundle.MediaTypeArtifactV1,
		"config":        configDescriptor,
		"layers":        []artifact.Descriptor{layerDescriptor},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encoding the manifest: %v", err)
	}
	subject := artifact.DescriptorFor(artifact.MediaTypeImageManifest, encoded)
	if err := registry.Push(ctx, ref, subject, bytes.NewReader(encoded)); err != nil {
		t.Fatalf("pushing the manifest: %v", err)
	}
	if err := registry.Tag(ctx, ref, subject, "v1"); err != nil {
		t.Fatalf("tagging: %v", err)
	}

	// A tag resolves to the digest that was published, not to something else
	// the registry decided to canonicalize.
	resolved, err := registry.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolving the tag: %v", err)
	}
	if resolved.Digest != subject.Digest {
		t.Errorf("the tag resolves to %s, and %s was published", resolved.Digest, subject.Digest)
	}

	// No evidence yet. An empty set, not an error: a subject with no evidence
	// is an ordinary state, and a registry that returns 404 for it must not
	// look like a broken one.
	before, storage, err := registry.Referrers(ctx, ref, subject, bundle.MediaTypeArtifactV1)
	if err != nil {
		t.Fatalf("listing referrers before attaching: %v", err)
	}
	if len(before) != 0 {
		t.Errorf("a fresh subject already has %d referrers", len(before))
	}
	t.Logf("evidence storage mode: %s", storage)

	evidenceBlob := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	evidenceDescriptor := artifact.DescriptorFor("application/json", evidenceBlob)
	attached, attachStorage, err := registry.Attach(ctx, ref, subject, evidenceDescriptor,
		bytes.NewReader(evidenceBlob), bundle.MediaTypeArtifactV1)
	if err != nil {
		t.Fatalf("attaching evidence: %v", err)
	}
	if attachStorage != storage {
		t.Errorf("attach reported storage %s and listing reported %s", attachStorage, storage)
	}

	after, _, err := registry.Referrers(ctx, ref, subject, bundle.MediaTypeArtifactV1)
	if err != nil {
		t.Fatalf("listing referrers: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("the subject has %d referrers after one attach, want 1", len(after))
	}
	if after[0].Digest != attached.Digest {
		t.Errorf("the listing names %s and the attach returned %s", after[0].Digest, attached.Digest)
	}

	// The referrer manifest is fetchable and names the subject it was attached
	// to. The relationship lives in the manifest, and a registry that
	// reconstructs the listing from an index must not lose it.
	reader, err := registry.Fetch(ctx, ref, after[0])
	if err != nil {
		t.Fatalf("fetching the referrer manifest: %v", err)
	}
	defer func() { _ = reader.Close() }()

	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading the referrer manifest: %v", err)
	}
	var referrer struct {
		ArtifactType string               `json:"artifactType"`
		Subject      *artifact.Descriptor `json:"subject"`
	}
	if err := json.Unmarshal(raw, &referrer); err != nil {
		t.Fatalf("decoding the referrer manifest: %v", err)
	}
	if referrer.Subject == nil || referrer.Subject.Digest != subject.Digest {
		t.Errorf("the referrer manifest does not name the subject: %+v", referrer.Subject)
	}
	if referrer.ArtifactType != bundle.MediaTypeArtifactV1 {
		t.Errorf("artifactType = %q, want %q", referrer.ArtifactType, bundle.MediaTypeArtifactV1)
	}
}

// TestLiveRegistryReferrerFiltering checks that the artifact-type filter is
// the registry's and not ours.
//
// A repository is an open attachment surface. If the filter is applied by the
// client after a full listing, a subject with thousands of unrelated referrers
// is a transfer nobody asked for; if the registry ignores the parameter, a
// caller that trusts it gets somebody else's evidence.
func TestLiveRegistryReferrerFiltering(t *testing.T) {
	registry, host := liveRegistry(t)
	ctx := t.Context()

	ref := liveReference(t, host, "filtered:v1")

	config := []byte(`{"schemaVersion":1}`)
	configDescriptor := artifact.DescriptorFor(bundle.MediaTypeConfigV1, config)
	if err := registry.Push(ctx, ref, configDescriptor, bytes.NewReader(config)); err != nil {
		t.Fatalf("pushing the config: %v", err)
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     artifact.MediaTypeImageManifest,
		"artifactType":  bundle.MediaTypeArtifactV1,
		"config":        configDescriptor,
		"layers":        []artifact.Descriptor{},
	})
	if err != nil {
		t.Fatalf("encoding the manifest: %v", err)
	}
	subject := artifact.DescriptorFor(artifact.MediaTypeImageManifest, manifest)
	if err := registry.Push(ctx, ref, subject, bytes.NewReader(manifest)); err != nil {
		t.Fatalf("pushing the manifest: %v", err)
	}

	for _, artifactType := range []string{bundle.MediaTypeArtifactV1, "application/vnd.example.other"} {
		blob := []byte(`{"kind":"` + artifactType + `"}`)
		descriptor := artifact.DescriptorFor("application/json", blob)
		if _, _, err := registry.Attach(ctx, ref, subject, descriptor,
			bytes.NewReader(blob), artifactType); err != nil {
			t.Fatalf("attaching %s: %v", artifactType, err)
		}
	}

	filtered, storage, err := registry.Referrers(ctx, ref, subject, bundle.MediaTypeArtifactV1)
	if err != nil {
		t.Fatalf("listing referrers: %v", err)
	}
	if storage == artifact.StorageTagFallback {
		t.Skip("the registry has no referrers API; the fallback tag cannot express a set")
	}
	if len(filtered) != 1 {
		t.Errorf("the filtered listing returned %d referrers, want 1", len(filtered))
	}

	all, _, err := registry.Referrers(ctx, ref, subject, "")
	if err != nil {
		t.Fatalf("listing every referrer: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("the unfiltered listing returned %d referrers, want 2", len(all))
	}
}
