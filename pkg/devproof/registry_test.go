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

package devproof_test

import (
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/thingzio/devproof"
)

// registryStub is a minimal OCI Distribution server, enough to exercise the
// SDK end to end against a registry without requiring one to be running.
//
// A conformance suite against real registries belongs in an integration job;
// this is here so that the publication ordering, tag-last rule, and read-back
// comparison are covered by the ordinary `go test` run.
type registryStub struct {
	server *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
	tags      map[string]string
	// corruptOnRead makes the registry serve a manifest that differs from
	// what was stored, so a test can confirm the read-back comparison is
	// load-bearing.
	corruptOnRead atomic.Bool
	// rejectManifestPut makes the registry refuse the manifest upload.
	rejectManifestPut atomic.Bool
	// order records the sequence of write operations, so a test can assert
	// that the tag was assigned last.
	order []string
}

func newRegistryStub(t *testing.T) *registryStub {
	t.Helper()

	s := &registryStub{
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
		tags:      map[string]string{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *registryStub) host() string { return strings.TrimPrefix(s.server.URL, "http://") }

func (s *registryStub) ref(repo, target string) string {
	return "oci://" + s.host() + "/" + repo + target
}

func (s *registryStub) events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}

func (s *registryStub) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v2/":
		w.WriteHeader(http.StatusOK)
	case strings.Contains(r.URL.Path, "/blobs/uploads/"):
		s.upload(w, r)
	case strings.Contains(r.URL.Path, "/blobs/"):
		s.blob(w, r)
	case strings.Contains(r.URL.Path, "/manifests/"):
		s.manifest(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *registryStub) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		w.Header().Set("Location", r.URL.Path+"session")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	body, _ := io.ReadAll(r.Body)
	digest := r.URL.Query().Get("digest")

	s.mu.Lock()
	s.blobs[digest] = body
	s.order = append(s.order, "blob")
	s.mu.Unlock()

	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (s *registryStub) blob(w http.ResponseWriter, r *http.Request) {
	digest := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]

	s.mu.Lock()
	body, ok := s.blobs[digest]
	s.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (s *registryStub) manifest(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	isTag := !strings.HasPrefix(target, "sha256:")

	if r.Method == http.MethodPut {
		if s.rejectManifestPut.Load() && !isTag {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		digest := sha256Digest(body)

		s.mu.Lock()
		s.manifests[digest] = body
		if isTag {
			s.tags[target] = digest
			s.order = append(s.order, "tag")
		} else {
			s.order = append(s.order, "manifest")
		}
		s.mu.Unlock()

		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	s.mu.Lock()
	digest := target
	if resolved, ok := s.tags[target]; ok {
		digest = resolved
	}
	body, ok := s.manifests[digest]
	s.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if s.corruptOnRead.Load() {
		body = append(append([]byte{}, body...), ' ')
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func registryClient(t *testing.T) *devproof.Client {
	t.Helper()
	return newClient(t, devproof.WithInsecureRegistry(nil))
}

// A registry destination must produce the same subject as a local one.
// Identity is a function of content and format version; a repository name is
// neither (DP-002).
func TestBuildToRegistryProducesTheSameSubject(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)
	source := defaultSource(t)

	toLayout, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if err != nil {
		t.Fatalf("build to layout: %v", err)
	}

	toRegistry, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("build to registry: %v", err)
	}

	if toRegistry.SubjectDigest != toLayout.SubjectDigest {
		t.Errorf("the destination changed the subject digest:\n  layout:   %s\n  registry: %s",
			toLayout.SubjectDigest, toRegistry.SubjectDigest)
	}
	if !strings.HasPrefix(toRegistry.Reference, "oci://") {
		t.Errorf("reference = %q, want a registry reference", toRegistry.Reference)
	}
	if !strings.Contains(toRegistry.Reference, toRegistry.SubjectDigest) {
		t.Errorf("reference %q does not name the subject by digest", toRegistry.Reference)
	}
}

// The tag is assigned last, after every blob and the manifest are present and
// the manifest has been read back. A name therefore never points at content
// that is not completely there (DP-007).
func TestPublicationAssignsTheTagLast(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)

	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	events := stub.events()
	if len(events) == 0 {
		t.Fatal("no write operations were recorded")
	}
	if events[len(events)-1] != "tag" {
		t.Errorf("write order was %v; the tag must come last", events)
	}
	// Every blob precedes the manifest that references them.
	manifestAt := -1
	for i, event := range events {
		if event == "manifest" {
			manifestAt = i
			break
		}
	}
	if manifestAt < 0 {
		t.Fatalf("no manifest was written: %v", events)
	}
	for i, event := range events[manifestAt:] {
		if event == "blob" {
			t.Errorf("a blob was written after the manifest, at position %d: %v", manifestAt+i, events)
		}
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Verify by tag; the report names the subject by digest.
	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: stub.ref("team/config", ":v1"),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.SubjectDigest != built.SubjectDigest {
		t.Errorf("verified %s, built %s", report.SubjectDigest, built.SubjectDigest)
	}

	destination := filepath.Join(t.TempDir(), "expanded")
	expanded, err := client.Expand(t.Context(), devproof.ExpandRequest{
		Reference:   stub.ref("team/config", "@"+built.SubjectDigest),
		Destination: destination,
	})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	// Rebuilding from the expanded tree reproduces the subject, so a
	// registry round trip preserved the bytes exactly.
	rebuilt, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  expanded.Destination,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt.SubjectDigest != built.SubjectDigest {
		t.Errorf("a registry round trip changed the subject:\n  %s\n  %s",
			built.SubjectDigest, rebuilt.SubjectDigest)
	}
}

// A copy changes where a subject lives and nothing about what it is.
func TestCopyPreservesTheSubject(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	copied, err := client.Copy(t.Context(), devproof.CopyRequest{
		Source:      stub.ref("team/config", "@"+built.SubjectDigest),
		Destination: stub.ref("mirror/config", ""),
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if copied.SubjectDigest != built.SubjectDigest {
		t.Errorf("copying changed the subject digest: %s", copied.SubjectDigest)
	}

	// The copy verifies at its new location on its own.
	report, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: stub.ref("mirror/config", ":v1"),
	})
	if err != nil {
		t.Fatalf("verifying the copy: %v", err)
	}
	if report.SubjectDigest != built.SubjectDigest {
		t.Errorf("the copy verified as %s", report.SubjectDigest)
	}
}

// A copy out of a registry and into a local layout is the offline-export
// case, and must preserve identity just as a registry-to-registry copy does.
func TestCopyFromRegistryToLayout(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	layoutPath := filepath.Join(t.TempDir(), "export")
	copied, err := client.Copy(t.Context(), devproof.CopyRequest{
		Source:      stub.ref("team/config", ":v1"),
		Destination: "oci-layout://" + layoutPath,
		Tag:         "v1",
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if copied.SubjectDigest != built.SubjectDigest {
		t.Errorf("copying changed the subject digest")
	}

	if _, err := client.Verify(t.Context(), devproof.VerifyRequest{
		Reference: "oci-layout://" + layoutPath + ":v1",
	}); err != nil {
		t.Errorf("the exported layout does not verify: %v", err)
	}
}

func TestCopyRequiresDigestWhenAsked(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	client := registryClient(t)

	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err := client.Copy(t.Context(), devproof.CopyRequest{
		Source:        stub.ref("team/config", ":v1"),
		Destination:   stub.ref("mirror/config", ""),
		RequireDigest: true,
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

func TestBuildRejectsDigestDestination(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath: defaultSource(t),
		Destination: "oci://registry.example.com/team/config@sha256:" +
			strings.Repeat("0", 64),
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

func TestBuildRejectsUnknownDestinationScheme(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: "https://example.com/artifact",
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

// sha256Digest renders a digest the way a registry reports one.
func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Publication is not complete because a write returned success; it is
// complete when the destination serves the same bytes back. Without the
// read-back, a registry that silently rewrote a manifest would have its
// digest reported as published.
func TestPublicationFailsWhenTheDestinationStoresSomethingElse(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	stub.corruptOnRead.Store(true)
	client := registryClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	})
	if err == nil {
		t.Fatal("a build reported success against a registry that stored different bytes")
	}

	// And nothing was tagged, so no name points at the bad content.
	for _, event := range stub.events() {
		if event == "tag" {
			t.Errorf("a tag was assigned despite the failure: %v", stub.events())
		}
	}
}

// A destination that rejects the upload must not produce a tag or a success
// result either.
func TestPublicationFailureLeavesNoTag(t *testing.T) {
	t.Parallel()

	stub := newRegistryStub(t)
	stub.rejectManifestPut.Store(true)
	client := registryClient(t)

	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SourcePath:  defaultSource(t),
		Destination: stub.ref("team/config", ""),
		Tag:         "v1",
	}); err == nil {
		t.Fatal("a build reported success despite a rejected manifest upload")
	}

	for _, event := range stub.events() {
		if event == "tag" {
			t.Errorf("a tag was assigned despite the failure: %v", stub.events())
		}
	}
}
