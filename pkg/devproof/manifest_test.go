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
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/devproof"
)

// writeManifest writes a manifest and the source trees it names, returning
// the manifest path.
func writeManifest(t *testing.T, manifest string, trees map[string]map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, files := range trees {
		for rel, content := range files {
			full := filepath.Join(dir, name, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("creating %s: %v", filepath.Dir(full), err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatalf("writing %s: %v", full, err)
			}
		}
	}

	path := filepath.Join(dir, "devproof.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}
	return path
}

const twoSourceManifest = `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example-config
spec:
  sources:
    - name: application
      type: path
      mountPath: app
      include:
        - "config/**"
      exclude:
        - "**/*.tmp"
      config:
        path: ./application

    - name: environment
      type: path
      mountPath: environment
      config:
        path: ./environment
`

func twoSourceTrees() map[string]map[string]string {
	return map[string]map[string]string{
		"application": {
			"config/service.yaml": "a: 1\n",
			"config/scratch.tmp":  "junk",
			"README.md":           "not selected",
		},
		"environment": {
			"production.yaml": "env: prod\n",
		},
	}
}

func TestBuildFromManifest(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    manifest,
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// The include and exclude patterns select exactly two files.
	if built.FileCount != 2 {
		t.Errorf("built %d files, want 2", built.FileCount)
	}

	paths := make([]string, 0, len(built.Lock.Files))
	for _, f := range built.Lock.Files {
		paths = append(paths, f.Path)
	}
	want := []string{"app/config/service.yaml", "environment/production.yaml"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("composed %v, want %v", paths, want)
	}

	// Every final path has exactly one owner (DP-011).
	for _, f := range built.Lock.Files {
		if f.Source == "" {
			t.Errorf("%s has no owner", f.Path)
		}
	}
}

// A mount path relocates a source's contribution. Its own tree digest is
// unaffected, because a source's identity is its content, not its placement.
func TestMountPathDoesNotChangeSourceTreeDigest(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	trees := twoSourceTrees()

	atApp := writeManifest(t, twoSourceManifest, trees)
	built, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: atApp, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	moved := writeManifest(t, strings.Replace(twoSourceManifest,
		"mountPath: app", "mountPath: elsewhere", 1), trees)
	rebuilt, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: moved, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "b"),
	})
	if err != nil {
		t.Fatalf("Build moved: %v", err)
	}

	if built.SubjectDigest == rebuilt.SubjectDigest {
		t.Error("moving a mount path did not change the subject digest")
	}

	original, _ := built.Lock.SourceByName("application")
	relocated, _ := rebuilt.Lock.SourceByName("application")
	if original.TreeDigest != relocated.TreeDigest {
		t.Errorf("the source tree digest changed with its mount path: %s then %s",
			original.TreeDigest, relocated.TreeDigest)
	}
}

// DP-011: source ordering is not an input to identity.
func TestSourceOrderDoesNotAffectOutput(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	trees := twoSourceTrees()

	forward := writeManifest(t, twoSourceManifest, trees)
	first, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: forward, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Same two sources, declared the other way round.
	reversed := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: example-config
spec:
  sources:
    - name: environment
      type: path
      mountPath: environment
      config:
        path: ./environment

    - name: application
      type: path
      mountPath: app
      exclude:
        - "**/*.tmp"
      include:
        - "config/**"
      config:
        path: ./application
`
	second, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: writeManifest(t, reversed, trees), Destination: "oci-layout://" + filepath.Join(t.TempDir(), "b"),
	})
	if err != nil {
		t.Fatalf("Build reversed: %v", err)
	}

	if first.SubjectDigest != second.SubjectDigest {
		t.Errorf("source order changed the subject digest:\n  %s\n  %s",
			first.SubjectDigest, second.SubjectDigest)
	}
	// The manifest digest is computed over the normalized model, so
	// reordering sources and include lists does not change it either.
	if first.ManifestDigest != second.ManifestDigest {
		t.Errorf("source order changed the manifest digest:\n  %s\n  %s",
			first.ManifestDigest, second.ManifestDigest)
	}
	if first.LockDigest != second.LockDigest {
		t.Errorf("source order changed the lock digest")
	}
}

// Two sources claiming one destination is an error, not a merge (DP-011).
func TestCollidingSourcesFail(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: colliding
spec:
  sources:
    - name: first
      type: path
      config: {path: ./first}
    - name: second
      type: path
      config: {path: ./second}
`
	trees := map[string]map[string]string{
		"first":  {"shared.yaml": "same"},
		"second": {"shared.yaml": "same"}, // identical bytes, still a collision
	}

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    writeManifest(t, manifest, trees),
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if !stderrors.Is(err, devproof.CodePathCollision) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodePathCollision)
	}
	// The message must name both sides; "something collided" is not
	// actionable.
	if err != nil && !strings.Contains(err.Error(), "first") {
		t.Errorf("the error does not name the colliding sources: %v", err)
	}
}

func TestLockRoundTrip(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	locked, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if locked.SourceCount != 2 || locked.FileCount != 2 {
		t.Errorf("lock records %d sources and %d files", locked.SourceCount, locked.FileCount)
	}

	// The lock landed beside the manifest and parses back identically.
	written, err := os.ReadFile(locked.OutputPath)
	if err != nil {
		t.Fatalf("reading lock: %v", err)
	}
	parsed, err := bundle.ParseLock(written)
	if err != nil {
		t.Fatalf("ParseLock: %v", err)
	}
	if parsed.TreeDigest != locked.TreeDigest {
		t.Error("the written lock does not describe the resolution that produced it")
	}

	// Locking again is idempotent.
	again, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest})
	if err != nil {
		t.Fatalf("second Lock: %v", err)
	}
	if again.LockDigest != locked.LockDigest {
		t.Errorf("locking twice produced different digests: %s then %s",
			locked.LockDigest, again.LockDigest)
	}
}

// A lock beside a manifest is enforced by default. A build that ignored it
// unless asked would make reproducibility opt-in (DP-004).
func TestBuildEnforcesLockByDefault(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	if _, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest}); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// A locked build of unchanged material succeeds.
	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: manifest, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"),
	}); err != nil {
		t.Fatalf("locked build of unchanged material: %v", err)
	}

	// Editing a source invalidates the lock.
	edited := filepath.Join(filepath.Dir(manifest), "environment", "production.yaml")
	if err := os.WriteFile(edited, []byte("env: staging\n"), 0o644); err != nil {
		t.Fatalf("editing source: %v", err)
	}

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: manifest, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "b"),
	})
	if !stderrors.Is(err, devproof.CodeStaleLock) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeStaleLock)
	}
}

// Relocking is explicit. A build never silently refreshes a lock, because
// that would make the lock a record of the last build rather than a
// constraint on the next one.
func TestBuildDoesNotRelockImplicitly(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	locked, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	edited := filepath.Join(filepath.Dir(manifest), "environment", "production.yaml")
	if err := os.WriteFile(edited, []byte("env: staging\n"), 0o644); err != nil {
		t.Fatalf("editing source: %v", err)
	}

	// UpdateLock resolves afresh instead of enforcing.
	updated, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: manifest, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"), UpdateLock: true,
	})
	if err != nil {
		t.Fatalf("build with UpdateLock: %v", err)
	}
	if updated.LockDigest == locked.LockDigest {
		t.Error("UpdateLock did not produce a new lock")
	}

	// The on-disk lock is untouched: writing it is the Lock operation's job.
	onDisk, err := os.ReadFile(locked.OutputPath)
	if err != nil {
		t.Fatalf("reading lock: %v", err)
	}
	if string(onDisk) != string(locked.LockBytes) {
		t.Error("a build rewrote the lock file")
	}
}

func TestLockCheckDetectsDrift(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	if _, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest}); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	checked, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest, Check: true})
	if err != nil {
		t.Fatalf("Lock --check on unchanged material: %v", err)
	}
	if !checked.Matched {
		t.Error("an unchanged lock did not match")
	}

	edited := filepath.Join(filepath.Dir(manifest), "environment", "production.yaml")
	if err := os.WriteFile(edited, []byte("env: staging\n"), 0o644); err != nil {
		t.Fatalf("editing source: %v", err)
	}

	drifted, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest, Check: true})
	if !stderrors.Is(err, devproof.CodeStaleLock) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeStaleLock)
	}
	if drifted != nil && drifted.Matched {
		t.Error("a drifted lock reported a match")
	}
}

// A lock records content, not location. Moving a checkout must not invalidate
// it; changing a byte inside must.
func TestLockSurvivesRelocationButNotEdits(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	trees := twoSourceTrees()
	original := writeManifest(t, twoSourceManifest, trees)

	locked, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: original})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// Same manifest and content, different directory.
	relocated := writeManifest(t, twoSourceManifest, trees)
	moved, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: relocated})
	if err != nil {
		t.Fatalf("Lock after relocation: %v", err)
	}
	if moved.LockDigest != locked.LockDigest {
		t.Errorf("relocating the checkout changed the lock digest:\n  %s\n  %s",
			locked.LockDigest, moved.LockDigest)
	}
}

// A lock must not contain a host absolute path (DP-025) or anything else that
// discloses where a build ran.
func TestLockContainsNoAbsolutePaths(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	locked, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: manifest})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	body := string(locked.LockBytes)
	checkoutDir := filepath.Dir(manifest)

	if strings.Contains(body, checkoutDir) {
		t.Errorf("the lock discloses the checkout directory %q", checkoutDir)
	}
	for _, forbidden := range []string{os.TempDir(), "/Users/", "/home/", "/private/"} {
		if forbidden != "" && strings.Contains(body, forbidden) {
			t.Errorf("the lock contains an absolute path fragment %q:\n%s", forbidden, body)
		}
	}
}

// A manifest whose sources partly fail produces nothing at all (DP-011).
func TestPartialSourceFailureProducesNoLock(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: partial
spec:
  sources:
    - name: present
      type: path
      mountPath: present
      config: {path: ./present}
    - name: absent
      type: path
      mountPath: absent
      config: {path: ./does-not-exist}
`
	specPath := writeManifest(t, manifest, map[string]map[string]string{
		"present": {"a.yaml": "a: 1\n"},
	})

	_, err := client.Lock(t.Context(), devproof.LockRequest{SpecPath: specPath})
	if err == nil {
		t.Fatal("a manifest with a missing source produced a lock")
	}

	if _, statErr := os.Stat(filepath.Join(filepath.Dir(specPath), devproof.DefaultLockName)); !os.IsNotExist(statErr) {
		t.Error("a partial lock was written")
	}
}

func TestBuildRejectsManifestAndDirectSourceTogether(t *testing.T) {
	t.Parallel()

	client := newClient(t)

	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    writeManifest(t, twoSourceManifest, twoSourceTrees()),
		SourcePath:  t.TempDir(),
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}
}

func TestBuildRejectsUnregisteredSourceType(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: extension
spec:
  sources:
    - name: remote
      type: storage.example.com/object
      config: {bucket: example}
`
	_, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath:    writeManifest(t, manifest, nil),
		Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
	})
	if !stderrors.Is(err, devproof.CodeUnsupportedSource) {
		t.Errorf("code = %q, want %q", codeOf(err), devproof.CodeUnsupportedSource)
	}
}

// A path source naming an absolute path is refused unless the embedding
// application opts in.
func TestAbsolutePathSourcesAreOptIn(t *testing.T) {
	t.Parallel()

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "a.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatalf("writing source: %v", err)
	}

	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: absolute
spec:
  sources:
    - name: elsewhere
      type: path
      config: {path: ` + target + `}
`
	specPath := writeManifest(t, manifest, nil)

	_, err := newClient(t).Build(t.Context(), devproof.BuildRequest{
		SpecPath: specPath, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "a"),
	})
	if !stderrors.Is(err, devproof.CodeInvalidInput) {
		t.Errorf("default client: code = %q, want %q", codeOf(err), devproof.CodeInvalidInput)
	}

	permissive := newClient(t, devproof.WithAbsolutePathSources())
	if _, err := permissive.Build(t.Context(), devproof.BuildRequest{
		SpecPath: specPath, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "b"),
	}); err != nil {
		t.Errorf("opted-in client: %v", err)
	}
}

// Concurrency must not be observable in the output. Resolving the same
// manifest repeatedly under a bound must produce one answer.
func TestConcurrentResolutionIsDeterministic(t *testing.T) {
	t.Parallel()

	manifest := `
apiVersion: devproof.thingz.io/v1alpha1
kind: Bundle
metadata:
  name: many
spec:
  sources:
    - {name: alpha, type: path, mountPath: a, config: {path: ./alpha}}
    - {name: bravo, type: path, mountPath: b, config: {path: ./bravo}}
    - {name: charlie, type: path, mountPath: c, config: {path: ./charlie}}
    - {name: delta, type: path, mountPath: d, config: {path: ./delta}}
    - {name: echo, type: path, mountPath: e, config: {path: ./echo}}
`
	trees := map[string]map[string]string{
		"alpha":   {"one.yaml": "1"},
		"bravo":   {"two.yaml": "2"},
		"charlie": {"three.yaml": "3"},
		"delta":   {"four.yaml": "4"},
		"echo":    {"five.yaml": "5"},
	}
	specPath := writeManifest(t, manifest, trees)

	client := newClient(t)
	var reference string

	for i := range 12 {
		built, err := client.Build(t.Context(), devproof.BuildRequest{
			SpecPath:    specPath,
			Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
			SkipLock:    true,
		})
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		if i == 0 {
			reference = built.SubjectDigest
			continue
		}
		if built.SubjectDigest != reference {
			t.Fatalf("build %d produced %s, want %s", i, built.SubjectDigest, reference)
		}
	}
}

// The concurrency bound is honored, so a manifest with many sources cannot
// open an unbounded number of handles at once.
func TestParallelSourceLimitIsHonored(t *testing.T) {
	t.Parallel()

	client := newClient(t, devproof.WithLimits(devproof.Limits{MaxParallelSources: 1}))
	manifest := writeManifest(t, twoSourceManifest, twoSourceTrees())

	if _, err := client.Build(t.Context(), devproof.BuildRequest{
		SpecPath: manifest, Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"), SkipLock: true,
	}); err != nil {
		t.Fatalf("serialized build: %v", err)
	}
}
