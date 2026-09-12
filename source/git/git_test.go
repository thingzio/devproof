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

package git

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/source"
)

// fixtureRepo builds a real on-disk repository and returns it.
//
// The resolver's open seam is replaced so the HTTPS rule stays intact for
// production callers while tests still exercise the real object-tree walk
// against real Git objects.
type fixtureRepo struct {
	repo   *gogit.Repository
	dir    string
	commit plumbing.Hash
}

func newFixtureRepo(t *testing.T, files map[string]string, executables ...string) *fixtureRepo {
	t.Helper()

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}

	executable := make(map[string]bool, len(executables))
	for _, name := range executables {
		executable[name] = true
	}

	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		mode := os.FileMode(0o644)
		if executable[rel] {
			mode = 0o755
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
		if _, err := worktree.Add(rel); err != nil {
			t.Fatalf("adding %s: %v", rel, err)
		}
	}

	// A fixed author keeps the commit hash reproducible, which matters for a
	// test that asserts a lock records the same commit twice.
	signature := &object.Signature{
		Name:  "Fixture",
		Email: "fixture@example.invalid",
		When:  time.Unix(0, 0).UTC(),
	}
	hash, err := worktree.Commit("fixture", &gogit.CommitOptions{Author: signature, Committer: signature})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &fixtureRepo{repo: repo, dir: dir, commit: hash}
}

// resolver returns a resolver wired to the fixture.
func (f *fixtureRepo) resolver() *Resolver {
	return &Resolver{
		open: func(context.Context, Config) (*gogit.Repository, error) { return f.repo, nil },
	}
}

func (f *fixtureRepo) tag(t *testing.T, name string) {
	t.Helper()
	if _, err := f.repo.CreateTag(name, f.commit, nil); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
}

func resolve(t *testing.T, r *Resolver, req source.ResolveRequest) (source.Snapshot, error) {
	t.Helper()
	if req.TempRoot == "" {
		req.TempRoot = t.TempDir()
	}
	snapshot, err := r.Resolve(t.Context(), req)
	if snapshot != nil {
		t.Cleanup(func() { _ = snapshot.Close() })
	}
	return snapshot, err
}

func TestResolveReadsTheCommitTree(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{
		"config/service.yaml": "a: 1\n",
		"scripts/run.sh":      "#!/bin/sh\n",
		"README.md":           "docs\n",
	}, "scripts/run.sh")

	snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	records := snapshot.Records()
	if len(records) != 3 {
		t.Fatalf("resolved %d files, want 3", len(records))
	}

	// The executable bit comes from the Git tree entry, not from a stat of a
	// checkout, so it cannot depend on the building machine's umask.
	byPath := map[string]uint32{}
	for _, record := range records {
		byPath[string(record.Path)] = record.Mode
	}
	if byPath["scripts/run.sh"] != bundle.ModeExecutable {
		t.Errorf("run.sh mode = %#o, want %#o", byPath["scripts/run.sh"], bundle.ModeExecutable)
	}
	if byPath["README.md"] != bundle.ModeFile {
		t.Errorf("README.md mode = %#o, want %#o", byPath["README.md"], bundle.ModeFile)
	}
}

func TestResolveRecordsTheImmutableCommit(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{"a.yaml": "a: 1\n"})

	snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	material := snapshot.Material()
	if got := material.Resolved["commit"]; got != fixture.commit.String() {
		t.Errorf("recorded commit %v, want %s", got, fixture.commit)
	}
	// The mutable ref is recorded as what was asked for, never as what was
	// resolved to.
	if got := material.Requested["ref"]; got != "HEAD" {
		t.Errorf("requested ref = %v", got)
	}
	if material.Resolved["objectFormat"] != "sha1" {
		t.Error("the object format was not recorded")
	}
}

// A tag is a mutable pointer. It must resolve to the commit it names, and the
// commit is what gets recorded.
func TestResolveFollowsTagsToCommits(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{"a.yaml": "a: 1\n"})
	fixture.tag(t, "v1.0.0")

	snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "v1.0.0"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := snapshot.Material().Resolved["commit"]; got != fixture.commit.String() {
		t.Errorf("tag resolved to %v, want %s", got, fixture.commit)
	}
}

func TestResolveSubPath(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{
		"deploy/service.yaml": "a: 1\n",
		"deploy/values.yaml":  "b: 2\n",
		"docs/README.md":      "ignored\n",
	})

	snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name: "application",
		Config: map[string]any{
			"url": "https://example.invalid/repo.git", "ref": "HEAD", "subPath": "deploy",
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var paths []string
	for _, record := range snapshot.Records() {
		paths = append(paths, string(record.Path))
	}
	// subPath selection happens before filtering, and the resulting paths are
	// relative to the subPath.
	want := []string{"service.yaml", "values.yaml"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("selected %v, want %v", paths, want)
	}
}

func TestResolveAppliesPatterns(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{
		"config/service.yaml": "a: 1\n",
		"config/scratch.tmp":  "junk\n",
		"README.md":           "docs\n",
	})

	snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:    "application",
		Config:  map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
		Include: []string{"config/**"},
		Exclude: []string{"**/*.tmp"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	records := snapshot.Records()
	if len(records) != 1 || string(records[0].Path) != "config/service.yaml" {
		t.Errorf("selected %v", records)
	}
}

// HTTPS only. Every other scheme carries its own trust and credential model,
// and file:// would let a manifest read anything the build account can reach
// while claiming to be a remote source.
func TestValidateConfigRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
	}{
		{"no url", Config{Ref: "main"}},
		{"no ref", Config{URL: "https://example.invalid/repo.git"}},
		{"ssh scheme", Config{URL: "ssh://git@example.invalid/repo.git", Ref: "main"}},
		{"git scheme", Config{URL: "git://example.invalid/repo.git", Ref: "main"}},
		{"file scheme", Config{URL: "file:///etc", Ref: "main"}},
		{"http scheme", Config{URL: "http://example.invalid/repo.git", Ref: "main"}},
		{"scp-style", Config{URL: "git@example.invalid:repo.git", Ref: "main"}},
		{
			"embedded credentials",
			Config{URL: "https://user:token@example.invalid/repo.git", Ref: "main"},
		},
		{
			"escaping subPath",
			Config{URL: "https://example.invalid/repo.git", Ref: "main", SubPath: "../../etc"},
		},
		{
			"absolute subPath",
			Config{URL: "https://example.invalid/repo.git", Ref: "main", SubPath: "/etc"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfig(tc.config)
			if err == nil {
				t.Fatal("an invalid config was accepted")
			}
			if !stderrors.Is(err, fault.CodeInvalidInput) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidInput)
			}
		})
	}

	valid := Config{URL: "https://example.invalid/repo.git", Ref: "main", SubPath: "deploy"}
	if err := validateConfig(valid); err != nil {
		t.Errorf("a valid config was rejected: %v", err)
	}
}

// A token in a URL must never reach a diagnostic, a lock, or provenance.
func TestRedactURLStripsCredentialsAndQuery(t *testing.T) {
	t.Parallel()

	got := redactURL("https://user:s3cret@example.invalid/repo.git?token=abcd#frag")

	for _, secret := range []string{"s3cret", "user", "abcd", "token"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted URL %q still contains %q", got, secret)
		}
	}
	if !strings.Contains(got, "example.invalid/repo.git") {
		t.Errorf("redacted URL %q lost the host and path", got)
	}
}

// The portable profile has no link type and does not materialize submodules,
// so both must fail rather than be silently skipped.
func TestResolveRejectsSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, name := range []string{"real.txt", "link.txt"} {
		if _, err := worktree.Add(name); err != nil {
			t.Fatalf("adding %s: %v", name, err)
		}
	}
	signature := &object.Signature{Name: "F", Email: "f@example.invalid", When: time.Unix(0, 0).UTC()}
	if _, err := worktree.Commit("with link", &gogit.CommitOptions{
		Author: signature, Committer: signature,
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	resolver := &Resolver{open: func(context.Context, Config) (*gogit.Repository, error) {
		return repo, nil
	}}
	_, err = resolve(t, resolver, source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

// An LFS pointer is a few hundred bytes of metadata, not the content it
// stands for. Packaging it as ordinary content would produce a bundle that
// looks complete and is not.
func TestResolveRejectsLFSPointer(t *testing.T) {
	t.Parallel()

	pointer := "version https://git-lfs.github.com/spec/v1\n" +
		"oid sha256:1111111111111111111111111111111111111111111111111111111111111111\n" +
		"size 12345\n"

	fixture := newFixtureRepo(t, map[string]string{"big.bin": pointer})

	_, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if !stderrors.Is(err, fault.CodeUnsupportedFile) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeUnsupportedFile)
	}
}

// A file that merely mentions LFS is not a pointer; over-rejecting would
// refuse legitimate documentation.
func TestResolveAcceptsContentMentioningLFS(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{
		"docs.md": "We do not use version https://git-lfs.github.com/spec/v1 here.\n",
	})

	if _, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	}); err != nil {
		t.Errorf("a file mentioning LFS was rejected: %v", err)
	}
}

func TestResolveUnknownRef(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{"a.yaml": "a: 1\n"})

	_, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "no-such-branch"},
	})
	if !stderrors.Is(err, fault.CodeSourceResolution) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeSourceResolution)
	}
}

// A locked build fetches the commit the lock names, not the mutable ref the
// manifest wrote. Otherwise moving a branch would change what a locked build
// produces (DP-004).
func TestLockedResolutionUsesTheLockedCommit(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{"a.yaml": "a: 1\n"})

	first, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	material := first.Material()

	locked := &bundle.LockedSource{
		Name:       "application",
		Type:       bundle.SourceTypeGit,
		Resolver:   identity.Name,
		Resolved:   map[string]any{"commit": material.Resolved["commit"]},
		TreeDigest: material.TreeDigest.String(),
	}

	if _, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
		Locked: locked,
	}); err != nil {
		t.Errorf("a matching lock was rejected: %v", err)
	}

	// A lock naming a different commit is stale.
	stale := *locked
	stale.Resolved = map[string]any{"commit": strings.Repeat("0", 40)}
	_, err = resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
		Locked: &stale,
	})
	if !stderrors.Is(err, fault.CodeStaleLock) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeStaleLock)
	}
}

// The commit matching but the tree digest differing means the filters or
// subPath changed, not the repository.
func TestLockedResolutionDetectsFilterDrift(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{"a.yaml": "a: 1\n", "b.yaml": "b: 2\n"})

	full, err := resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:   "application",
		Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	locked := &bundle.LockedSource{
		Name:       "application",
		Type:       bundle.SourceTypeGit,
		Resolver:   identity.Name,
		Resolved:   map[string]any{"commit": full.Material().Resolved["commit"]},
		TreeDigest: full.Material().TreeDigest.String(),
	}

	// Same commit, narrower include: the tree digest no longer matches.
	_, err = resolve(t, fixture.resolver(), source.ResolveRequest{
		Name:    "application",
		Config:  map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
		Include: []string{"a.yaml"},
		Locked:  locked,
	})
	if !stderrors.Is(err, fault.CodeStaleLock) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeStaleLock)
	}
}

func TestResolveIsDeterministic(t *testing.T) {
	t.Parallel()

	fixture := newFixtureRepo(t, map[string]string{
		"config/service.yaml": "a: 1\n",
		"scripts/run.sh":      "#!/bin/sh\n",
	}, "scripts/run.sh")

	var reference string
	for i := range 5 {
		snapshot, err := resolve(t, fixture.resolver(), source.ResolveRequest{
			Name:   "application",
			Config: map[string]any{"url": "https://example.invalid/repo.git", "ref": "HEAD"},
		})
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		digest := snapshot.Material().TreeDigest.String()
		if i == 0 {
			reference = digest
			continue
		}
		if digest != reference {
			t.Fatalf("resolve %d produced %s, want %s", i, digest, reference)
		}
	}
}

func TestResolverIdentity(t *testing.T) {
	t.Parallel()

	r := New()
	if r.Type() != bundle.SourceTypeGit {
		t.Errorf("Type() = %q", r.Type())
	}
	if r.Identity().Name != "devproof.thingz.io/git/v1" {
		t.Errorf("Identity() = %+v", r.Identity())
	}
}
