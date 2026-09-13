# Releasing

Releases are cut by pushing a semver tag. Everything after that is automated.

This document is for maintainers. Contributors do not need it — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Cutting a release

```shell
make bump-patch   # v1.2.3 -> v1.2.4
make bump-minor   # v1.2.3 -> v1.3.0
make bump-major   # v1.2.3 -> v2.0.0
```

`tools/bump` refuses to tag from a branch other than `main`, refuses a dirty or
untracked-file-carrying tree, refuses when the branch is ahead of or behind
`origin`, and runs `make qualify` before it tags anything. A tag names bytes
other people will verify against, and it cannot be taken back, so the checks are
enforced rather than listed. `SKIP_QUALIFY=1` exists for re-tagging a commit
already known to be green; it is not for saving time.

A tag pointing at a commit that is not on `origin/main` produces a release
nobody can reproduce from the public history -- which matters more here than
most places, given what this project is for. That is why unpushed commits are
refused rather than warned about.

The branch and the tag are pushed with `git push --atomic`, so a race that
rejects one rejects both: the remote never ends up carrying a tag that points at
a commit nobody can fetch.

## What happens on the tag

`.github/workflows/release.yaml` runs on any tag matching ``v*``. It qualifies
the tagged commit here and then hands everything else to
[`release-go.yaml`](https://github.com/thingzio/actions/blob/main/.github/workflows/release-go.md)
in `thingzio/actions`, pinned by commit SHA:

1. **The full suite runs first**, here, on every platform a release ships
   binaries for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, and
   `darwin/arm64`. The independent `conformance` reader runs too, so the
   artifact is checked against the format specification rather than against the
   code that produced it. A failure aborts the release before anything is
   built.
2. **Build.** goreleaser builds the `devproof` CLI for every supported
   platform, a checksum file covering every artifact, and an SPDX SBOM per
   archive. There are no container images and no cloud credentials in this
   repository. This job holds no signing identity.
3. **Sign.** In a separate job that runs no code from this repository,
   `cosign` signs the checksum file with a keyless Sigstore signature. Signing
   the checksums rather than each archive means one signature covers the
   release and there is exactly one thing to verify. Before signing, that job
   re-downloads every asset on the release and re-derives its digest, so it
   never signs a checksum file describing something the release does not carry.
4. **Attest.** Build provenance is attested in the same isolated job.
5. **Verify.** `cosign verify-blob` checks the signature that was just
   produced, requiring the shared workflow's own identity. A signature nobody
   checks is a signature nobody knows is broken, and this fails the release
   rather than publishing an unverifiable one.
6. **Publish.** The release is created as a draft and flipped to published
   only after verification succeeds, so a release is never visible before its
   signature has been checked.

**The signer is `thingzio/actions`, not this repository.** That is the point of
the split: because the job holding the signing identity runs no code from here,
goreleaser hooks in this repository cannot reach it, and the provenance reaches
SLSA Build Level 3 rather than 2. Consumers check it with `--signer-workflow`;
the exact commands are in the release notes of every release.

Releases cut before this migration — `v0.1.0` and earlier — were signed by
`thingzio/devproof/.github/workflows/release.yaml` and still verify against that
identity. Their release notes carry the commands that match them.

The Homebrew cask is pushed to `thingzio/homebrew-tap` during step 2, so
`brew install thingzio/tap/devproof` picks up the new version.

## Release candidates

A prerelease tag (`v0.1.0-rc.1`) exercises the whole path without publishing
the Homebrew cask: `prerelease: auto` detects it and `skip_upload: auto` skips
the cask for prereleases. Useful before a first release, or any release that
changes the pipeline.

The final tag goes on a *later* commit than its candidate. The shared workflow
tells goreleaser the triggering tag explicitly via `GORELEASER_CURRENT_TAG`, so
two tags on one commit no longer confuse it — that fix moved to
`thingzio/actions` with the rest of the release, and is no longer set in this
repository. A release and its candidate pointing at the same tree is still
confusing for people, though.

## The Homebrew tap

The cask is published only when the repository has a `HOMEBREW_DEPLOY_KEY`
secret: a fine-grained PAT with `contents: write` on `thingzio/homebrew-tap`.
Without it goreleaser skips the cask rather than failing, so a release works
before the secret exists and starts publishing the cask once it does.

A cask rather than a formula, because these are prebuilt signed binaries. A
formula would ask Homebrew to build from source, producing a binary nobody
attested to — from a project whose subject is provenance.

One ordering wrinkle: the cask is pushed while the GitHub release is still a
draft, since publication waits for signature verification. A release that fails
verification leaves a cask pointing at a tag that never publishes, and the fix
is to revert that commit in the tap. That is the right trade against publishing
a release nobody checked.

Since releasing moved to the shared workflow that window spans a whole separate
job rather than a few steps, so it is minutes rather than seconds. Cutting a
release candidate first is the cheap way to find a pipeline problem before a
real cask points at a draft.

## Versioning

[Semantic versioning](https://semver.org). `v0.1.0` established the baseline.
Until 1.0, minor versions may carry breaking changes; patch versions do not.

**The bundle format has its own compatibility contract**, separate from the Go
API's version number. See [docs/compatibility.md](docs/compatibility.md) -- a
format change can reissue the identity of every artifact ever produced, which is
not something a patch version should be able to do.

When 1.0 arrives, this section gets rewritten with a real compatibility
commitment. Until then, pin exactly if you depend on this.

## If a release goes wrong

**The signing job failed.** Re-run **only the failed jobs**, not the whole
workflow. The signing job keeps the checksum file from the build for seven days
and will re-download the release's assets and re-verify them against it.
Re-running the whole workflow means a second `goreleaser release` against a
release that already exists — survivable, because `release.use_existing_draft`
makes goreleaser reuse the draft rather than open a second one for the same tag,
but there is no reason to rebuild what is already built.

Nothing is public while this is true: the release stays a draft until the
signature verifies.

**The tag exists but the workflow failed.** Fix the problem on `main`, then cut
a new patch version. Do not delete and re-push the tag — someone may already
have consumed it, and a moving tag is worse than a skipped version number.
Version numbers are free.

If the build never got as far as creating the release, deleting the draft and
re-tagging is also fine: a draft is not immutable, a published release is.

**A released version has a serious defect.** Cut a new patch release. There is
no yank mechanism, and the supported-version policy in
[SECURITY.md](SECURITY.md) means only the latest release is maintained anyway.

## Release checklist

Nothing here is enforced by tooling, which is why it is written down:

- [ ] CI is green on the commit being tagged
- [ ] Anything user-visible is reflected in the docs
- [ ] A format-affecting change, if any, carries a new format version and new
      golden vectors — never a silent change to existing ones (DP-015)

`make qualify` and the clean-tree and unpushed-commit checks are enforced by
`tools/bump`, so they are deliberately absent from this list. A checklist item
that tooling already guarantees is an item people stop reading.
