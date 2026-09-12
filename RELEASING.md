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

`tools/bump` refuses to tag a dirty tree, refuses to tag when there are
unpushed commits, and runs `make qualify` before it tags anything. A tag names
bytes other people will verify against, and it cannot be taken back, so the
checks are enforced rather than listed. `SKIP_QUALIFY=1` exists for re-tagging
a commit already known to be green; it is not for saving time.

A tag pointing at a commit that is not on `origin/main` produces a release
nobody can reproduce from the public history -- which matters more here than
most places, given what this project is for. That is why unpushed commits are
refused rather than warned about.

## What happens on the tag

`.github/workflows/release.yaml` runs on any tag matching
``v*``:

1. **The full suite runs first**, on every platform a release ships binaries
   for: `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`. The
   independent `conformance` reader runs too, so the artifact is checked
   against the format specification rather than against the code that produced
   it. A failure aborts the release before anything is published.
2. **Build.** goreleaser builds the `devproof` CLI for every supported
   platform, a checksum file covering every artifact, and an SPDX SBOM per
   archive. There are no container images and no cloud credentials in this
   repository.
3. **Sign.** `cosign` signs the checksum file with a keyless Sigstore
   signature. Signing the checksums rather than each archive means one
   signature covers the release and there is exactly one thing to verify.
4. **Attest.** Build provenance is attested by the workflow rather than by the
   build, so a compromised build step cannot forge it.
5. **Verify.** `cosign verify-blob` checks the signature that was just
   produced. A signature nobody checks is a signature nobody knows is broken,
   and this fails the release rather than publishing an unverifiable one.
6. **Publish.** The release is created as a draft and flipped to published
   only after verification succeeds, so a release is never visible before its
   signature has been checked.

The Homebrew cask is pushed to `thingzio/homebrew-tap` during step 2, so
`brew install thingzio/tap/devproof` picks up the new version.

## Release candidates

A prerelease tag (`v0.1.0-rc.1`) exercises the whole path without publishing
the Homebrew cask: `prerelease: auto` detects it and `skip_upload: auto` skips
the cask for prereleases. Useful before a first release, or any release that
changes the pipeline.

The final tag goes on a *later* commit than its candidate. goreleaser is told
the triggering tag explicitly via `GORELEASER_CURRENT_TAG`, so two tags on one
commit no longer confuse it, but a release and its candidate pointing at the
same tree is confusing for people too.

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

## Versioning

[Semantic versioning](https://semver.org). No release has been cut yet, so the
first tag establishes the baseline. Until 1.0, minor versions may carry breaking
changes; patch versions do not.

**The bundle format has its own compatibility contract**, separate from the Go
API's version number. See [docs/compatibility.md](docs/compatibility.md) -- a
format change can reissue the identity of every artifact ever produced, which is
not something a patch version should be able to do.

When 1.0 arrives, this section gets rewritten with a real compatibility
commitment. Until then, pin exactly if you depend on this.

## If a release goes wrong

**The tag exists but the workflow failed.** Fix the problem on `main`, then cut
a new patch version. Do not delete and re-push the tag — someone may already
have consumed it, and a moving tag is worse than a skipped version number.
Version numbers are free.

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
