# Release Checklist

synthcorpus releases are annotated Git tags plus GitHub release notes. The
repository does not publish a prebuilt generator binary, package-manager
artifact, separately attached corpus bundle, signature, key, checksum manifest,
or provenance asset. GitHub's automatic source archives are expected; they
contain the committed repository, including the committed-synthetic corpus,
and no generated-real material. This intentionally follows
[`docs/decisions/ADR-0002-no-publish-no-worktree-generator.md`](docs/decisions/ADR-0002-no-publish-no-worktree-generator.md).

## 1. Quality gates

- [ ] Confirm all release changes are merged to `main` and the worktree is clean.
- [ ] Run the complete local gate with the pinned consumer binary:

  ```sh
  DECERNOR_BIN=/absolute/path/to/decernor make check-all
  ```

- [ ] Confirm the required `basic-ubuntu`, `basic-macos`, and `gitleaks` checks
      pass on the release commit.

## 2. Release identity and documentation

- [ ] Confirm `VERSION` contains the intended version without a `v` prefix.
- [ ] Build the generator and confirm its version matches `VERSION`:

  ```sh
  make build
  test "$(./bin/synthcorpus-gen -version)" = "$(tr -d '\n' < VERSION)"
  ```

- [ ] Confirm the release date, headline features, compatibility notes, and
      no-publish posture agree across:
  - [ ] the release section in `CHANGELOG.md`;
  - [ ] the current entry in `RELEASE_NOTES.md`;
  - [ ] `docs/releases/v<version>.md`.
- [ ] At tag time, replace every `2026-NN-NN` placeholder and confirm all three
      release surfaces use the actual calendar date on which the tag is created.
- [ ] Confirm every bracketed release version in `CHANGELOG.md` has a footer
      link definition and `[Unreleased]` compares the release tag to `HEAD`.
- [ ] Confirm every release surface uses capability-only, public-reader wording
      and makes no unsupported future commitment.

## 3. No-publish sanity sweep

- [ ] Confirm the repository still contains no packaging configuration or
      package-manager publication surface:

  ```sh
  find . -path './.git' -prune -o \
    \( -name '.goreleaser*' -o -path '*/Formula/*' -o \
       -path '*/bucket/*.json' -o -name 'package.json' -o \
       -name 'pyproject.toml' \) -print
  ```

  Expected output: empty.

- [ ] Confirm no workflow publishes a prebuilt generator binary,
      package-manager artifact, separately attached corpus bundle, signature,
      key, checksum manifest, or provenance asset.
- [ ] Confirm no files will be uploaded to the release. GitHub's automatic
      source archives are expected and contain no generated-real material.

## 4. Tag and release notes

- [ ] Confirm the tag matches `VERSION`:

  ```sh
  release_version="$(tr -d '\n' < VERSION)"
  test "v${release_version}" = "v0.1.0"
  ```

- [ ] Create and push the annotated tag:

  ```sh
  git tag -a v0.1.0 -m "v0.1.0 — synthetic fixtures with provable boundaries"
  git push origin v0.1.0
  ```

- [ ] Create the GitHub release from `RELEASE_NOTES.md` without uploading files:

  ```sh
  gh release create v0.1.0 --title "synthcorpus v0.1.0" \
    --notes-file RELEASE_NOTES.md
  ```

- [ ] Confirm the release has zero uploaded assets. GitHub's automatic source
      archives are not included in the `assets` API field:

  ```sh
  test "$(gh release view v0.1.0 --json assets --jq '.assets | length')" -eq 0
  ```

## 5. Post-release housekeeping

- [ ] Confirm the tag and GitHub release resolve to the intended `main` commit.
- [ ] Confirm the three required checks remain green on that commit.
- [ ] Verify `[Unreleased]` in `CHANGELOG.md` starts from `v0.1.0`.
- [ ] Keep only the three most recent entries in `RELEASE_NOTES.md`; retain the
      complete per-release narrative under `docs/releases/`.
