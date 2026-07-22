# Release Checklist

synthcorpus releases are GPG-signed Git tags plus GitHub release notes. Version
tag refs are protected by an active repository ruleset; an authorized
organization administrator creates and pushes each release tag through that
ruleset. The repository does not publish a prebuilt generator binary,
package-manager artifact, separately attached corpus bundle, artifact signature
or key, checksum manifest, or provenance asset. GitHub's automatic source
archives are expected; they contain the committed repository, including the
committed-synthetic corpus, and no generated-real material. This intentionally
follows
[`docs/decisions/ADR-0002-no-publish-no-worktree-generator.md`](docs/decisions/ADR-0002-no-publish-no-worktree-generator.md).

## Release environment

The maintainer loads the signing identity from the operator-private release
environment and sets the release tag and literal check-verified commit. The
dedicated keyring must remain outside every Git worktree.

- `THREELEAPS_SYNTHCORPUS_RELEASE_TAG`: the intended `vMAJOR.MINOR.PATCH` tag;
- `THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT`: the full lowercase 40-hex commit SHA
  on which the release gates and hosted checks passed;
- `THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR`: the dedicated release-signing keyring;
- `THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT`: the full uppercase 40-hex
  primary fingerprint that independently authorizes the release identity;
- `THREELEAPS_SYNTHCORPUS_PGP_KEY_ID`: an exact signing-subkey selector: either
  its uppercase 16-hex key ID or full uppercase 40-hex fingerprint, followed by
  `!` so GnuPG cannot silently select a different signing subkey;
- `THREELEAPS_SYNTHCORPUS_TAGGER_NAME`: the tagger name associated with the
  signing identity;
- `THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL`: a tagger email present on the signing
  key and verified for the publishing account.

To discover the primary and signing-subkey identifiers from the dedicated
keyring without exporting key material, run:

```sh
GNUPGHOME="$THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR" \
  gpg --keyid-format long \
      --with-subkey-fingerprint \
      --list-secret-keys
```

Use the full fingerprint printed beneath the `sec` record as the independent
primary authorization value. Choose an unexpired `ssb` record carrying `[S]`,
then use either its long key ID from the `ssb` line or its full fingerprint from
the following line, with `!` appended as the exact selector. For example:

```sh
export THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT='<40-hex-primary-fingerprint>'
export THREELEAPS_SYNTHCORPUS_PGP_KEY_ID='<16-or-40-hex-signing-subkey-id>!'
```

The guard requires the selected signing subkey to belong to the independently
authorized primary and rejects disabled, expired, revoked, invalid, or
non-signing key records.

Git release tags carry GPG signatures. This no-asset release creates no
minisign signature or uploaded key; minisign material is not part of this
ceremony.

## 1. Quality gates

- [ ] Confirm all release changes are merged to `main`; fetch and record the
      intended release commit; and confirm the clean checkout matches it:

  ```sh
  git fetch origin main
  gate_verified_commit="$(git rev-parse origin/main)"
  readonly gate_verified_commit
  printf 'release commit: %s\n' "$gate_verified_commit"
  test "$(git rev-parse HEAD)" = "$gate_verified_commit"
  test -z "$(git status --porcelain)"
  ```

- [ ] Run the complete local gate with the pinned consumer binary:

  ```sh
  DECERNOR_BIN=/absolute/path/to/decernor make check-all
  ```

- [ ] Confirm the required `basic-ubuntu`, `basic-macos`, and `gitleaks` checks
      pass on the recorded release commit.

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
- [ ] Confirm no `2026-NN-NN` placeholder remains and all three release surfaces
      use the actual calendar date on which the tag is created.
- [ ] Confirm every bracketed release version in `CHANGELOG.md` has a footer
      link definition and `[Unreleased]` compares the release tag to `HEAD`.
- [ ] Confirm every release surface uses capability-only, public-reader wording
      and makes no unsupported future commitment.

## 3. No-publish sanity sweep

- [ ] Run the durable repository policy gate:

  ```sh
  make policy
  ```

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
      package-manager artifact, separately attached corpus bundle, artifact
      signature or key, checksum manifest, or provenance asset.
- [ ] Confirm no files will be uploaded to the release. GitHub's automatic
      source archives are expected and contain no generated-real material.

## 4. Tag and release notes

- [ ] Confirm the tag matches `VERSION`:

  ```sh
  export THREELEAPS_SYNTHCORPUS_RELEASE_TAG="v$(tr -d '\n' < VERSION)"
  export THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT='<literal full SHA from the check-verified handoff>'
  readonly THREELEAPS_SYNTHCORPUS_RELEASE_TAG
  readonly THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT
  make release-guard-tag-version
  ```

- [ ] As the maintainer, load the operator-private release environment and
      validate all required variables and out-of-band paths without copying key
      material into the repository:

  ```sh
  source <operator-private-release-env>
  make release-guard-signing-env
  ```

- [ ] Confirm the active tag-protection ruleset covers only `refs/tags/v*`,
      blocks creation, update, deletion, and non-fast-forward changes, and
      permits only the authorized organization-administrator bypass:

  ```sh
  make release-guard-tag-ruleset
  ```

- [ ] Confirm the three required hosted checks are green on the recorded
      `THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT`. This literal full SHA is the
      verifier-to-maintainer handoff; never replace it with a newly resolved
      `HEAD` or `origin/main`. Keep the checkout unchanged through signing.
- [ ] As an authorized organization administrator, create the GPG-signed tag
      with out-of-band key material. The target validates the signing
      environment and live ruleset, embeds the ruleset-policy fingerprint,
      explicitly tags the check-verified commit, and verifies the annotated
      object directly targets that commit with type `commit`, plus the exact
      signing-subkey fingerprint and its primary-key relationship, tagger
      identity, policy attestation, and peeled target:

  ```sh
  make release-tag
  ```

- [ ] Push the signed tag through the protected-tag bypass. The push target
      rechecks the signature and signer, tagger identity, policy attestation,
      peeled target, live ruleset, clean checkout, and `origin/main` equality
      immediately before publication. This guarded split is intentional: it
      preserves the check-verified SHA across local signing and publication.

  ```sh
  make release-push-tag
  ```

- [ ] After the maintainer reports a successful push, return control to the
  release operator. Confirm GitHub reports the annotated tag signature as
  verified and its target as the literal check-verified release commit:

  ```sh
  export THREELEAPS_SYNTHCORPUS_RELEASE_TAG="v$(tr -d '\n' < VERSION)"
  export THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT='<same literal full SHA used by the maintainer>'
  make release-verify-remote-tag
  ```

- [ ] Create the GitHub release from `RELEASE_NOTES.md` without uploading files:

  ```sh
  gh release create "$THREELEAPS_SYNTHCORPUS_RELEASE_TAG" \
    --title "synthcorpus $THREELEAPS_SYNTHCORPUS_RELEASE_TAG" \
    --notes-file RELEASE_NOTES.md
  ```

- [ ] Confirm the release has zero uploaded assets. GitHub's automatic source
      archives are not included in the `assets` API field:

  ```sh
  test "$(gh release view "$THREELEAPS_SYNTHCORPUS_RELEASE_TAG" \
    --json assets --jq '.assets | length')" -eq 0
  ```

## 5. Post-release housekeeping

- [ ] Confirm the tag and GitHub release resolve to the intended `main` commit.
- [ ] Confirm the three required checks remain green on that commit.
- [ ] Verify `[Unreleased]` in `CHANGELOG.md` starts from `v0.1.0`.
- [ ] Keep only the three most recent entries in `RELEASE_NOTES.md`; retain the
      complete per-release narrative under `docs/releases/`.
