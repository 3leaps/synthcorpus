# Release Notes

This file contains release notes for up to the three most recent releases in reverse chronological order. For the complete release history, see the [CHANGELOG](CHANGELOG.md) or the [docs/releases/](docs/releases/) directory.

---

## v0.1.3 (2026-08-25)

**Decernor v0.1.5 pin and public baseline**

synthcorpus v0.1.3 pins the Decernor consumer contract to tagged `v0.1.5`,
adds link-only community stubs, and cleans public examples so they do not
advertise a host layout path. Generated-real material still never enters Git.
Releases remain signed tags plus notes. Early scaffold commits are historical;
the current tree is the public contract.

### Highlights

- **Decernor consumer pin is tagged `v0.1.5`.** Machine pin and docs name
  `0.1.5` / `v0.1.5` / `5dfd574`. Exact committed-synthetic fingerprint
  goldens track that binary. Fingerprint output is unchanged from the prior
  tagged cut; goldens are not rewritten. Locate remains `DECERNOR_BIN` / PATH.
- Link-only `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and `SECURITY.md` point at
  `3leaps/oss-policies` (no forked policy bodies).
- Generator help and public examples use `--out /path/to/isolated-root` or
  `$SYNTHCORPUS_OUT`; they no longer advertise a host path.
- Repository and generator report version `0.1.3`. No-publish posture is
  unchanged: no prebuilt generator binary or attached corpus bundle.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

No migration is required. Consumer contract callers must supply a Decernor
binary that satisfies `manifests/decernor-pin.json` (`v0.1.5` / `5dfd574`).

See [docs/releases/v0.1.3.md](docs/releases/v0.1.3.md) for the complete release
narrative.

## v0.1.2 (2026-08-20)

**MIT license**

synthcorpus v0.1.2 adds a root MIT `LICENSE` (copyright 2025-2026 3 Leaps, LLC)
and a README license pointer. Generated-real material still never enters Git.
Releases remain signed tags plus notes.

### Highlights

- Root `LICENSE` is MIT. `NOTICE.md` restates the copyright and points at that
  file. README `## License` links it. The MIT License applies to earlier tagged
  source as well; v0.1.2 is the first tag whose automatic source archive
  includes the `LICENSE` file.
- Repository and generator report version `0.1.2`. No-publish posture is
  unchanged: no prebuilt generator binary or attached corpus bundle.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

No migration is required. The Decernor consumer pin remained tagged `v0.1.4`
for that cut.

See [docs/releases/v0.1.2.md](docs/releases/v0.1.2.md) for the complete release
narrative.

## v0.1.1 (2026-08-20)

**Lexical lane and tagged Decernor pin**

synthcorpus v0.1.1 adds a second generator lane for deterministic
lexical-mutation corpora and pins the Decernor consumer contract to tagged
`v0.1.4`. Generated-real material still never enters Git.

### Highlights

- **Lexical-mutation corpus generator.** `synthcorpus-lexgen` emits a 49-cell
  matrix of visibly synthetic terms (`zzlx` plus a seed-derived body) with
  sterile and protected output planes. Population floors and generation-time
  guards fail the run rather than emit a thin or colliding corpus.
- **Decernor consumer pin is tagged `v0.1.4`.** Exact committed-synthetic
  fingerprint goldens track that binary. Locate remains `DECERNOR_BIN` / PATH.
  Fingerprint output is unchanged from the prior tagged cut; goldens are not
  rewritten.
- **Per-generator ownership markers.** Each generator owns a distinct marker
  file and kind so `--force` can only replace a root its own lane created.
- Repository and generator report version `0.1.1`. Releases remain signed tags
  plus notes, with no prebuilt generator binary or attached corpus bundle.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

No migration is required. The generator remains a repository-local dogfooding
tool and is not distributed. Consumer contract callers must supply a Decernor
binary that satisfies `manifests/decernor-pin.json` (`v0.1.4` / `32d0176`).

See [docs/releases/v0.1.1.md](docs/releases/v0.1.1.md) for the complete release
narrative.
