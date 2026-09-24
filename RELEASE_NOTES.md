# Release Notes

This file contains release notes for up to the three most recent releases in reverse chronological order. For the complete release history, see the [CHANGELOG](CHANGELOG.md) or the [docs/releases/](docs/releases/) directory.

---

## v0.1.5 (2026-09-24)

**Decernor v0.1.8 consumer pin and binary lookup order**

synthcorpus v0.1.5 pins its Decernor consumer contract to published `v0.1.8`
at peeled commit `08c0afc`. The committed-synthetic goldens, fixture content,
and generated-real boundary are unchanged.

### Highlights

- Binary lookup uses an explicit absolute path, then
  `THREELEAPS_SYNTHCORPUS_DECERNOR_BIN`, `DECERNOR_BIN`, and `PATH`. A non-empty
  explicit or environment choice that is unusable fails without fallback.
- Exact committed-synthetic goldens and transient generated-real properties
  pass against Decernor `v0.1.8`; no golden refresh was needed.
- Go remains at 1.26.6, with `edwards25519` v1.2.0 and YAML v3.0.5. No module
  update was available.
- Repository and both generators report version `0.1.5`. The release vehicle
  remains a signed Git tag plus notes, with zero uploaded assets.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

Consumer contract callers must supply a Decernor binary satisfying
`manifests/decernor-pin.json` (`v0.1.8` / `08c0afc`). The legacy
`DECERNOR_BIN` variable remains supported after the repo-scoped variable.

See [docs/releases/v0.1.5.md](docs/releases/v0.1.5.md) for the complete release
narrative.

## v0.1.4 (2026-09-18)

**Patched Go baseline and Decernor v0.1.7 consumer pin**

synthcorpus v0.1.4 moves to Go 1.26.6, updates YAML to v3.0.5, and pins the
Decernor consumer contract to published `v0.1.7` at peeled commit `70efa26`.
The corpus, schemas, and expected fingerprint records are unchanged.

### Highlights

- **Decernor consumer pin is tagged `v0.1.7`.** Exact committed-synthetic
  goldens remain byte-identical; generated-real checks remain transient. Locate
  remains an absolute `DECERNOR_BIN` or `PATH` lookup.
- **Go 1.26.6** clears the standard-library advisories applicable to the prior
  Go 1.26.4 baseline.
- **YAML v3.0.5** provides the available direct dependency patch;
  `edwards25519` remains at v1.2.0.
- Repository and both generators report version `0.1.4`. Releases remain
  GPG-signed tags plus notes, with zero uploaded assets.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

No migration is required. Consumer contract callers must supply a Decernor
binary satisfying `manifests/decernor-pin.json` (`v0.1.7` / `70efa26`).

See [docs/releases/v0.1.4.md](docs/releases/v0.1.4.md) for the complete release
narrative.

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
