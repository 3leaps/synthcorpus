# Release Notes

This file contains release notes for up to the three most recent releases in reverse chronological order. For the complete release history, see the [CHANGELOG](CHANGELOG.md) or the [docs/releases/](docs/releases/) directory.

---

## v0.1.6 (2026-10-13)

**GnuPG agent key specimens and a Decernor verdict contract**

synthcorpus v0.1.6 adds committed-synthetic GnuPG agent key specimens, an
expected-verdict manifest for them, and a contract lane that checks a pinned
Decernor binary against that manifest. The Decernor pin moves to `v0.1.9`.

### Highlights

- `fixtures-agent/` holds placeholder-only agent key specimens: plaintext,
  passphrase-protected, smartcard and TPM shadow stubs, malformed forms,
  keyring-internal files, and benign look-alikes.
- `manifests/decernor-scan-verdicts.json` (v0) gives each specimen's class,
  placement, expected `scan` finding per profile, and expected `guardread`
  verdict. Expectations come from the key format and class intent, not from
  detector output.
- `make verdict-check`, part of `make contract`, runs the pinned binary over
  every specimen and checks the expected findings, guardread verdicts, and
  class rules.
- The generated-real contract expects Decernor v0.1.9's two null
  `unsupported-kind` agent key records and fails if either carries a
  fingerprint.
- The minimum Go version is 1.26.9. Repository and both generators report
  version `0.1.6`.

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens are committed.

### Compatibility

Consumer contract callers must supply a Decernor binary satisfying
`manifests/decernor-pin.json` (`v0.1.9` / `43f57d9`).

See [docs/releases/v0.1.6.md](docs/releases/v0.1.6.md) for the complete release
narrative.

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
