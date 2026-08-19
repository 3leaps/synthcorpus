# Changelog

All notable changes to synthcorpus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Lexical-mutation corpus generator.** A second lane produces deterministic
  synthetic corpora for benchmarking term matching. Terms are an immutable
  `zzlx` anchor plus a seed-derived base32 body, and transforms touch only the
  body, so every generated string stays visibly synthetic. Seven surfaces and
  fourteen mutation classes populate a 49-cell matrix under enforced population
  floors; `synthcorpus-lexgen` writes it, and `docs/lexical-matrix.md` documents
  the grammar, cells, floors, and output planes.
- **Sterile and protected output planes.** A generated corpus separates opaque
  identifiers, answer-key coordinates, and digests from term values and the
  artifacts a detector scans, with the former referencing the latter by SHA-256
  alone. The split is a handling boundary, not a confidentiality control:
  generation is deterministic from a seed the sterile plane carries.
- **Generation-time correctness guards.** A positive case whose rendered
  variant is byte-identical to the unmutated term is rejected, as is a term
  value that collides with another term or contains a common word. Population
  floors fail the run rather than emitting a thin corpus.

### Changed

- **Decernor consumer pin is tagged `v0.1.3`.** Exact committed-synthetic
  fingerprint goldens track that binary (`fb19564`): GPG success records carry
  `key_role`, and minisign public-blob SHA-256 is lowercase hex. Locate remains
  `DECERNOR_BIN` / PATH.
- **Per-generator output-root ownership markers.** Each generator owns a
  distinct marker file and kind, so `--force` can only replace a root its own
  lane created, and a corpus holding no key material is no longer labelled with
  the marker that locates key-bearing roots. The marker kind is the
  authorization attribute; the tool field is provenance only.
- The release checklist gates the version identity of every shipped binary.

## [0.1.0] - 2026-07-22

**Synthetic Security Fixtures with Provable Boundaries**

### Added

- **Committed-synthetic security fixtures.** Real-shaped GPG, minisign, SSH,
  and malformed specimens are synthetic by construction and backed by
  structural and negative-crypto proofs.
- **Isolated generated-real minting.** `synthcorpus-gen` creates throwaway real
  key material only in guarded dogfooding directories outside Git worktrees.
- **Decernor consumer contracts.** A locate-by-binary pin, deterministic golden
  fingerprints for committed fixtures, and property-only generated-real checks
  detect consumer drift without committing real key material.
- **Cross-platform guardrail CI.** Ubuntu and macOS run the complete default Go
  lane and prove guardrail tests execute without skips; a separate redacted
  Gitleaks lane scans the tree and runs hermetic scanner canaries.
- **Declared platform coverage.** A machine-checked five-platform matrix
  separates required coverage from observed execution. Only active lanes count;
  blocked, deferred, and excluded states require a missing capability, reason,
  and lift condition instead of silent skips or emulation.
- **Release identity and structural no-publish enforcement.** The repository
  and generator report version `0.1.0`; workflow policy rejects capabilities
  outside its exact allowed set, and repository policy forbids defined packaging
  and release-automation surfaces. Releases are signed tags plus notes, with no
  prebuilt generator binary, package-manager artifact, separately attached
  corpus bundle, artifact signature or key, checksum manifest, or provenance
  asset. GitHub's automatic source archives contain only repository content and
  therefore no generated-real material.

### Security

- Generated-real material never enters the repository. Only registered,
  provably unusable committed-synthetic specimens live under `fixtures/`.
- The generator rejects Git worktrees and Git directories, stages output before
  publication, and restricts replacement to synthcorpus-owned directories.

[Unreleased]: https://github.com/3leaps/synthcorpus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/3leaps/synthcorpus/releases/tag/v0.1.0
