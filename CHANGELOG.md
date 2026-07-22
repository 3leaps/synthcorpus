# Changelog

All notable changes to synthcorpus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  and generator report version `0.1.0`; workflow and repository policy reject
  unreviewed publish paths and packaging metadata. Releases are signed tags plus
  notes, with no prebuilt generator binary, package-manager artifact, separately
  attached corpus bundle, artifact signature or key, checksum manifest, or
  provenance asset. GitHub's automatic source archives contain only repository
  content and therefore no generated-real material.

### Security

- Generated-real material never enters the repository. Only registered,
  provably unusable committed-synthetic specimens live under `fixtures/`.
- The generator rejects Git worktrees and Git directories, stages output before
  publication, and restricts replacement to synthcorpus-owned directories.

[Unreleased]: https://github.com/3leaps/synthcorpus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/3leaps/synthcorpus/releases/tag/v0.1.0
