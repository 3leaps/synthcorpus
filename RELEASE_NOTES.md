# Release Notes

This file contains release notes for up to the three most recent releases in reverse chronological order. For the complete release history, see the [CHANGELOG](CHANGELOG.md) or the [docs/releases/](docs/releases/) directory.

---

## v0.1.0 (2026-07-22)

**Synthetic Security Fixtures with Provable Boundaries**

synthcorpus v0.1.0 provides a shared, real-shaped security-fixture corpus for
detectors while keeping real credentials out of Git. The initial release pairs
provably unusable committed fixtures with an isolated throwaway-key generator
for the cases that require genuine cryptographic structure.

### Highlights

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

### Governing invariant

Generated-real material never enters the repository. Only registered,
provably unusable committed-synthetic specimens live under `fixtures/`.

### Compatibility

This is the initial release. There is no upgrade or migration requirement.
The generator remains a repository-local dogfooding tool and is not distributed.

See [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md) for the complete release
narrative.
