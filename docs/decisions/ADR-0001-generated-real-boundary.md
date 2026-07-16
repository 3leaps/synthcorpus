# ADR-0001: generated-real and committed-synthetic boundary

## Status

Accepted.

## Context

synthcorpus has two different material classes:

- generated-real: real, throwaway cryptographic material minted on demand for detector dogfooding.
- committed-synthetic: scanner-safe fixtures that look like credential shapes but are provably unusable.

The repository exists because detector repos must not mint or commit real key material, even for tests.

## Decision

Generated-real material is produced only by `cmd/synthcorpus-gen` into an output root outside git, defaulting to `~/dev/dogfooding/<tool>`. The generator refuses to use an output path inside a git worktree and writes a synthcorpus ownership marker so `--force` can only replace directories it owns.

Committed fixtures, added in later briefs, must be synthetic by construction and must carry their own proof that they are not usable keys.

## Consequences

- Detector repos can test realistic key shapes without becoming key generators.
- Generated-real output is intentionally local, unversioned, and disposable.
- Review and CI focus first on the guardrail envelope before fixture breadth.
