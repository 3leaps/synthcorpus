# ADR-0003: golden-manifest split (exact synthetic vs property generated-real)

## Status

Accepted and implemented.

## Context

Generated-real keys are random by design. Exact committed goldens over them
would flake or pressure operators to commit real material. Committed-synthetic
fixtures are stable and must prove they are unusable as real keys.

## Decision

1. **Committed-synthetic → exact, committed goldens** pinned against a declared
   decernor version/commit (see `manifests/decernor-pin.json`).
2. **Generated-real → property checks only** — record counts, expected schemes,
   null+reason cases, path_mode hygiene. Never commit exact fingerprints.
3. **Locate decernor by built binary + declared version** (`DECERNOR_BIN` or
   `PATH`). Never resolve via sibling path (`../decernor`).
4. The committed-synthetic contract compares raw newline-terminated NDJSON
   bytes. Its manifest declares the relative path mode, stable record ordering,
   timestamp absence, expected record count, output path, and SHA-256 digest;
   the verifier performs no hand-normalization.
5. The generated-real contract mints into an isolated temporary root and checks
   only schema, record/scheme counts, fail-closed reasons, canonical value
   encodings, and relative-path hygiene. It never persists detector output.

## Consequences

- The local/CI contract fails closed on committed-synthetic byte drift.
- Dogfood/ceremony evidence stays local under dogfooding roots.
- Detector repos remain free of key-minting responsibilities.
