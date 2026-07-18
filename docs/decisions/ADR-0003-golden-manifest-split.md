# ADR-0003: golden-manifest split (exact synthetic vs property generated-real)

## Status

Accepted (soft path) — pin + locate contract landed for the drift-check consumer
leg; exact goldens wait on committed-synthetic fixtures.

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

## Consequences

- Drift CI can fail closed on synthetic golden divergence once synthetic
  fixtures exist.
- Dogfood/ceremony evidence stays local under dogfooding roots.
- Detector repos remain free of key-minting responsibilities.
