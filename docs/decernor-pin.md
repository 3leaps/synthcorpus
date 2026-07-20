# decernor consumer pin (drift-check soft path)

synthcorpus depends on **decernor as a binary consumer only** — never a sibling
worktree path, never a Go module import from decernor into synthcorpus.

## Pin (current)

| Field | Value |
|-------|-------|
| Source | https://github.com/3leaps/decernor |
| Min version | `0.1.1` |
| Preferred commit | `8ca1555` (includes minisign public-blob detection and fail-closed GPG revocation mapping) |
| Machine pin file | [`manifests/decernor-pin.json`](../manifests/decernor-pin.json) |

Until decernor cuts a release tag suitable for CI, the **commit SHA** is the
primary pin (minimum 7 hex characters; identity must equal the pin or be a
longer extension of it). Flip to tag pinning when the first tagged release ships.

## Locate rules (one-way dependency)

1. Prefer **`DECERNOR_BIN`** (absolute path to a built `decernor` binary).
2. Else search **`PATH`** for `decernor`.
3. Refuse relative/`../decernor` guesses. Callers must pass an explicit binary.

Verify identity with extended version output (never parse secret material):

```sh
"$DECERNOR_BIN" version -e
# Version: 0.1.1
# Commit:  8ca1555
```

Package helper: `internal/decernorloc` (`Locate`, `ReadIdentity`, `CheckPin`).
Empty/`unknown` commits and malformed versions fail closed.

## Contract lanes

| Lane | Contract |
|------|----------|
| Committed-synthetic | Raw NDJSON bytes match `manifests/decernor-fingerprint-v0.ndjson`; manifest header fixes relative paths, stable ordering, timestamp absence, record count, and digest |
| Generated-real | Transient output satisfies schema, count/scheme, canonical encoding, null+reason, and relative-path properties; no random fingerprint is persisted |

Run both against the declared binary:

```sh
DECERNOR_BIN=/absolute/path/to/decernor make contract
```

## Generated-real property checks (no exact fingerprints)

When exercising a dogfood corpus from `synthcorpus-gen`:

- Minisign complete public keys emit **two** records: `minisign-key-id-v1` and
  `minisign-public-blob-sha256-v1` (non-canonical untrusted-comment OK).
- GPG revocation certificates emit `class=other`, `fingerprint=null`,
  `reason=unsupported-kind` (not `helper-unavailable`).
- Paths honor the selected `path_mode` (never absolute on default relative mode
  for walk roots).
- Never commit generated-real fingerprints or captured detector output into this repository.
