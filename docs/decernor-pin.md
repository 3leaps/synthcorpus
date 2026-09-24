# decernor consumer pin (drift-check soft path)

synthcorpus depends on **decernor as a binary consumer only** — never a sibling
worktree path, never a Go module import from decernor into synthcorpus.

## Pin (current)

| Field | Value |
|-------|-------|
| Source | https://github.com/3leaps/decernor |
| Min version | `0.1.8` |
| Preferred tag | `v0.1.8` |
| Preferred commit | `08c0afc` (commit peeled from the annotated tag; fingerprint contracts remain separate) |
| Machine pin file | [`manifests/decernor-pin.json`](../manifests/decernor-pin.json) |

The **tag** is the locate contract. `preferred_commit` records the tagged
object (minimum 7 hex characters; identity must equal the pin or be a longer
extension of it). Track the shipping tagged cut. Refresh exact goldens only
when fingerprint output changes.

## Locate rules (one-way dependency)

1. Use an explicit absolute binary path when the caller provides one.
2. Else use **`THREELEAPS_SYNTHCORPUS_DECERNOR_BIN`**, then **`DECERNOR_BIN`**.
   Both must be absolute paths. The pin keeps the legacy `env` field and adds
   `env_order` for this priority.
3. Else search **`PATH`** for `decernor`.

A non-empty higher-priority value that is relative, missing, or otherwise
unusable fails the lookup; it never falls through to another environment
variable or `PATH`. Identity checking still rejects a binary below the pinned
version or at the wrong commit.

Verify identity with extended version output (never parse secret material):

```sh
"$THREELEAPS_SYNTHCORPUS_DECERNOR_BIN" version -e
# Version: 0.1.8
# Commit:  08c0afc
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
THREELEAPS_SYNTHCORPUS_DECERNOR_BIN=/absolute/path/to/decernor make contract
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
