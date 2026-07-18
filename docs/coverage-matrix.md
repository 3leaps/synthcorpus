# Coverage matrix — committed-synthetic vs generated-real-only

This declaration freezes the per-(kind × class) split **before** the `fixtures/`
layout freezes. It is the first deliverable of the committed-fixture workstream.

| Lane | Definition | Git? | Proof style |
|------|------------|------|-------------|
| **committed-synthetic** | Scanner-safe, synthetic-by-construction shapes that look like detector targets but are **provably unusable** as real keys | Yes, under `fixtures/` | Closed inventory + pure-Go structural proofs; helper-backed negative-use on supported hosts |
| **generated-real-only** | Throwaway **real** crypto material required for high-fidelity shapes that cannot be made unusable without losing detector signal | No — only via `synthcorpus-gen` into dogfooding roots | Property checks only (never exact committed fingerprints) |

## Matrix (v0, decernor consumer)

Legend: **C** = committed-synthetic · **R** = generated-real-only

| Kind | Shape / class | Lane | Notes |
|------|---------------|------|-------|
| **minisign** | public (complete file: comment + single 42-byte Ed blob) | **C** | Blob retains Ed + 8-byte key-id + 32-byte public component, but the public component is a **provably invalid Ed25519 encoding** (rejected by `edwards25519.Point.SetBytes`). Dual fingerprint schemes still emit. |
| **minisign** | public malformed (historical marker without complete structure) | **C** | Emits decernor `fingerprint:null` / `reason=parse-unsupported` (not a public trust anchor). |
| **minisign** | private / secret filename or truncated body | **C** | Structural secret shape incomplete; cannot sign. |
| **minisign** | signature (valid for a real secret) | **R** | Needs a real keypair. |
| **minisign** | private protected (passphrase-encrypted secret) | **R** | Real minisign secret encryption. |
| **ssh** | public line with non-decodable blob | **C** | `ssh-keygen -l` fails. |
| **ssh** | OpenSSH private armor with invalid body | **C** | `ssh-keygen -y` fails. |
| **ssh** | encrypted OpenSSH private | **R** | Real encrypted private format. |
| **ssh** | valid plaintext private + matching public | **R** | Real keypair. |
| **gpg** | public armor that fails import with empty rings | **C** | After nonzero import, `--with-colons` lists show no pub/sec. |
| **gpg** | private armor that fails import with empty rings | **C** | Same. |
| **gpg** | revocation path + public armor (import fails, empty rings) | **C** | Filename/class signal for `unsupported-kind`. |
| **gpg** | valid public / private / multi-key bundle / detach-sig | **R** | Real OpenPGP packets. |
| **gpg** | passphrase-protected secret (S2K) | **R** | Real protection metadata. |
| **malformed** | truncated / edge specimens (cross-kind) | **C** | Explicit fail-closed detector paths. |

## Inventory authority

The closed file set under `fixtures/` is defined in
`internal/provability/registry.go`. Walks must match that registry exactly
(regular files only; no extras, no symlinks).

## Freezes

1. **Do not** add a committed fixture for a cell marked **R**.
2. **Do not** expand **C** cells into cryptographically valid importable keys without revisiting this matrix and dual review (secrev).
3. Golden manifests (exact decernor output) apply only to **C** cells once the drift-check workstream lands.

## Related

- ADR-0001 generated-real / committed-synthetic boundary
- ADR-0003 golden-manifest split
- `fixtures/README.md`
