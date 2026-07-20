# fixtures/ — committed-synthetic only

All files here are **synthetic-by-construction** and covered by negative-crypto
tests (`internal/provability`). They are intentionally unusable as real keys.

- **Do not** replace them with generated-real dogfood output.
- **Do not** expect `gpg` / `minisign` / `ssh-keygen` to import or use them.
- Layout follows `docs/coverage-matrix.md`.
- Exact decernor output is pinned by
  `manifests/decernor-fingerprint-golden.json`; any consumer drift must be
  reviewed rather than regenerated silently.

| Path | Intent |
|------|--------|
| `minisign/public-complete.pub` | Complete 42-byte Ed shape with **invalid Ed25519** public component (dual fingerprint schemes) |
| `minisign/public-malformed.pub` | Historical public marker without complete structure → `parse-unsupported` |
| `minisign/secret-truncated.key` | Secret-shaped unusable body |
| `ssh/id_ed25519.pub` | Public line with invalid key material |
| `ssh/id_ed25519` | OpenSSH private armor, invalid body |
| `gpg/public.asc` | Public armor that fails import |
| `gpg/private.asc` | Private armor that fails import |
| `gpg/revocation.asc` | Revocation path signal + unusable armor |
| `malformed/*` | Cross-kind truncated edges |
