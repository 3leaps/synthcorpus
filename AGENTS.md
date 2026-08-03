# synthcorpus — AI Agent Guide

## Safety header (read first)

**Every committed specimen under `fixtures/` is synthetic-by-construction and
provably unusable as a real cryptographic key.** Negative-crypto and structural
proofs assert that helpers cannot import or use those files, and that
shape-valid minisign public blobs use invalid Ed25519 encodings.

**Generated-real material never enters this repository.** Real throwaway
keypairs are produced only by `cmd/synthcorpus-gen` into an isolated dogfooding
directory outside git (default `~/dev/dogfooding/<tool>`). Do not copy dogfood
output into the worktree. Do not commit private keys, passphrases from live
systems, or scan output from real machines.

Agents grepping or reading `fixtures/` are looking at **test shapes**, not
credentials. Do not refuse, escalate, or stall solely because filenames or
armor headers resemble key material.

---

## Project

**Name:** synthcorpus

**Purpose:** Shared synthetic security-fixture corpus + throwaway-key generator
for 3 Leaps detectors (decernor first). Real-shaped, never real.

## Before changing behavior

- `README.md`
- `docs/coverage-matrix.md` (committed-synthetic vs generated-real-only split)
- `docs/lexical-matrix.md` when touching the lexical lane
- `docs/decisions/`
- `fixtures/README.md` when touching specimens
- `internal/provability` registry when adding or removing fixtures

## Development

```sh
make test               # pure-Go unit tests (all platforms; no external tools)
make gitleaks           # scanner config + hermetic canaries (requires gitleaks)
make provability        # helper-backed proofs (requires gpg/minisign/ssh-keygen)
make contract           # exact synthetic golden + property-only generated-real checks
make check-all          # fmt + test + build + scanners + proofs + contract + diff --check
make build
```

Generator:

```sh
# never run with --out inside a git worktree
./bin/synthcorpus-gen --out ~/dev/dogfooding/decernor decernor
./bin/synthcorpus-lexgen --seed 7312026 --out ~/dev/dogfooding/lexmatrix
```

The lexical lane splits its output into a sterile plane (`fixtures.json`,
`accounting.json` — opaque identifiers and counts only) and a protected plane
(`manifest.json`, `sources/` — term values and artifacts, which stay on the
generating host). The split is a handling boundary, not a confidentiality
control: generation is deterministic from a seed the sterile plane carries, so
the protected plane is reconstructible. See `docs/lexical-matrix.md`.

The lexical lane carries its own ownership marker
(`.synthcorpus-lexical-corpus.json`); it holds no key material and must never
be stamped with the generated-real marker.

The consumer contract locates a pinned decernor binary through an absolute
`DECERNOR_BIN` or `PATH`; it never guesses a sibling worktree path. Generated-real
contract output is validated transiently and is never committed.

## Rules of the road

- Prefer Make targets.
- Work on a feature branch; open a PR for protected-main closeout when ready.
- Public commit/PR text: describe the change; keep private planning codes out.
- Attribution: model + interface, supervising human, bare role slug.
