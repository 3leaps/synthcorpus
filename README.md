# synthcorpus — real-shaped, never real.

▎ The shared synthetic-fixture corpus for the 3 Leaps galaxy's security detectors.

## Elevator

synthcorpus is the shared, synthetic security-fixture corpus for the 3 Leaps galaxy's detectors — decernor first, seclusor and others next. It commits provably-bogus, scanner-safe specimens of GPG, minisign, and SSH key material — including the passphrase-protected and deliberately-malformed shapes detectors trip on — plus golden manifests pinned against the real tool's output. For the cases that demand actual cryptographic material, it ships an on-demand generator that produces real-but-throwaway keypairs into an isolated dogfooding area that is never a git repo and never committed. The whole design turns on one line: generated-real material stays out of git; only synthetic fixtures land in the tree. That keeps a detector like decernor honest — provable against realistic, every-shape key material, without a single real credential ever entering a repo.

---

One-line: Synthetic, scanner-safe security-fixture corpus + throwaway-key generator for 3 Leaps detectors (decernor, seclusor). Real-shaped, never real.

## Layout (quick)

| Path | Role |
|------|------|
| `fixtures/` | **Committed-synthetic only** — provably unusable; see `fixtures/README.md` |
| `docs/coverage-matrix.md` | Per-(kind × class) synthetic vs generated-real-only split |
| `ci/platforms.json` | Five-platform obligations plus machine-checked observed execution states |
| `cmd/synthcorpus-gen` | Generated-real mint (dogfooding roots only; never inside git) |
| `cmd/synthcorpus-lexgen` | Lexical-mutation corpus generator (same never-inside-git rule) |
| `docs/lexical-matrix.md` | Lexical-mutation matrix v1 — grammar, cells, floors, output planes |
| `manifests/decernor-pin.json` | Consumer pin for drift-check locate-by-binary (tagged decernor `v0.1.4`) |
| `docs/releases/` | Per-cut notes; current pack is [`v0.1.2`](docs/releases/v0.1.2.md) |
| `manifests/decernor-fingerprint-golden.json` | Deterministic committed-synthetic fingerprint contract |
| `manifests/decernor-generated-real-properties.json` | Property-only generated-real contract (no exact random values) |
| `AGENTS.md` | Agent guide — **safety header first** |

```sh
make check-all
DECERNOR_BIN=/absolute/path/to/decernor make contract
./bin/synthcorpus-gen --out ~/dev/dogfooding/decernor decernor   # outside this repo
```

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
