# Lexical-mutation matrix v1

The lexical lane generates synthetic term-matching benchmark corpora: a fixed
matrix of surfaces and transform classes, populated deterministically from a
seed, with a machine-checked answer key.

It shares synthcorpus's central discipline with the crypto lanes — everything
committed here is synthetic by construction, and the generator's output is
written outside any git worktree.

## Grammar: `synthlex-v1`

Every term is an immutable `zzlx` anchor followed by a seed-derived base32
body. Transforms only ever touch body scalars, so a mutated variant is still
greppable as synthetic:

```
zzlxq3vy          term          (anchor + body, two tokens)
zzlxq3 VY         case variant  (body upper-cased, anchor untouched)
```

Two exceptions to the anchor rule are deliberate:

| Shape | Why |
|-------|-----|
| Common-word decoys | A negative control has to look like an ordinary word |
| Below-policy-length terms (1–3 scalars) | Too short to hold a full anchor; they carry a prefix of one (`z`, `zz`, `zzl`) |

Generated terms are checked against a public common-word list, so a grammar
change that starts producing word-like output fails the run rather than
landing quietly.

## The matrix

Seven surfaces, each with its own transform classes and severity mix:

| Surface | Transform classes | Severity mix |
|---------|-------------------|--------------|
| `prose` | case, separator, plural, insertion, deletion, substitution, transposition, token_split, token_join | medium/high/critical |
| `path` | case, separator, insertion, deletion, substitution, token_join | high/critical |
| `camel_case` | case, separator, insertion, deletion, substitution, token_join | high/critical |
| `snake_case` | case, separator, insertion, deletion, substitution, transposition, truncation | high |
| `kebab_case` | case, separator, insertion, deletion, substitution, transposition | high |
| `config_value` | case, separator, insertion, deletion, substitution, token_join | high |
| `commit_message` | case, separator, plural, insertion, deletion, substitution, transposition, token_split, token_join | medium/high/critical |

That is **49 required cells**. Six of them carry a pinned severity rather than
the surface rotation: `prose × token_split`, `prose × token_join`,
`camel_case × token_join` and `commit_message × transposition` are critical;
`snake_case × truncation` and `path × token_join` are high.

Unicode classes, vowel-drop, and truncation on surfaces other than
`snake_case` are implemented but sit outside the required matrix.
`--include-extensions` emits them, marked as extension scope. Truncation is the
one class that is required on one surface and an extension on four others
(`path`, `camel_case`, `kebab_case`, `config_value`).

## Population floors

Enforced at generation time — a run that cannot meet them fails rather than
emitting a thin corpus:

| Floor | Value |
|-------|-------|
| Positives per cell | 12 |
| Distinct terms per cell | 4 |
| Distinct scalar bands per cell | 2 |
| Duplicate/concentration clusters per cell | 1 |
| Negative controls per surface | 6 |
| Below-policy-length cases per surface | 12 |

A default run produces 721 cases: 588 positives, 49 non-length negative
controls, and 84 below-policy-length cases.

## Reading the answer key

`min_findings` and `max_findings` are scoped **per case**, not per source
artifact. A case declares what a detector should report for the spans that case
owns.

This matters for clusters. Each cell's duplicate/concentration cluster puts
three identical occurrences into one artifact and emits three cases that share a
`source_id`, each declaring one span and `min = max = 1`. Scanning that artifact
yields three findings in total, which is correct: one per case. A runner that
totals findings per *source* and compares against a single case's bounds will
fail every cluster case in every cell.

## Lanes

`case` and `separator` differences survive normalization, so an exact matcher
is expected to catch them — those cells are the **deterministic** lane. Every
other transform needs approximate matching. Negative controls form their own
lane and never declare a finding.

A subset of deterministic-lane cases on surfaces whose mix includes critical
are flagged `critical_seed`: the answer key asserts these are never missed.

## Output

```sh
./bin/synthcorpus-lexgen --seed 7312026 --out ~/dev/dogfooding/lexmatrix
```

| Flag | Effect |
|------|--------|
| `--seed` | Fixes every derived choice. Any 32-bit value works. |
| `--out` | Output root. Must not be inside a git worktree. |
| `--force` | Replace an existing root — only one this lane created. |
| `--include-extensions` | Add the non-required cells, marked extension scope. |
| `--profile` | **Label only.** Recorded as `profile` in the fixture set because the contract carries the field; it does not change what is generated. All three values produce identical corpora at the same seed. |

The replacement is built alongside the target and swapped in once complete, so
an interrupted run leaves the previous corpus intact.

The output root must not be inside a git worktree — the same guard the
generated-real lane uses. It contains:

| File | Plane | Contents |
|------|-------|----------|
| `fixtures.json` | sterile | Opaque identifiers, answer-key coordinates, digests |
| `manifest.json` | protected | Term values and source-artifact resolution |
| `sources/*.txt` | protected | The artifacts a detector actually scans |
| `accounting.json` | sterile | Per-cell and per-surface floor evidence |

`fixtures.json` and `accounting.json` are the sterile plane: they carry opaque
identifiers, coordinates and counts, never a term value or a variant.
`manifest.json` and `sources/` are the protected plane and stay on the
generating host. The fixture set references the manifest by SHA-256 alone, so a
consumer can prove which manifest an answer key belongs to without holding the
manifest itself.

**The split is a handling boundary, not a confidentiality control.** Generation
is deterministic from the seed, the seed travels in the sterile plane
(`generator.seed`, and again inside `fixture_set_id`), and this generator is
open source — so anyone holding `fixtures.json` can reconstruct the protected
manifest byte-for-byte, digest included. Treat the sterile plane as safe to move
because of what it *contains*, not because it withholds anything a determined
reader could not regenerate. A corpus whose terms must genuinely stay secret
cannot be produced by seed-deterministic generation alone.

## Determinism

The same seed and generator version always produce a byte-identical output
tree. No wall-clock, no PRNG: every choice is derived from a SHA-256 over the
seed and a stable label path, so digests are reproducible across machines and
Go releases. Change generated output and you must bump `GeneratorVersion`.
