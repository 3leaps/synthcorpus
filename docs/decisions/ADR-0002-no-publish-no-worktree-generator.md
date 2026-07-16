# ADR-0002: generator no-publish and no-git-worktree posture

## Status

Accepted.

## Context

`synthcorpus-gen` can mint real throwaway key material. That is useful for local detector dogfooding and dangerous if treated as a normal published tool or run inside a repository.

## Decision

The generator is a repo-local development binary. It has no packaging metadata, release manifest, Homebrew path, or Scoop path. Full structural packaging checks land with the release-hardening brief, but this repository does not add a publishing route for the generator.

At runtime, the generator treats the output root as a security boundary:

- every existing path component is inspected with `lstat` first;
- the **named output root** (final component), if it exists, must not be a symlink — never mint or `--force`-delete through a retargetable final link;
- intermediate path components may resolve through symlinks (required for portability: e.g. macOS `/var` → `/private/var`), but the guard **canonicalizes** the existing prefix with `EvalSymlinks` and then performs git checks, marker reads, `MkdirAll`, and `RemoveAll` **only** on the realpath — it never retains a symlink-bearing pathname across the check→write window (closes TOCTOU retarget after check);
- after canonicalize, residual symlink components fail closed;
- git is the authority for repository detection via both `rev-parse --is-inside-work-tree` and `rev-parse --is-inside-git-dir` from the nearest existing **real** ancestor (covers worktrees, `<repo>/.git/...` descendants, and bare repositories; non-boolean output fails closed);
- the git-authority subprocess runs with inherited `GIT_*` environment removed, so caller state cannot redirect or disable the check;
- `--force` requires a bounded regular-file synthcorpus marker (not a symlink, FIFO, device, or other special file).

## Consequences

- The intended operating mode is local dogfooding, not distribution.
- Accidental writes into repositories fail before sidecars run.
- Replacement is marker-scoped instead of a blind recursive delete.
