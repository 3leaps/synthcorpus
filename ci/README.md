# CI platform policy

`platforms.json` is the machine-checked declaration of the five platforms in
the corpus coverage contract. It records desired coverage separately from
observed execution. A lane is counted as executed only when its state is
`active` and its exact command is present in the bound workflow job.

Current observed coverage:

| Platform | Runner | Sidecar-free | Committed golden | Generated-real |
|----------|--------|--------------|------------------|----------------|
| `linux-amd64` | active | active | blocked | blocked |
| `linux-arm64` | deferred | deferred | deferred | deferred |
| `darwin-arm64` | active | active | blocked | blocked |
| `windows-amd64` | deferred | deferred | deferred | excluded |
| `windows-arm64` | deferred | deferred | deferred | excluded |

Active runners bind to an exact workflow job ID and display name, runner label,
observed `GOOS`/`GOARCH` assertion, and lane command. Every blocked, deferred,
or excluded record carries its missing capability, reason, and lift condition;
verbose policy CI logs all of them. These states never count as executed
coverage and do not use skipped tests, soft failures, or emulation.

The workflow policy admits only the exact reviewed workflow, job, and ordered
step shapes. Checkout and Go setup are pinned to reviewed full commit SHAs with
exact inputs. Run steps have exact shell and environment rules, all required
jobs and steps are unconditional, and shell commands match an exact allowlist.
The parser also rejects duplicate keys, aliases, privilege broadening, secret
contexts, whole GitHub context access, and unreviewed GitHub properties.

Repository policy forbids GoReleaser, Homebrew Formula, Scoop bucket, and
release-automation metadata outright. The broader package-metadata absence
check remains explicit tag-time evidence in `RELEASE_CHECKLIST.md`; this
durable gate does not claim to parse arbitrary package formats.
