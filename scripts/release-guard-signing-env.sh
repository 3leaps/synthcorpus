#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

root="$(release_repo_root)"
cd "${root}"
release_validate_signing_env

echo "[ok] release signing environment is ready"
