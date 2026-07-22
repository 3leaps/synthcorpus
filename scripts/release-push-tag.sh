#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

root="$(release_repo_root)"
cd "${root}"

release_validate_signing_env
release_assert_checkout
release_verify_local_tag
"${script_dir}/release-guard-tag-ruleset.sh"

git push origin "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"

echo "[ok] pushed signed tag ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
echo "[--] run make release-verify-remote-tag before creating the GitHub release"
