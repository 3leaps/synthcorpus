#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

root="$(release_repo_root)"
cd "${root}"

release_assert_tag_version
release_validate_release_commit
release_require_command gh
release_require_command jq

tag_ref="$(gh api \
	"repos/3leaps/synthcorpus/git/ref/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}")"
if ! jq -e '.object.type == "tag"' >/dev/null <<<"${tag_ref}"; then
	echo "error: remote version-tag ref does not target an annotated tag object" >&2
	exit 1
fi

tag_object_sha="$(jq -r '.object.sha' <<<"${tag_ref}")"
tag_object="$(gh api "repos/3leaps/synthcorpus/git/tags/${tag_object_sha}")"
if ! jq -e \
	--arg tag "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" \
	--arg commit "${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}" '
        .tag == $tag and
        .object.type == "commit" and
        .object.sha == $commit and
        .verification.verified == true and
        .verification.reason == "valid"
    ' >/dev/null <<<"${tag_object}"; then
	echo "error: GitHub does not report the expected verified signed tag and target" >&2
	exit 1
fi

echo "[ok] GitHub reports a verified signed tag at ${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}"
