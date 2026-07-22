#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

root="$(release_repo_root)"
cd "${root}"

release_validate_signing_env
release_setup_gpg_tty
release_assert_checkout
release_assert_tag_absent

policy_attestation="$("${script_dir}/release-guard-tag-ruleset.sh" --print-attestation)"
readonly policy_attestation
if ! [[ "${policy_attestation}" =~ ^Tag-Publish-Policy-SHA256:\ [0-9a-f]{64}$ ]]; then
	echo "error: tag publication-policy attestation is malformed" >&2
	exit 1
fi

export GIT_COMMITTER_NAME="${THREELEAPS_SYNTHCORPUS_TAGGER_NAME}"
export GIT_COMMITTER_EMAIL="${THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL}"

echo "Creating GPG-signed tag ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG} at ${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}"
GNUPGHOME="${GNUPGHOME}" git tag -s -a \
	-u "${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" \
	-m "synthcorpus ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" \
	-m "${policy_attestation}" \
	"${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" \
	"${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}"

release_verify_local_tag

echo "[ok] created and verified signed tag ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
echo "[--] the tag is local only; run make release-push-tag from this unchanged checkout"
