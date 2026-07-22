#!/usr/bin/env bash

set -euo pipefail

release_common_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly release_common_dir

release_repo_root() {
	git rev-parse --show-toplevel
}

release_read_version() {
	if [ ! -f VERSION ]; then
		echo "error: VERSION file not found" >&2
		return 1
	fi
	tr -d ' \t\r\n' <VERSION
}

release_require_env() {
	local name="$1"
	if [ -z "${!name:-}" ]; then
		echo "error: ${name} is required" >&2
		return 1
	fi
}

release_require_command() {
	local name="$1"
	if ! command -v "${name}" >/dev/null 2>&1; then
		echo "error: ${name} is required on PATH" >&2
		return 1
	fi
}

release_assert_tag_version() {
	release_require_env THREELEAPS_SYNTHCORPUS_RELEASE_TAG

	local version expected_tag
	version="$(release_read_version)"
	expected_tag="v${version}"

	if ! [[ "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "error: THREELEAPS_SYNTHCORPUS_RELEASE_TAG must match vMAJOR.MINOR.PATCH" >&2
		return 1
	fi
	if [ "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" != "${expected_tag}" ]; then
		echo "error: THREELEAPS_SYNTHCORPUS_RELEASE_TAG does not match VERSION (${expected_tag})" >&2
		return 1
	fi
}

release_validate_release_commit() {
	release_require_env THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT
	if ! [[ "${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "error: THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT must be a full lowercase 40-hex SHA" >&2
		return 1
	fi
	if [ "$(git cat-file -t "${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}" 2>/dev/null || true)" != "commit" ]; then
		echo "error: THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT must identify a commit object" >&2
		return 1
	fi
}

release_canonical_directory() {
	local path="$1"
	if [ ! -d "${path}" ]; then
		return 1
	fi
	CDPATH='' cd -- "${path}" && pwd -P
}

release_configure_gpg() {
	release_require_env THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR

	local canonical_home
	canonical_home="$(release_canonical_directory "${THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR}" || true)"
	if [ -z "${canonical_home}" ]; then
		echo "error: THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR must name an existing directory" >&2
		return 1
	fi
	if git -C "${canonical_home}" rev-parse --git-dir >/dev/null 2>&1; then
		echo "error: THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR must remain outside every Git repository" >&2
		return 1
	fi

	export GNUPGHOME="${canonical_home}"
}

release_validate_fingerprint() {
	release_require_env THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT
	if ! [[ "${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]]; then
		echo "error: THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT must be a full uppercase 40-hex fingerprint" >&2
		return 1
	fi
}

release_validate_tagger_env() {
	release_require_env THREELEAPS_SYNTHCORPUS_TAGGER_NAME
	release_require_env THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL
	case "${THREELEAPS_SYNTHCORPUS_TAGGER_NAME}" in
		*$'\n'* | *'<'* | *'>'*)
			echo "error: THREELEAPS_SYNTHCORPUS_TAGGER_NAME contains an invalid character" >&2
			return 1
			;;
	esac
	case "${THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL}" in
		*$'\n'* | *'<'* | *'>'* | *' '*)
			echo "error: THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL contains an invalid character" >&2
			return 1
			;;
	esac
}

release_primary_fingerprints() {
	local listing="$1"
	printf '%s\n' "${listing}" | awk -F: '
        $1 == "sec" || $1 == "pub" { want_fingerprint = 1; next }
        want_fingerprint && $1 == "fpr" { print $10; want_fingerprint = 0 }
    '
}

release_key_uid_emails() {
	local listing="$1"
	printf '%s\n' "${listing}" |
		awk -F: '$1 == "uid" { print $10 }' |
		sed -n 's/.*<\([^<>]*\)>.*/\1/p'
}

release_validate_verification_env() {
	release_assert_tag_version
	release_validate_release_commit
	release_configure_gpg
	release_validate_fingerprint
	release_validate_tagger_env
	release_require_command gpg

	local public_listing primary_fingerprints primary_count
	public_listing="$(GNUPGHOME="${GNUPGHOME}" gpg --batch --with-colons \
		--fingerprint --list-keys \
		"${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" 2>/dev/null || true)"
	primary_fingerprints="$(release_primary_fingerprints "${public_listing}")"
	primary_count="$(printf '%s\n' "${primary_fingerprints}" | awk 'NF { count++ } END { print count + 0 }')"
	if [ "${primary_count}" -ne 1 ] ||
		[ "${primary_fingerprints}" != "${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" ]; then
		echo "error: signing fingerprint does not select exactly one primary public key in the release keyring" >&2
		return 1
	fi

	local uid_emails
	uid_emails="$(release_key_uid_emails "${public_listing}")"
	if ! grep -qxF "${THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL}" <<<"${uid_emails}"; then
		echo "error: THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL matches no UID on the configured signing key" >&2
		return 1
	fi
}

release_validate_signing_env() {
	release_validate_verification_env

	local secret_listing primary_fingerprints primary_count
	secret_listing="$(GNUPGHOME="${GNUPGHOME}" gpg --batch --with-colons \
		--fingerprint --list-secret-keys \
		"${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" 2>/dev/null || true)"
	primary_fingerprints="$(release_primary_fingerprints "${secret_listing}")"
	primary_count="$(printf '%s\n' "${primary_fingerprints}" | awk 'NF { count++ } END { print count + 0 }')"
	if [ "${primary_count}" -ne 1 ] ||
		[ "${primary_fingerprints}" != "${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" ]; then
		echo "error: signing fingerprint does not select exactly one primary secret key in the release keyring" >&2
		return 1
	fi
}

release_setup_gpg_tty() {
	if [ ! -t 0 ] || [ ! -t 1 ]; then
		echo "error: release-tag requires an interactive terminal for GPG pinentry" >&2
		return 1
	fi

	export GPG_TTY
	GPG_TTY="$(tty)"
	if command -v gpg-connect-agent >/dev/null 2>&1; then
		gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1 || true
	fi
}

release_assert_checkout() {
	if [ "$(git branch --show-current)" != "main" ]; then
		echo "error: the release checkout must be on main" >&2
		return 1
	fi
	if [ -n "$(git status --porcelain)" ]; then
		echo "error: the release checkout must be clean" >&2
		return 1
	fi
	if [ "$(git rev-parse HEAD)" != "${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}" ]; then
		echo "error: HEAD does not equal the check-verified release commit" >&2
		return 1
	fi

	git fetch origin main
	local current_main
	current_main="$(git rev-parse origin/main)"
	readonly current_main
	if [ "${current_main}" != "${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}" ]; then
		echo "error: origin/main does not equal the check-verified release commit" >&2
		return 1
	fi
}

release_assert_tag_absent() {
	if git rev-parse -q --verify "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" >/dev/null; then
		echo "error: local tag ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG} already exists" >&2
		return 1
	fi

	local remote_status
	set +e
	git ls-remote --exit-code --tags origin \
		"refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" >/dev/null 2>&1
	remote_status=$?
	set -e
	case "${remote_status}" in
		0)
			echo "error: remote tag ${THREELEAPS_SYNTHCORPUS_RELEASE_TAG} already exists" >&2
			return 1
			;;
		2) ;;
		*)
			echo "error: unable to determine whether the remote tag exists" >&2
			return 1
			;;
	esac
}

release_expected_policy_attestation() {
	"${release_common_dir}/release-guard-tag-ruleset.sh" --expected-attestation
}

release_validsig_primary_fingerprint() {
	local verification="$1"
	local validsig count
	validsig="$(sed -n 's/^\[GNUPG:\] VALIDSIG //p' <<<"${verification}")"
	count="$(printf '%s\n' "${validsig}" | awk 'NF { count++ } END { print count + 0 }')"
	if [ "${count}" -ne 1 ]; then
		return 1
	fi
	awk '{ if (NF >= 10) print $10; else print $1 }' <<<"${validsig}"
}

release_verify_local_tag() {
	local tag="${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
	local expected_commit="${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}"
	local tag_text tag_header object_type embedded_tag peeled_commit expected_attestation

	object_type="$(git cat-file -t "refs/tags/${tag}" 2>/dev/null || true)"
	if [ "${object_type}" != "tag" ]; then
		echo "error: ${tag} must resolve to an annotated tag object" >&2
		return 1
	fi
	tag_text="$(git cat-file tag "refs/tags/${tag}")"
	tag_header="$(sed '/^$/q' <<<"${tag_text}")"

	local direct_objects direct_types
	direct_objects="$(sed -n 's/^object //p' <<<"${tag_header}")"
	direct_types="$(sed -n 's/^type //p' <<<"${tag_header}")"
	if [ "$(printf '%s\n' "${direct_objects}" | awk 'NF { count++ } END { print count + 0 }')" -ne 1 ] ||
		[ "${direct_objects}" != "${expected_commit}" ]; then
		echo "error: annotated tag must directly target the check-verified release commit" >&2
		return 1
	fi
	if [ "$(printf '%s\n' "${direct_types}" | awk 'NF { count++ } END { print count + 0 }')" -ne 1 ] ||
		[ "${direct_types}" != "commit" ]; then
		echo "error: annotated tag direct object type must be commit" >&2
		return 1
	fi

	embedded_tag="$(sed -n 's/^tag //p' <<<"${tag_header}")"
	if [ "${embedded_tag}" != "${tag}" ]; then
		echo "error: annotated tag object identity does not match ${tag}" >&2
		return 1
	fi
	if [ "$(grep -c '^-----BEGIN PGP SIGNATURE-----$' <<<"${tag_text}")" -ne 1 ] ||
		[ "$(grep -c '^-----END PGP SIGNATURE-----$' <<<"${tag_text}")" -ne 1 ]; then
		echo "error: annotated tag must contain exactly one OpenPGP signature" >&2
		return 1
	fi

	expected_attestation="$(release_expected_policy_attestation)"
	if [ "$(grep -c '^Tag-Publish-Policy-SHA256: ' <<<"${tag_text}")" -ne 1 ] ||
		! grep -qxF "${expected_attestation}" <<<"${tag_text}"; then
		echo "error: signed tag lacks exactly the expected publication-policy attestation" >&2
		return 1
	fi

	local tagger_line tagger_name tagger_email
	tagger_line="$(sed -n 's/^tagger //p' <<<"${tag_header}")"
	# shellcheck disable=SC2001 # POSIX character-class match is clearer here.
	tagger_name="$(sed 's/ <[^<>]*> [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$//' <<<"${tagger_line}")"
	tagger_email="$(sed -n 's/^.* <\([^<>]*\)> [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$/\1/p' <<<"${tagger_line}")"
	if [ "${tagger_name}" != "${THREELEAPS_SYNTHCORPUS_TAGGER_NAME}" ] ||
		[ "${tagger_email}" != "${THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL}" ]; then
		echo "error: signed tag tagger identity does not match the required release identity" >&2
		return 1
	fi

	local verification primary_fingerprint
	if ! verification="$(GNUPGHOME="${GNUPGHOME}" git verify-tag --raw "${tag}" 2>&1)"; then
		printf '%s\n' "${verification}" >&2
		echo "error: tag signature verification failed" >&2
		return 1
	fi
	if grep -Eq '^\[GNUPG:\] (EXPKEYSIG|EXPSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED) ' <<<"${verification}"; then
		echo "error: tag signature or signing key is expired or revoked" >&2
		return 1
	fi
	primary_fingerprint="$(release_validsig_primary_fingerprint "${verification}" || true)"
	if [ "${primary_fingerprint}" != "${THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT}" ]; then
		echo "error: tag signature was not made by the required primary signing fingerprint" >&2
		return 1
	fi

	peeled_commit="$(git rev-parse "${tag}^{}" 2>/dev/null || true)"
	if [ "${peeled_commit}" != "${expected_commit}" ]; then
		echo "error: signed tag does not peel to the check-verified release commit" >&2
		return 1
	fi
}
