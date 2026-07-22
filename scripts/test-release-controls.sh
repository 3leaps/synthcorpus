#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"
# shellcheck source=scripts/release-guard-tag-ruleset.sh
source "${script_dir}/release-guard-tag-ruleset.sh"

tests_run=0

pass() {
	tests_run=$((tests_run + 1))
}

expect_success() {
	local description="$1"
	shift
	local output
	if ! output="$("$@" 2>&1)"; then
		echo "not ok: ${description}" >&2
		printf '%s\n' "${output}" >&2
		exit 1
	fi
	pass
}

expect_failure() {
	local description="$1"
	shift
	if ("$@" >/dev/null 2>&1); then
		echo "not ok: ${description} unexpectedly passed" >&2
		exit 1
	fi
	pass
}

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

remote="${tmp_root}/remote.git"
repo="${tmp_root}/repo"
publisher="${tmp_root}/publisher"
gpg_home="${tmp_root}/release-gnupg"
mkdir -p "${gpg_home}"

git init --bare -q "${remote}"
git init -q -b main "${repo}"
git -C "${repo}" config user.name "Release Test"
git -C "${repo}" config user.email "release@example.invalid"
printf '0.1.0\n' >"${repo}/VERSION"
git -C "${repo}" add VERSION
git -C "${repo}" commit -q -m initial
first_commit="$(git -C "${repo}" rev-parse HEAD)"
git -C "${repo}" remote add origin "${remote}"
git -C "${repo}" push -q -u origin main

readonly expected_fingerprint="0123456789ABCDEF0123456789ABCDEF01234567"
readonly expected_name="3 Leaps Release"
readonly expected_email="release@example.invalid"

export THREELEAPS_SYNTHCORPUS_RELEASE_TAG="v0.1.0"
export THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="${first_commit}"
export THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR="${gpg_home}"
export THREELEAPS_SYNTHCORPUS_GPG_SIGNING_FINGERPRINT="${expected_fingerprint}"
export THREELEAPS_SYNTHCORPUS_TAGGER_NAME="${expected_name}"
export THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL="${expected_email}"

real_git="$(command -v git)"
verify_mode="good"

gpg() {
	case " $* " in
		*' --list-secret-keys '*)
			printf 'sec:u:255:22:0123456789ABCDEF:0:0:::::scESC:::\n'
			printf 'fpr:::::::::%s:\n' "${expected_fingerprint}"
			printf 'uid:u::::0::HASH::3 Leaps Release <%s>::::::::::0:\n' "${expected_email}"
			;;
		*' --list-keys '*)
			printf 'pub:u:255:22:0123456789ABCDEF:0:0:::::scESC:::\n'
			printf 'fpr:::::::::%s:\n' "${expected_fingerprint}"
			printf 'uid:u::::0::HASH::3 Leaps Release <%s>::::::::::0:\n' "${expected_email}"
			;;
		*) return 1 ;;
	esac
}

git() {
	if [ "${1:-}" = "verify-tag" ]; then
		case "${verify_mode}" in
			good)
				printf '[GNUPG:] VALIDSIG %s 2026-07-22 1784736000 0 4 0 22 10 00 %s\n' \
					"${expected_fingerprint}" "${expected_fingerprint}"
				return 0
				;;
			wrong-signer)
				printf '[GNUPG:] VALIDSIG %s 2026-07-22 1784736000 0 4 0 22 10 00 %s\n' \
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				return 0
				;;
			expired)
				printf '[GNUPG:] EXPKEYSIG 0123456789ABCDEF expired\n'
				printf '[GNUPG:] VALIDSIG %s 2026-07-22 1784736000 0 4 0 22 10 00 %s\n' \
					"${expected_fingerprint}" "${expected_fingerprint}"
				return 0
				;;
			invalid) return 1 ;;
		esac
	fi
	command "${real_git}" "$@"
}

cd "${repo}"

expect_success "valid tag and full commit inputs" release_assert_tag_version
expect_success "full commit object accepted" release_validate_release_commit
# shellcheck disable=SC2016 # $1 is intentionally expanded by the child shell.
expect_failure "missing verified SHA rejected" bash -c \
	'unset THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT; source "$1"; release_validate_release_commit' \
	_ "${script_dir}/release-common.sh"

saved_commit="${THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT}"
THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="${saved_commit:0:12}"
expect_failure "abbreviated verified SHA rejected" release_validate_release_commit
THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="0000000000000000000000000000000000000000"
expect_failure "unknown verified SHA rejected" release_validate_release_commit
blob_commit="$(printf blob | command git hash-object -w --stdin)"
THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="${blob_commit}"
expect_failure "non-commit object rejected as release SHA" release_validate_release_commit
THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="${saved_commit}"

expect_success "valid OOB signing environment accepted" release_validate_signing_env
unset THREELEAPS_SYNTHCORPUS_TAGGER_NAME
expect_failure "absent tagger name rejected" release_validate_verification_env
export THREELEAPS_SYNTHCORPUS_TAGGER_NAME="${expected_name}"
THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL="wrong@example.invalid"
expect_failure "tagger email absent from key UID rejected" release_validate_verification_env
THREELEAPS_SYNTHCORPUS_TAGGER_EMAIL="${expected_email}"

mkdir -p .test-gnupg
THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR="${repo}/.test-gnupg"
expect_failure "in-worktree GPG home rejected" release_configure_gpg
ln -s "${repo}/.test-gnupg" "${tmp_root}/gnupg-alias"
THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR="${tmp_root}/gnupg-alias"
expect_failure "symlink alias into worktree rejected" release_configure_gpg
git init -q "${tmp_root}/other-repo"
mkdir -p "${tmp_root}/other-repo/gnupg"
THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR="${tmp_root}/other-repo/gnupg"
expect_failure "GPG home in another Git worktree rejected" release_configure_gpg
THREELEAPS_SYNTHCORPUS_GPG_HOMEDIR="${gpg_home}"
release_configure_gpg

expect_success "clean main at verified origin/main accepted" release_assert_checkout
git switch -q -c topic
expect_failure "wrong branch rejected" release_assert_checkout
git switch -q main
printf dirty >dirty.txt
expect_failure "dirty checkout rejected" release_assert_checkout
rm dirty.txt

git clone -q "${remote}" "${publisher}"
git -C "${publisher}" config user.name "Publisher"
git -C "${publisher}" config user.email "publisher@example.invalid"
printf 'advance\n' >"${publisher}/advance.txt"
git -C "${publisher}" add advance.txt
git -C "${publisher}" commit -q -m advance
git -C "${publisher}" push -q origin main
expect_failure "moved origin/main rejected against verified SHA" release_assert_checkout
git fetch -q origin main
git reset -q --hard origin/main
second_commit="$(command git rev-parse HEAD)"
THREELEAPS_SYNTHCORPUS_RELEASE_COMMIT="${second_commit}"
expect_success "rebased literal verified SHA accepted" release_assert_checkout

expect_success "absent local and remote tag accepted" release_assert_tag_absent
command git tag "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
expect_failure "existing local tag rejected" release_assert_tag_absent
command git tag -d "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" >/dev/null
command git tag "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
command git push -q origin "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
command git tag -d "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" >/dev/null
expect_failure "existing remote tag rejected" release_assert_tag_absent
command git push -q origin --delete "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"

expected_attestation="$(release_expected_policy_attestation)"

write_tag_object() {
	local target="$1"
	local policy_mode="$2"
	local tagger_name="$3"
	local tagger_email="$4"
	local signature_mode="$5"
	local target_type="${6:-commit}"
	local object_file="${tmp_root}/tag-object"

	{
		printf 'object %s\n' "${target}"
		printf 'type %s\n' "${target_type}"
		printf 'tag %s\n' "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
		printf 'tagger %s <%s> 1784736000 -0400\n\n' "${tagger_name}" "${tagger_email}"
		printf 'synthcorpus %s\n\n' "${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
		case "${policy_mode}" in
			good) printf '%s\n' "${expected_attestation}" ;;
			missing) ;;
			duplicate) printf '%s\n%s\n' "${expected_attestation}" "${expected_attestation}" ;;
			wrong) printf 'Tag-Publish-Policy-SHA256: %064d\n' 0 ;;
		esac
		if [ "${signature_mode}" = "signed" ]; then
			printf '%s\n' '-----BEGIN PGP SIGNATURE-----' '' 'synthetic-test-signature' '-----END PGP SIGNATURE-----'
		fi
	} >"${object_file}"

	local object_sha
	object_sha="$(command git hash-object -t tag -w "${object_file}")"
	command git update-ref "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" "${object_sha}"
}

write_tag_object "${second_commit}" good "${expected_name}" "${expected_email}" signed
verify_mode=good
expect_success "fully bound signed tag accepted" release_verify_local_tag
write_tag_object "${second_commit}" good "${expected_name}" "${expected_email}" unsigned
inner_tag="$(command git rev-parse "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}")"
write_tag_object "${inner_tag}" good "${expected_name}" "${expected_email}" signed tag
expect_failure "indirect nested annotated tag target rejected" release_verify_local_tag
write_tag_object "${second_commit}" good "${expected_name}" "${expected_email}" signed
verify_mode=wrong-signer
expect_failure "wrong signer rejected" release_verify_local_tag
verify_mode=expired
expect_failure "expired signer rejected" release_verify_local_tag
verify_mode=invalid
expect_failure "invalid signature rejected" release_verify_local_tag
verify_mode=good

write_tag_object "${second_commit}" missing "${expected_name}" "${expected_email}" signed
expect_failure "missing policy attestation rejected" release_verify_local_tag
write_tag_object "${second_commit}" duplicate "${expected_name}" "${expected_email}" signed
expect_failure "duplicate policy attestation rejected" release_verify_local_tag
write_tag_object "${second_commit}" wrong "${expected_name}" "${expected_email}" signed
expect_failure "wrong policy attestation rejected" release_verify_local_tag
write_tag_object "${second_commit}" good "Wrong Name" "${expected_email}" signed
expect_failure "mismatched tagger name rejected" release_verify_local_tag
write_tag_object "${second_commit}" good "${expected_name}" "wrong@example.invalid" signed
expect_failure "mismatched tagger email rejected" release_verify_local_tag
write_tag_object "${first_commit}" good "${expected_name}" "${expected_email}" signed
expect_failure "wrong peeled release commit rejected" release_verify_local_tag
write_tag_object "${second_commit}" good "${expected_name}" "${expected_email}" unsigned
expect_failure "unsigned annotated tag rejected" release_verify_local_tag
command git update-ref "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}" "${second_commit}"
expect_failure "lightweight tag rejected" release_verify_local_tag
command git update-ref -d "refs/tags/${THREELEAPS_SYNTHCORPUS_RELEASE_TAG}"
expect_failure "absent tag rejected" release_verify_local_tag

good_policy="$(expected_policy_json | jq '{
    name: .ruleset_name,
    source_type: .source_type,
    source: .repository,
    target: .target,
    enforcement: .enforcement,
    conditions: .conditions,
    rules: (.rules | map({type: .})),
    bypass_actors: .bypass_actors
}')"
expected_digest="092d1bc03f4ade53d425dcb91b0d45913a765013bb25f4945added4764d3068b"
if [ "$(policy_digest)" != "${expected_digest}" ]; then
	echo "not ok: canonical policy digest changed unexpectedly" >&2
	exit 1
fi
pass
expect_success "exact ruleset policy accepted" validate_ruleset "${good_policy}"
expect_failure "ruleset repository scope mutation rejected" validate_ruleset \
	"$(jq '.source = "3leaps/other"' <<<"${good_policy}")"
expect_failure "ruleset name mutation rejected" validate_ruleset \
	"$(jq '.name = "Other Protection"' <<<"${good_policy}")"
expect_failure "ruleset source type mutation rejected" validate_ruleset \
	"$(jq '.source_type = "Organization"' <<<"${good_policy}")"
expect_failure "ruleset target mutation rejected" validate_ruleset \
	"$(jq '.target = "branch"' <<<"${good_policy}")"
expect_failure "ruleset ref pattern mutation rejected" validate_ruleset \
	"$(jq '.conditions.ref_name.include = ["refs/tags/*"]' <<<"${good_policy}")"
expect_failure "ruleset ref exclusion mutation rejected" validate_ruleset \
	"$(jq '.conditions.ref_name.exclude = ["refs/tags/v0.1.0"]' <<<"${good_policy}")"
expect_failure "ruleset enforcement mutation rejected" validate_ruleset \
	"$(jq '.enforcement = "evaluate"' <<<"${good_policy}")"
expect_failure "ruleset rule-set mutation rejected" validate_ruleset \
	"$(jq '.rules |= map(select(.type != "deletion"))' <<<"${good_policy}")"
expect_failure "ruleset extra rule rejected" validate_ruleset \
	"$(jq '.rules += [{"type":"required_status_checks","parameters":{}}]' <<<"${good_policy}")"
expect_failure "ruleset rule parameters rejected" validate_ruleset \
	"$(jq '.rules[0].parameters = {}' <<<"${good_policy}")"
expect_failure "ruleset bypass actor mutation rejected" validate_ruleset \
	"$(jq '.bypass_actors[0].actor_type = "RepositoryRole"' <<<"${good_policy}")"
expect_failure "ruleset bypass mode mutation rejected" validate_ruleset \
	"$(jq '.bypass_actors[0].bypass_mode = "pull_request"' <<<"${good_policy}")"
expect_failure "ruleset bypass actor id mutation rejected" validate_ruleset \
	"$(jq '.bypass_actors[0].actor_id = 5' <<<"${good_policy}")"
expect_failure "ruleset extra bypass actor rejected" validate_ruleset \
	"$(jq '.bypass_actors += [{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}]' <<<"${good_policy}")"
expect_failure "missing ruleset response rejected" validate_ruleset ""
expect_failure "malformed ruleset response rejected" validate_ruleset "not-json"

echo "[ok] release controls: ${tests_run} hermetic checks passed"
