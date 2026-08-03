.PHONY: all help fmt test policy build build-linux-arm64 gitleaks provability drift-check generated-real-check contract check-all clean
.PHONY: release-control-test release-guard-signing-env release-guard-tag-version release-guard-tag-ruleset release-tag release-push-tag release-verify-tag release-verify-remote-tag

BINARY_NAME := synthcorpus-gen
LEX_BINARY_NAME := synthcorpus-lexgen
BINARY_EXT :=
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif

# Whitespace checks cover both the live working tree and committed tip vs main.
DIFF_BASE ?= origin/main

all: check-all

help:
	@printf '%s\n' \
		'synthcorpus targets:' \
		'  fmt               Format Go sources' \
		'  test              Pure-Go unit tests (no gpg/minisign/ssh-keygen/gitleaks)' \
		'  policy            CI platform + no-publish/workflow policy tests' \
		'  build             Build both generators for the host' \
		'  build-linux-arm64 Static linux/arm64 binary (ceremony VM delivery)' \
		'  gitleaks          Scanner gate: CLI detect + hermetic canary tests (needs gitleaks)' \
		'  provability       Helper-backed negative-crypto proofs (needs gpg/minisign/ssh-keygen)' \
		'  drift-check       Exact committed-synthetic decernor golden check (needs pinned decernor)' \
		'  generated-real-check  Property-only dogfood check (needs pinned decernor + sidecars)' \
		'  contract          Run both decernor consumer-contract lanes' \
		'  check-all         fmt + tests + build + scanners + proofs + contract + diff --check' \
		'  release-control-test  Hermetic negative tests for release tooling' \
		'  release-guard-signing-env  Validate the operator-private signing environment' \
		'  release-guard-tag-version  Verify release tag and commit inputs' \
		'  release-guard-tag-ruleset  Verify the live version-tag publication policy' \
		'  release-tag       Create and verify the signed release tag locally' \
		'  release-push-tag  Recheck and push the signed release tag' \
		'  release-verify-tag  Verify an existing signed release tag' \
		'  release-verify-remote-tag  Verify GitHub tag signature state and target' \
		'  clean             Remove local build artifacts'

fmt:
	go fmt ./...

test:
	go test ./...

release-control-test:
	@bash -n scripts/*.sh
	@./scripts/test-release-controls.sh

policy:
	go test ./internal/repopolicy/ -count=1

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/$(BINARY_NAME)$(BINARY_EXT) ./cmd/synthcorpus-gen
	CGO_ENABLED=0 go build -trimpath -o bin/$(LEX_BINARY_NAME)$(BINARY_EXT) ./cmd/synthcorpus-lexgen

build-linux-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/synthcorpus-gen

gitleaks:
	@command -v gitleaks >/dev/null || { echo 'gitleaks required on PATH'; exit 1; }
	# --source . keeps finding paths source-root-relative for ^path$ allowlists
	gitleaks detect --source . --no-git --config .gitleaks.toml --no-banner --redact=100 --max-decode-depth=0
	go test -tags=scanner ./internal/provability/ -count=1

# Supported-host gate: real helpers must identify themselves and reject fixtures.
provability:
	go test -tags=sidecars ./internal/provability/ -count=1

drift-check:
	go test -tags=contract ./internal/decernorcontract/ -run '^TestCommittedSyntheticGolden$$' -count=1

generated-real-check:
	go test -tags=contract,sidecars ./internal/decernorcontract/ -run '^TestGeneratedRealProperties$$' -count=1

contract: drift-check generated-real-check

check-all: fmt test policy release-control-test build gitleaks provability contract
	@git diff --check
	@git diff --check $(DIFF_BASE)...HEAD
	@echo 'check-all ok'

release-guard-signing-env:
	@./scripts/release-guard-signing-env.sh

release-guard-tag-version:
	@./scripts/release-guard-tag-version.sh

release-guard-tag-ruleset:
	@./scripts/release-guard-tag-ruleset.sh

release-tag:
	@./scripts/release-tag.sh

release-push-tag:
	@./scripts/release-push-tag.sh

release-verify-tag:
	@./scripts/release-verify-tag.sh

release-verify-remote-tag:
	@./scripts/release-verify-remote-tag.sh

clean:
	rm -rf bin
