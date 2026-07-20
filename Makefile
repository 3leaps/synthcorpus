.PHONY: all help fmt test build build-linux-arm64 gitleaks provability check-all clean

BINARY_NAME := synthcorpus-gen
BINARY_EXT :=
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif

# Branch-range whitespace check for closeout (committed tip vs main).
DIFF_BASE ?= origin/main

all: check-all

help:
	@printf '%s\n' \
		'synthcorpus targets:' \
		'  fmt               Format Go sources' \
		'  test              Pure-Go unit tests (no gpg/minisign/ssh-keygen/gitleaks)' \
		'  build             Build cmd/synthcorpus-gen for the host' \
		'  build-linux-arm64 Static linux/arm64 binary (ceremony VM delivery)' \
		'  gitleaks          Scanner gate: CLI detect + hermetic canary tests (needs gitleaks)' \
		'  provability       Helper-backed negative-crypto proofs (needs gpg/minisign/ssh-keygen)' \
		'  check-all         fmt + pure-Go tests + build + gitleaks + provability + diff --check' \
		'  clean             Remove local build artifacts'

fmt:
	go fmt ./...

test:
	go test ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/$(BINARY_NAME)$(BINARY_EXT) ./cmd/synthcorpus-gen

build-linux-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/synthcorpus-gen

gitleaks:
	@command -v gitleaks >/dev/null || { echo 'gitleaks required on PATH'; exit 1; }
	# --source . keeps finding paths source-root-relative for ^path$ allowlists
	gitleaks detect --source . --no-git --config .gitleaks.toml --no-banner
	go test -tags=scanner ./internal/provability/ -count=1

# Supported-host gate: real helpers must identify themselves and reject fixtures.
provability:
	go test -tags=sidecars ./internal/provability/ -count=1

check-all: fmt test build gitleaks provability
	@git diff --check $(DIFF_BASE)...HEAD
	@echo 'check-all ok'

clean:
	rm -rf bin
