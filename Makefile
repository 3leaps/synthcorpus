.PHONY: all help fmt test build build-linux-arm64 check-all clean

BINARY_NAME := synthcorpus-gen
BINARY_EXT :=
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif

all: check-all

help:
	@printf '%s\n' \
		'synthcorpus targets:' \
		'  fmt               Format Go sources' \
		'  test              Run tests' \
		'  build             Build cmd/synthcorpus-gen for the host' \
		'  build-linux-arm64 Static linux/arm64 binary (ceremony VM delivery)' \
		'  check-all         Run fmt, tests, and host build' \
		'  clean             Remove local build artifacts'

fmt:
	go fmt ./...

test:
	go test ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/$(BINARY_NAME)$(BINARY_EXT) ./cmd/synthcorpus-gen

# Headless Debian arm64 ceremony hosts receive scp'd static binaries built on
# a Mac/dev workstation. Requires a healthy GOOS=linux GOARCH=arm64 toolchain.
build-linux-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/synthcorpus-gen

check-all: fmt test build

clean:
	rm -rf bin
