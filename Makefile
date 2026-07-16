.PHONY: all help fmt test build check-all clean

BINARY_NAME := synthcorpus-gen
BINARY_EXT :=
ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
endif

all: check-all

help:
	@printf '%s\n' \
		'synthcorpus targets:' \
		'  fmt        Format Go sources' \
		'  test       Run tests' \
		'  build      Build cmd/synthcorpus-gen' \
		'  check-all  Run fmt, tests, and build' \
		'  clean      Remove local build artifacts'

fmt:
	go fmt ./...

test:
	go test ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/$(BINARY_NAME)$(BINARY_EXT) ./cmd/synthcorpus-gen

check-all: fmt test build

clean:
	rm -rf bin
