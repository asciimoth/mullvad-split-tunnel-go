set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

check: tidy typos fmt lint vet test fuzz build build-windows

tidy:
    go mod tidy

typos:
    typos .

fmt:
    golangci-lint fmt ./...
    mdformat --wrap 80 $(git ls-files '*.md')
    nixfmt flake.nix

lint:
    golangci-lint run ./...
    actionlint .github/workflows/*.yml
    deadnix --fail flake.nix
    markdownlint $(git ls-files '*.md')
    statix check flake.nix

vet:
    go vet ./...

test:
    go test -race -count=1 -timeout 2m ./...

fuzz:
    go test -run '^$' -fuzz '^FuzzDriverDecoders$' -fuzztime 10s .

vulncheck:
    govulncheck ./...

build:
    go build ./...

build-windows:
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
    GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...

abi upstream="../win-split-tunnel":
    test -f "{{upstream}}/src/public.h"
    tmp_dir="$(mktemp -d)"; trap 'rm -rf "$tmp_dir"' EXIT; g++ -std=c++17 -Wall -Wextra -Werror -I "{{upstream}}/src" tools/abi_fixture.cpp -o "$tmp_dir/abi-fixture"; "$tmp_dir/abi-fixture" > "$tmp_dir/abi.json"; cmp testdata/abi.json "$tmp_dir/abi.json"
