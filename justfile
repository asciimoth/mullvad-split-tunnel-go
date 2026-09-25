set shell := ["bash", "-euo", "pipefail", "-c"]

project_dir := `if test -f go.mod; then printf .; else printf local/mullvad-split-tunnel-go; fi`

default:
    @just --list

check: tidy typos fmt lint vet test fuzz build build-windows

tidy:
    go -C {{project_dir}} mod tidy

typos:
    typos . --exclude local
    typos {{project_dir}}

fmt:
    cd {{project_dir}} && golangci-lint fmt ./...
    nixfmt flake.nix

lint:
    cd {{project_dir}} && golangci-lint run ./...
    actionlint {{project_dir}}/.github/workflows/*.yml
    deadnix --fail flake.nix
    statix check flake.nix

vet:
    go -C {{project_dir}} vet ./...

test:
    go -C {{project_dir}} test -race -count=1 -timeout 2m ./...

fuzz:
    go -C {{project_dir}} test -run '^$' -fuzz '^FuzzDriverDecoders$' -fuzztime 10s .

vulncheck:
    cd {{project_dir}} && govulncheck ./...

build:
    go -C {{project_dir}} build ./...

build-windows:
    cd {{project_dir}} && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
    cd {{project_dir}} && GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...

abi upstream="../win-split-tunnel":
    test -f "{{upstream}}/src/public.h"
    tmp_dir="$(mktemp -d)"; trap 'rm -rf "$tmp_dir"' EXIT; g++ -std=c++17 -Wall -Wextra -Werror -I "{{upstream}}/src" {{project_dir}}/tools/abi_fixture.cpp -o "$tmp_dir/abi-fixture"; "$tmp_dir/abi-fixture" > "$tmp_dir/abi.json"; cmp {{project_dir}}/testdata/abi.json "$tmp_dir/abi.json"
