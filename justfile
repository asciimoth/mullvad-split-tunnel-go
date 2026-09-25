set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

check: tidy typos fmt lint vet build build-windows winvm-check test-total

test-total: test fuzz winvm-tests

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

winvm-doctor:
    dev/winvm/doctor.sh

winvm-input-hashes:
    dev/winvm/doctor.sh --print-input-hashes

winvm-image:
    dev/winvm/build-image.sh

test-windows-vm:
    dev/winvm/run.sh baseline

test-windows-e2e:
    dev/winvm/run.sh e2e

test-windows-flow:
    dev/winvm/run.sh flow

winvm-shell run:
    dev/winvm/run.sh --shell "{{run}}"

winvm-clean:
    dev/winvm/run.sh --clean

winvm-check:
    if [[ "${OS:-}" == "Windows_NT" || "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]]; then printf 'Skipping Linux-only Windows VM host checks.\n'; else dev/winvm/tests/host-scripts.sh; fi

winvm-tests:
    if [[ "${OS:-}" == "Windows_NT" || "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]]; then printf 'Skipping Linux-only Windows VM tests.\n'; else dev/winvm/build-image.sh && dev/winvm/run.sh baseline && dev/winvm/run.sh e2e && dev/winvm/run.sh flow; fi

abi upstream="../win-split-tunnel":
    test -f "{{upstream}}/src/public.h"
    tmp_dir="$(mktemp -d)"; trap 'rm -rf "$tmp_dir"' EXIT; g++ -std=c++17 -Wall -Wextra -Werror -I tools/abi_compat -I "{{upstream}}/src" tools/abi_fixture.cpp -o "$tmp_dir/abi-fixture"; "$tmp_dir/abi-fixture" > "$tmp_dir/abi.json"; cmp testdata/abi.json "$tmp_dir/abi.json"
