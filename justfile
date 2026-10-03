set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

check: tidy typos fmt lint vet build build-windows vulncheck winvm-check test-total

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
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        printf 'Skipping fuzzing in GitHub Actions.\n'
        exit 0
    fi
    fuzz_time="$({
        python3 - "${FUZZ_TIME:-1m}" <<'PY'
    import re
    import sys

    value = sys.argv[1]
    units = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6,
             "ms": 1e-3, "s": 1, "m": 60, "h": 3600}
    parts = re.findall(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)", value)
    if not parts or "".join(number + unit for number, unit in parts) != value:
        raise SystemExit(f"invalid FUZZ_TIME duration: {value!r}")
    seconds = sum(float(number) * units[unit] for number, unit in parts)
    if seconds <= 0:
        raise SystemExit("FUZZ_TIME must be positive")
    print(f"{seconds / 6:.9f}s")
    PY
    })"
    go test -run '^$' -fuzz '^FuzzDriverDecoders$' -fuzztime "$fuzz_time" .
    go test -run '^$' -fuzz '^FuzzConfigurationRoundTrip$' -fuzztime "$fuzz_time" .
    go test -run '^$' -fuzz '^FuzzProcessEncoding$' -fuzztime "$fuzz_time" .
    go test -run '^$' -fuzz '^FuzzGUID$' -fuzztime "$fuzz_time" .
    go test -run '^$' -fuzz '^FuzzParseConfig$' -fuzztime "$fuzz_time" ./cmd/tunneldemo
    go test -run '^$' -fuzz '^FuzzDemoTunnelProtocol$' -fuzztime "$fuzz_time" ./internal/demotunnel

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

qualify-windows entry evidence:
    python3 dev/winvm/tools/qualify.py --matrix dev/winvm/qualification-matrix.json --entry "{{entry}}" --native-unit "{{evidence}}/native-unit-evidence.json" --live-driver "{{evidence}}/live-driver-evidence.json" --packet-flow "{{evidence}}/packet-flow-suite-evidence.json" --packet-evidence "{{evidence}}/packet-flow-evidence.json" --output "{{evidence}}/qualification.json"

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
