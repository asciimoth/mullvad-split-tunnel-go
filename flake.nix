{
  description = "mullvad-split-tunnel-go development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      pre-commit-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        markdownFormatter = pkgs.python3.withPackages (
          pythonPackages: with pythonPackages; [
            mdformat
            mdformat-gfm
          ]
        );

        windowsDriverRevision = "5b6f46cde692acb77ee74b37b9fd3f1678c45a52";

        fetchWindowsDriverFile =
          architecture: file: hash:
          pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/mullvad/mullvadvpn-app-binaries/${windowsDriverRevision}/${architecture}-pc-windows-msvc/split-tunnel/${file}";
            inherit hash;
          };

        windowsTestDrivers = pkgs.runCommand "mullvad-split-tunnel-driver-1.3.0.0" { } ''
          install -Dm0444 ${
            fetchWindowsDriverFile "x86_64" "mullvad-split-tunnel.sys"
              "sha256-EM8lu8/lH9Zjof7IipjpuFjzpXlYm7LsSWtm5P3RsgE="
          } $out/amd64/mullvad-split-tunnel.sys
          install -Dm0444 ${
            fetchWindowsDriverFile "x86_64" "mullvad-split-tunnel.inf"
              "sha256-PdWQXl+5jWGpQqM+jJpboHw6LeHk8xnh/sPlTfZZFgg="
          } $out/amd64/mullvad-split-tunnel.inf
          install -Dm0444 ${
            fetchWindowsDriverFile "x86_64" "mullvad-split-tunnel.cat"
              "sha256-xZmSagMn164GtTT0zQOdswOS4Yl7udA+T+w2MXRKTm0="
          } $out/amd64/mullvad-split-tunnel.cat

          install -Dm0444 ${
            fetchWindowsDriverFile "aarch64" "mullvad-split-tunnel.sys"
              "sha256-avizv+WqCV1Sdhh1WMfH06PgwXSzRAbNbEs/jm/6ZTQ="
          } $out/arm64/mullvad-split-tunnel.sys
          install -Dm0444 ${
            fetchWindowsDriverFile "aarch64" "mullvad-split-tunnel.inf"
              "sha256-C/2wROQFNdq76zYgtlXBVjcUs6bzIx00kslyxujepvE="
          } $out/arm64/mullvad-split-tunnel.inf
          install -Dm0444 ${
            fetchWindowsDriverFile "aarch64" "mullvad-split-tunnel.cat"
              "sha256-w9J2NnOeuqfd42nREzR96D4+IXO4pRK7iGPRGxSN584="
          } $out/arm64/mullvad-split-tunnel.cat
        '';

        hasGoModule = builtins.pathExists ./go.mod;

        goModuleProxy =
          (pkgs.buildGoModule {
            pname = "mullvad-split-tunnel-go-dependencies";
            version = "0";
            src = ./.;
            proxyVendor = true;
            modPostBuild = "go mod tidy";
            vendorHash = "sha256-y+USlkoM8K8T9WwjSM3SzvNi5oP12KsTKNnZ36vF9hA=";
          }).goModules;

        offlineGo =
          if hasGoModule then
            "env GOPROXY=file://${goModuleProxy} ${pkgs.go}/bin/go"
          else
            "${pkgs.go}/bin/go";

        offlineGolangciLint =
          if hasGoModule then
            "env GOPROXY=file://${goModuleProxy} ${pkgs.golangci-lint}/bin/golangci-lint"
          else
            "${pkgs.golangci-lint}/bin/golangci-lint";

        goModuleCheck =
          command:
          pkgs.writeShellScript "go-module-check" ''
            if test -f go.mod; then
              exec ${command}
            fi
          '';

        checks = {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              actionlint.enable = true;
              commitizen.enable = true;
              deadnix.enable = true;
              gofmt.enable = true;
              markdownlint = {
                enable = true;
              };
              nixfmt.enable = true;
              statix.enable = true;
              typos.enable = true;

              golangci-lint = {
                enable = true;
                entry = builtins.toString (goModuleCheck "${offlineGolangciLint} run ./...");
                extraPackages = [ pkgs.go ];
                pass_filenames = false;
              };
              golangtest = {
                enable = true;
                description = "Run Go tests with the race detector";
                entry = builtins.toString (goModuleCheck "${offlineGo} test -race -count=1 -timeout 2m ./...");
                pass_filenames = false;
              };
              gotidy = {
                enable = true;
                description = "Check that go.mod matches the source code";
                entry = builtins.toString (goModuleCheck "${offlineGo} mod tidy -diff");
                pass_filenames = false;
              };
              govet = {
                enable = true;
                entry = builtins.toString (goModuleCheck "${offlineGo} vet ./...");
                pass_filenames = false;
              };
              typos-commit = {
                enable = true;
                description = "Find typos in commit messages";
                entry = builtins.toString (
                  pkgs.writeShellScript "typos-commit" ''
                    ${pkgs.typos}/bin/typos "$1"
                  ''
                );
                stages = [ "commit-msg" ];
              };
            };
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          winvm-host =
            pkgs.runCommand "winvm-host-check"
              {
                nativeBuildInputs = with pkgs; [
                  coreutils
                  git
                  jq
                  openssh
                  python3
                  qemu-utils
                  shellcheck
                  util-linux
                ];
              }
              ''
                cp -R ${./.} source
                chmod -R u+w source
                cd source
                patchShebangs dev/winvm
                dev/winvm/tests/host-scripts.sh
                touch $out
              '';
        };
      in
      {
        inherit checks;

        packages.windows-test-drivers = windowsTestDrivers;

        devShells.default = pkgs.mkShell {
          inherit (checks.pre-commit-check) shellHook;

          MULLVAD_SPLIT_TUNNEL_DRIVER_DIR = windowsTestDrivers;
          WINVM_OVMF_CODE = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
          WINVM_OVMF_VARS = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";

          packages =
            with pkgs;
            [
              go
              golangci-lint
              gopls
              govulncheck

              actionlint
              commitizen
              deadnix
              gcc
              just
              markdownFormatter
              markdownlint-cli
              nixfmt
              statix
              typos
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              curl
              jq
              openssh
              OVMF
              python3
              qemu
              shellcheck
              shfmt
              util-linux
              xorriso
            ];
        };
      }
    );
}
