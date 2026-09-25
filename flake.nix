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

        hasGoModule = builtins.pathExists ./go.mod;

        goModuleProxy =
          (pkgs.buildGoModule {
            pname = "mullvad-split-tunnel-go-dependencies";
            version = "0";
            src = ./.;
            proxyVendor = true;
            modPostBuild = "go mod tidy";
            vendorHash = "sha256-W30d2csXBFVi3857waoWZFFDWJkdd9eU2x1OueKij7k=";
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
        };
      in
      {
        inherit checks;

        devShells.default = pkgs.mkShell {
          inherit (checks.pre-commit-check) shellHook;

          packages = with pkgs; [
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
          ];
        };
      }
    );
}
