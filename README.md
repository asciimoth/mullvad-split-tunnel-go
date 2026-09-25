# mullvad-split-tunnel-go

## Development environment

Enter the Nix development shell:

```sh
nix develop
```

If direnv is installed, run `direnv allow` once instead.

Use `just` to list the available commands. Use `just check` to format, lint,
test, fuzz, and build the project for Linux and Windows. The commands use the
temporary source tree in `local/mullvad-split-tunnel-go` until `go.mod` is moved
to the repository root. No tooling changes are necessary after that move.

Git hooks are installed when the development shell starts. Evaluate and run the
configured repository checks without entering the shell with:

```sh
nix flake check
```

The ABI fixture check also needs a checkout of `mullvad/win-split-tunnel` at the
commit documented by the project. By default, `just abi` expects that checkout
at `../win-split-tunnel`. Pass a different path as its first argument if needed.
