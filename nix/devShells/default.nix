{
  bun,
  coreutils,
  findutils,
  gh,
  git,
  git-lfs,
  go,
  go-mockery,
  golangci-lint,
  just,
  komac,
  mkShell,
  nix,
  nix-update,
  nixfmt,
  renovate,
  treefmt,
}:
# https://nixos.org/manual/nixpkgs/unstable#sec-pkgs-mkShell
mkShell {
  packages = [
    # Nix.
    #
    # Nix is dynamically linked on some systems. If we set LD_LIBRARY_PATH,
    # running Nix commands with the system-installed Nix may fail due to mismatched library versions.
    nix
    nix-update
    nixfmt
    # Utilities.
    coreutils
    findutils
    # Git.
    git
    git-lfs
    # Just.
    just
    # Treefmt.
    treefmt
    # Go.
    go
    go-mockery
    golangci-lint
    # Bun.
    bun
    # GitHub CLI.
    gh
    # WinGet package utilities.
    komac
    # Renovate.
    renovate
  ];

  shellHook = ''
    echo "❄️"
  '';
}
