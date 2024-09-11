{
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
  nodejs,
  oxfmt,
  oxlint,
  pnpm,
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
    # JavaScript.
    nodejs
    pnpm
    oxfmt
    oxlint
    # GitHub CLI.
    gh
    # WinGet package utilities.
    komac
    # Renovate.
    renovate
  ];

  shellHook = ''
    # AWS CDK.
    #
    # https://github.com/aws/aws-cdk-cli/tree/main/packages/aws-cdk#configuration
    export CDK_DISABLE_VERSION_CHECK=1

    # GitHub CLI.
    #
    # https://cli.github.com/manual/gh_help_environment
    export GH_NO_UPDATE_NOTIFIER=true
    export GH_NO_EXTENSION_UPDATE_NOTIFIER=true
    export GH_TELEMETRY=false

    echo "❄️"
  '';
}
