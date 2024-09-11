# amazon-ec2-ssh-utils

> 🚧 Under construction.

Utilities for configuring SSH in EC2 instances for [EC2 Instance Connect](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-eic.html) and [EC2 Key Pairs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html).

> Connecting to instances with [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) is handled by the [Amazon SSM Agent](https://github.com/aws/amazon-ssm-agent) instead.

## Layout

```text
Key:
🤖 = Generated

.
│   # Client.
├── client
│   └── ...
│
│   # Infrastructure.
├── infrastructure
│   └── ...
│
│   # Nix flake outputs.
├── nix
│   └── ...
│
│   # Tests.
├── tests
│   └── ...
│
│   # Nix configuration.
├── flake.nix
└── flake.lock 🤖
```

## Tools

### Nix

[Nix](https://nixos.org) is a package manager and build system centered around reproducibility.

For us, Nix's most useful feature is its ability to create reproducible + isolated CLI shells on the same machine which use different versions of the same package (e.g. Java 17 and 21). Shell configurations can be encapsulated in Nix files which can be shared across multiple computers.

The best way to install Nix is with the [Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer) ([guide](https://zero-to-nix.com/start/install)).

Once installed, running `nix develop` in a directory with a `flake.nix` will create a nested Bash shell defined by the flake.

> 🔖
>
> If you're on a network with lots of GitHub traffic, you may get a rate limiting error. To work around this, you can either switch networks (e.g. turn off VPN) or add a GitHub personal access token (classic) to your [Nix configuration](https://nix.dev/manual/nix/latest/command-ref/conf-file).
>
> ```text
> access-tokens = github.com=ghp_{rest of token}
> ```

### direnv

[direnv](https://direnv.net) is a shell extension which can automatically load and unload environment variables when you enter or leave a specific directory.

It can automatically load and unload a Nix environment when we enter and leave a project directory.

__Unlike `nix develop` which drops you in a nested Bash shell, direnv extracts the environment variables from the nested Bash shell into your current shell (e.g. Bash, Zsh, Fish).__

Follow the [installation instructions on its website](https://direnv.net#basic-installation).

It also has [editor integration](https://github.com/direnv/direnv/wiki#editor-integration). Note that some integrations won't automatically reload the environment after Nix flake changes unlike direnv itself so manual reloads may be needed.

## Notes

### Updating Flake Locks

The `flake.lock` file locks the inputs (e.g. the Nixpkgs revision) used to evaluate `flake.nix` files. To update the inputs (e.g. to get newer packages in a later Nixpkgs revision), you'll need to update your `flake.lock` file.

```shell
# Update flake.lock.
nix flake update
```

## To-Do

- `amazon-ec2-ssh-utils`
	- Manpage generation (https://github.com/urfave/cli-docs).
- Documentation
	- Have AWS add EC2 Instance Connect paths to [IMDS documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories) (and maybe [aws/amazon-ec2-metadata-mock](https://github.com/aws/amazon-ec2-metadata-mock)).
		- Currently guessing these based on [aws/aws-ec2-instance-connect-config](https://github.com/aws/aws-ec2-instance-connect-config).
- E2E testing
	- Add macOS + Windows.
- Packaging
	- Nixpkgs package
	- `.deb` (Debian, Ubuntu)
	- `.rpm` (Amazon Linux, RHEL, Fedora)
	- [Homebrew formula](https://docs.brew.sh/Formula-Cookbook) (publish to the [AWS Homebrew tap](https://github.com/aws/homebrew-tap))
	- [Windows Package Manager](https://learn.microsoft.com/en-us/windows/package-manager/package)
- CI/CD
	- PR (build)
	- Merge-to-main (build + integration test + publish if version is bumped in `utilities/package.nix`)
	- Renovate (automatically update Nix, Go, and JavaScript dependencies)
