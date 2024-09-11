# amazon-ec2-ssh-utils

> 🚧 Under construction.
>
> Pending evaluation by AWS.

Utilities for configuring SSH in EC2 instances for [EC2 Key Pairs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) and [EC2 Instance Connect](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-eic.html).

> Connecting to instances with [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) is handled by the [AWS Systems Manager Agent](https://github.com/aws/amazon-ssm-agent) instead.

## Utilities

### `amazon-ec2-openssh-authorized-keys`

This is an OpenSSH [`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand) program which gets public keys for EC2 Key Pairs and EC2 Instance Connect from IMDS.

The simplest way to make the instance's OpenSSH daemon use this utility is to add the following lines to the instance's `/etc/ssh/sshd_config` file:

```text
AuthorizedKeysCommand {path to installation folder, e.g. /usr/bin}/amazon-ec2-openssh-authorized-keys -f %f -u %u

# This can be any user, but the OpenSSH documentation recommends a dedicated user that has no other role on the host than running authorized keys commands.
AuthorizedKeysCommandUser amazon-ec2-ssh
```

#### EC2 Key Pairs

EC2 Key Pair public keys can be used to log in as any user.

> Logging in as `root` requires the server's OpenSSH daemon to have its [`PermitRootLogin`](https://man.openbsd.org/sshd_config#PermitRootLogin) option be something besides `no` (default for Amazon-managed AMIs).

The [default user](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html) for Amazon-managed AMIs (e.g. `ec2-user`) has passwordless `sudo` access. Since the default user can switch to any user (e.g. `sudo su {user}`), the authorization scope is equivalent to saving the public key in `{default user home}/.ssh/authorized_keys`.

Unlike the AWS-customized cloud-init ([Amazon Linux 2](https://docs.aws.amazon.com/linux/al2/ug/amazon-linux-cloud-init.html), [Amazon Linux 2023](https://docs.aws.amazon.com/linux/al2023/ug/cloud-init.html)) which saves public keys to disk, using this utility helps prevent accidentally baking public keys into AMIs (security vulnerability).

> This may be vulnerable to man-in-the-middle attacks since EC2 Key Pairs don't have any signing mechanism like EC2 Instance Connect.
>
> https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE
>
> Saving the EC2 Key Pair public key to disk on instance launch with cloud-init is vulnerable to this as well but only during instance launch.

#### EC2 Instance Connect

EC2 Instance Connect public keys are scoped to the user specified in the [`SendSSHPublicKey`](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html) API call.

## Layout

See [Organizing a Go module](https://go.dev/doc/modules/layout).

```text
Key:
🤖 = Generated

.
│   # Build outputs.
├── build/ 🤖
│   └── ...
│
│   # Go commands.
├── cmd/
│   └── ...
│
│   # Go internal packages.
├── internal/
│   │   # Go interfaces.
│   ├── interfaces/
│   │   │   # Go interface mocks.
│   │   ├── *_mock.go 🤖
│   │   │
│   │   └── ...
│   │
│   │   # Go implementations.
│   └── implementations/
│       └── ...
│
│   # Reproducible shell configuration.
├── flake.nix
├── flake.lock 🤖
│
│   # Go path configuration.
├── go.mod
├── go.sum 🤖
│
│   # Mockery configuration.
├── .mockery.yaml
│
│   # Build recipes.
└── justfile
```

## Tools

* GNU Core Utilities
* GNU Find Utilities
	* For deleting files.
* Git
* Just
	* For build recipes.
* Go
* Mockery
	* For creating mocks.
* golangci-lint
	* Go linter.

A reproducible shell can be created with [Nix](https://nixos.org) (described by the `flake.nix` + `flake.lock` files).

Nix can be installed with the [Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer) ([guide](https://zero-to-nix.com/start/install)).

Afterwards, you can change into the project directory and create the reproducible shell with `nix develop`.

You can also install the [direnv](https://direnv.net) shell extension to automatically load and unload the reproducible shell when you enter and leave the project directory.

Unlike `nix develop` which drops you in a nested Bash shell, direnv extracts the environment variables from the nested Bash shell into your current shell (e.g. Bash, Zsh, Fish).

## Developing

Common build recipes are provided as Just recipes. To list them, run:

```shell
just help
```

To build the project, run:

```shell
just release
```

To use a utility, run:

```shell
go run cmd/{utility}/main.go
```

## Notes

### Updating Flake Locks

The `flake.lock` file locks the inputs (e.g. the Nixpkgs revision) used to evaluate `flake.nix` files. To update the inputs (e.g. to get newer packages in a later Nixpkgs revision), you'll need to update your `flake.lock` file.

```shell
# Update flake.lock.
nix flake update
```

## To-Do

* `amazon-ec2-openssh-authorized-keys`
	* Review certificate + OCSP staple verification. Something's probably incorrect.
		* Are the [Amazon root CAs](https://www.amazontrust.com/repository) expected to be on systems already?
* Documentation
	* Have AWS add EC2 Instance Connect paths to [IMDS documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories) (and maybe [aws/amazon-ec2-metadata-mock](https://github.com/aws/amazon-ec2-metadata-mock)).
		* Currently guessing these based on [aws/aws-ec2-instance-connect-config](https://github.com/aws/aws-ec2-instance-connect-config).
* Packaging
	* Nix package
	* `.deb` (Debian, Ubuntu)
	* `.rpm` (Amazon Linux, RHEL, Fedora)
	* [Homebrew formula](https://docs.brew.sh/Formula-Cookbook) (publish to the [AWS Homebrew tap](https://github.com/aws/homebrew-tap))
	* [Windows Package Manager](https://learn.microsoft.com/en-us/windows/package-manager/package)
* Integration testing
	* Use EC2 Image Builder.
		* Make the image tests do a self-SSH.
		* Use AWS CDK for infrastructure.
			* Create an EC2 Key Pair (CloudFormation creates an SSM parameter).
			* Create an EC2 launch template that uses the key pair.
			* Create an EC2 Image Builder image resource (CloudFormation will trigger an image pipeline execution).
		* Pending support for additional operating systems (macOS, Windows) for full coverage.
* CI/CD
	* See [commiterate/nix-images](https://github.com/commiterate/nix-images) for a poor man's version of [Amazon-internal Pipelines](https://aws.amazon.com/builders-library/cicd-pipeline) ([video](https://www.youtube.com/watch?v=ngnMj1zbMPY)) with GitHub Actions.
	* Dependabot (automatically update Nix, Go, and JavaScript dependencies).
