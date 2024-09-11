# Client

Client.

## Commands

### `amazon-ec2-ssh-utils`

#### `openssh-authorized-keys`

This is an OpenSSH [`AuthorizedKeysCommand`](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand) program which gets public keys for EC2 Instance Connect and EC2 Key Pairs from IMDS.

The simplest way to make the instance's OpenSSH daemon use this utility is to add the following lines to the instance's `/etc/ssh/sshd_config` file:

```text
# The `ec2-key-pairs` source option is omitted for security.
AuthorizedKeysCommand {path to installation folder, e.g. /usr/bin}/amazon-ec2-ssh-utils openssh-authorized-keys -f %f -u %u --source ec2-instance-connect

# This can be any user, but the OpenSSH documentation recommends a dedicated user that has no other role on the host.
AuthorizedKeysCommandUser nobody
```

##### EC2 Instance Connect

EC2 Instance Connect public keys are scoped to the user specified in the [`SendSSHPublicKey`](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html) API call.

##### EC2 Key Pairs

EC2 Key Pair public keys can be used to log in as any user.

> Logging in as `root` requires the server's OpenSSH daemon to have its [`PermitRootLogin`](https://man.openbsd.org/sshd_config#PermitRootLogin) option be something besides `no` (default for Amazon-managed AMIs).

The [default user](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html) for Amazon-managed AMIs (e.g. `ec2-user`) has passwordless `sudo` access. Since the default user can switch to any user (e.g. `sudo su {user}`), the authorization scope is equivalent to saving the public key in `{default user home}/.ssh/authorized_keys`.

> This is [vulnerable to man-in-the-middle attacks](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE) since EC2 Key Pairs don't have any signing mechanism like EC2 Instance Connect.
>
> It's discouraged to use this utility with EC2 Key Pairs support as an OpenSSH `AuthorizedKeysCommand`.
>
> Instead, saving the EC2 Key Pair public key to disk on instance launch like the AWS-customized cloud-init ([Amazon Linux 2](https://docs.aws.amazon.com/linux/al2/ug/amazon-linux-cloud-init.html), [Amazon Linux 2023](https://docs.aws.amazon.com/linux/al2023/ug/cloud-init.html)) is preferred.
>
> ```shell
> {path to installation folder, e.g. /usr/bin}/amazon-ec2-ssh-utils openssh-authorized-keys --source ec2-key-pairs >> {default user home}/.ssh/authorized_keys
> ```

## Layout

See [Organizing a Go module](https://go.dev/doc/modules/layout).

```text
Key:
🤖 = Generated

.
│   # Build outputs.
├── build 🤖
│   └── ...
│
│   # Go commands.
├── cmd
│   └── ...
│
│   # Go internal packages.
├── internal
│   │   # Go interfaces.
│   ├── interfaces
│   │   │   # Go interface mocks.
│   │   ├── *_mock.go 🤖
│   │   │
│   │   └── ...
│   │
│   │   # Go implementations.
│   └── implementations
│       └── ...
│
│   # Go configuration.
├── go.mod
├── go.sum 🤖
│
│   # Mockery configuration.
├── .mockery.yaml
│
│   # Build recipes.
└── justfile
```

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
go run cmd/amazon-ec2-ssh-utils/main.go
```
