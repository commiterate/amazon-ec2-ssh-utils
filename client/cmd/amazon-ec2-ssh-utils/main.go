package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/implementations/openssh/authorizedkeys/ec2instanceconnect"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/implementations/openssh/authorizedkeys/ec2keypairs"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/openssh/authorizedkeys"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "amazon-ec2-ssh-utils",
		Usage: "EC2 SSH utilities.",
		Commands: []*cli.Command{
			{
				Name:  "openssh-authorized-keys",
				Usage: "Print authorized keys from IMDS in the OpenSSH authorized_keys format.",
				Flags: []cli.Flag{
					// Flags corresponding to OpenSSH sshd_config tokens.
					//
					// https://man.openbsd.org/sshd_config#TOKENS
					&cli.StringFlag{
						Name:  "f",
						Usage: "The fingerprint of the key or certificate.",
					},
					&cli.StringFlag{
						Name:  "u",
						Usage: "The username.",
					},
					// Flags NOT corresponding to OpenSSH sshd_config tokens.
					&cli.StringSliceFlag{
						Name:     "source",
						Required: true,
						Usage:    "Authorized keys sources. (ec2-instance-connect, ec2-key-pairs)",
						Validator: func(sources []string) error {
							validSources := map[string]bool{
								"ec2-instance-connect": true,
								"ec2-key-pairs":        true,
							}

							for _, source := range sources {
								if !validSources[source] {
									return cli.Exit("Invalid authorized keys source.", 1)
								}
							}

							return nil
						},
					},
					&cli.UintFlag{
						Name:  "timeout",
						Usage: "The timeout in seconds.",
						Value: 5,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					ctx, cancel := context.WithTimeout(ctx, time.Duration(cmd.Uint("timeout"))*time.Second)
					defer cancel()

					sources := map[string]bool{}
					for _, source := range cmd.StringSlice("source") {
						sources[source] = true
					}

					cfg, err := config.LoadDefaultConfig(ctx)
					if err != nil {
						return cli.Exit(err, 1)
					}

					imdsClient := imds.NewFromConfig(cfg)

					authorizedKeys := []string{}

					for source := range maps.Keys(sources) {
						switch source {
						case "ec2-instance-connect":
							ec2InstanceConnectAuthorizedKeys, err := ec2instanceconnect.New(ec2instanceconnect.WithImdsClient(imdsClient))
							if err != nil {
								return cli.Exit(err, 1)
							}

							authorizedKeys = append(authorizedKeys, ec2InstanceConnectAuthorizedKeys.Get(ctx, authorizedkeys.GetOptions{Fingerprint: cmd.String("f"), User: cmd.String("u")})...)
						case "ec2-key-pairs":
							ec2KeyPairsAuthorizedKeys, err := ec2keypairs.New(ec2keypairs.WithImdsClient(imdsClient))
							if err != nil {
								return cli.Exit(err, 1)
							}

							authorizedKeys = append(authorizedKeys, ec2KeyPairsAuthorizedKeys.Get(ctx, authorizedkeys.GetOptions{Fingerprint: cmd.String("f"), User: cmd.String("u")})...)
						default:
							return cli.Exit("Unimplemented authorized keys source.", 1)
						}
					}

					for _, authorizedKey := range authorizedKeys {
						_, _ = fmt.Println(authorizedKey)
					}

					return nil
				},
			},
		},
		EnableShellCompletion: true,
	}

	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		os.Exit(1)
	}
}
