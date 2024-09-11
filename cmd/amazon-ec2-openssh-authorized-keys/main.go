package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsAuthorizedKeys "github.com/commiterate/amazon-ec2-ssh-utils/internal/implementations/openssh/authorizedkeys/imds"
)

func main() {
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.Usage = func() {
		fmt.Fprintf(flagSet.Output(), "%s is an OpenSSH AuthorizedKeysCommand program which gets public keys for EC2 Key Pairs and EC2 Instance Connect from IMDS.\n", os.Args[0])
		fmt.Fprintf(flagSet.Output(), "\n")
		fmt.Fprintf(flagSet.Output(), "Usage: %s [flags]\n", os.Args[0])
		fmt.Fprintf(flagSet.Output(), "\n")
		fmt.Fprintf(flagSet.Output(), "Flags:\n")
		flagSet.PrintDefaults()
	}
	// Flag names and usage strings correspond to OpenSSH sshd_config tokens.
	//
	// https://man.openbsd.org/sshd_config#TOKENS
	fingerprint := flagSet.String("f", "", "The fingerprint of the key or certificate.")
	user := flagSet.String("u", "", "The username.")
	timeout := flagSet.Uint("timeout", 5, "The timeout in seconds.")
	_ = flagSet.Parse(os.Args[1:])

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.Error("Failed to load AWS SDK configuration.", "error", err)
		return
	}

	imdsClient := imds.NewFromConfig(cfg)

	authorizedKeys, err := imdsAuthorizedKeys.New(imdsAuthorizedKeys.WithImdsClient(imdsClient))
	if err != nil {
		slog.Error("Failed to create ImdsAuthorizedKeys.", "error", err)
		return
	}

	for _, authorizedKey := range authorizedKeys.Get(ctx, user, fingerprint, nil) {
		fmt.Println(authorizedKey)
	}
}
