package ec2keypairs

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/openssh/authorizedkeys"
	"golang.org/x/crypto/ssh"
)

type Ec2KeyPairsAuthorizedKeys struct {
	// IMDS client for retrieving public keys.
	//
	// Required.
	imdsClient imdsInterface.ImdsClient
}

// Check interface conformity.
var _ authorizedkeys.AuthorizedKeys = (*Ec2KeyPairsAuthorizedKeys)(nil)

type Option func(*Ec2KeyPairsAuthorizedKeys)

func WithImdsClient(imdsClient imdsInterface.ImdsClient) Option {
	return func(ekpak *Ec2KeyPairsAuthorizedKeys) {
		ekpak.imdsClient = imdsClient
	}
}

func New(options ...Option) (*Ec2KeyPairsAuthorizedKeys, error) {
	ec2KeyPairsAuthorizedKeys := &Ec2KeyPairsAuthorizedKeys{}

	for _, option := range options {
		option(ec2KeyPairsAuthorizedKeys)
	}

	if ec2KeyPairsAuthorizedKeys.imdsClient == nil {
		return nil, fmt.Errorf("imdsClient is required")
	}

	return ec2KeyPairsAuthorizedKeys, nil
}

func (ekpak *Ec2KeyPairsAuthorizedKeys) Get(ctx context.Context, opts authorizedkeys.GetOptions) []string {
	publicKeyOutput, err := ekpak.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "public-keys/0/openssh-key"})
	if err != nil {
		slog.Warn("Couldn't get EC2 Key Pairs public key. Skipping key.", "error", err)
		return []string{}
	}

	authorizedKeys := []string{}

	// The IMDS endpoints for EC2 Key Pairs public keys return OpenSSH authorized_keys file contents.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	// https://www.mankier.com/8/sshd#Authorized_keys_File_Format
	publicKeyContent := bufio.NewScanner(publicKeyOutput.Content)
	for publicKeyContent.Scan() {
		line := publicKeyContent.Text()
		if !strings.HasPrefix(line, "#") {
			if publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyContent.Bytes()); err != nil {
				slog.Warn("Couldn't parse EC2 Key Pairs public key. Skipping key.", "error", err, "key", line)
			} else {
				// Detect the fingerprint hash algorithm.
				//
				// The SHA-256 format is a base64 string with the algorithm prefixed (e.g. `SHA256:{hash base64}`).
				// The MD5 format is a hex string without the algorithm prefixed (e.g. `{hash hex}`).
				//
				// https://www.openssh.com/txt/release-6.8
				publicKeyFingerprint := ""
				if opts.Fingerprint != "" {
					if strings.HasPrefix(opts.Fingerprint, "SHA256:") {
						publicKeyFingerprint = ssh.FingerprintSHA256(publicKey)
					} else {
						publicKeyFingerprint = ssh.FingerprintLegacyMD5(publicKey)
					}
				}

				if opts.Fingerprint != "" && publicKeyFingerprint != opts.Fingerprint {
					slog.Warn("EC2 Key Pairs public key fingerprint doesn't match specified fingerprint. Skipping key.", "key", line)
				} else {
					authorizedKeys = append(authorizedKeys, line)
				}
			}
		}
	}

	return authorizedKeys
}
