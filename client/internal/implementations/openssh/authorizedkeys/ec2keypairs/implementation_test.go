package ec2keypairs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/openssh/authorizedkeys"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

type Ec2KeyPairsAuthorizedKeysSuite struct {
	suite.Suite
	ctx                       context.Context
	imdsClient                *imdsInterface.MockImdsClient
	ec2KeyPairsAuthorizedKeys *Ec2KeyPairsAuthorizedKeys
}

func (suite *Ec2KeyPairsAuthorizedKeysSuite) SetupTest() {
	suite.ctx = context.Background()

	suite.imdsClient = imdsInterface.NewMockImdsClient(suite.T())

	ec2KeyPairsAuthorizedKeys, err := New(WithImdsClient(suite.imdsClient))
	if err != nil {
		suite.FailNow("Failed to create ImdsAuthorizedKeys.", err)
	}
	suite.ec2KeyPairsAuthorizedKeys = ec2KeyPairsAuthorizedKeys
}

func (suite *Ec2KeyPairsAuthorizedKeysSuite) TestNewOptions() {
	_, err := New()
	suite.Error(err, "ImdsClient should be required.")
}

func (suite *Ec2KeyPairsAuthorizedKeysSuite) TestGet_Success() {
	authorizedSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedSshPublicKey, err := ssh.NewPublicKey(authorizedSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to wrap SSH public key.", err)
	}

	authorizedPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedAuthorizedSshPublicKey))),
	)

	unauthorizedSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedUnauthorizedSshPublicKey, err := ssh.NewPublicKey(unauthorizedSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to create SSH public key.", err)
	}

	unauthorizedPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedUnauthorizedSshPublicKey))),
	)

	invalidPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s {invalid public key} comment",
		ssh.KeyAlgoED25519,
	)

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "public-keys/0/openssh-key"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(strings.Join(
					[]string{
						"# Authorized key.",
						authorizedPublicKey,
						"# Unauthorized key (mismatched fingerprint).",
						unauthorizedPublicKey,
						"# Invalid key (invalid public key).",
						invalidPublicKey,
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	authorizedKeys := suite.ec2KeyPairsAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{
			Fingerprint: ssh.FingerprintSHA256(wrappedAuthorizedSshPublicKey),
		},
	)

	suite.Equal(
		[]string{
			authorizedPublicKey,
		},
		authorizedKeys,
	)
}

func (suite *Ec2KeyPairsAuthorizedKeysSuite) TestGet_NoFingerprint() {
	authorizedSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedSshPublicKey, err := ssh.NewPublicKey(authorizedSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to wrap SSH public key.", err)
	}

	authorizedPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedAuthorizedSshPublicKey))),
	)

	invalidPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s {invalid public key} comment",
		ssh.KeyAlgoED25519,
	)

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "public-keys/0/openssh-key"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(strings.Join(
					[]string{
						"# Authorized key.",
						authorizedPublicKey,
						"# Invalid key (invalid public key).",
						invalidPublicKey,
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	authorizedKeys := suite.ec2KeyPairsAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{},
	)

	suite.Equal(
		[]string{
			authorizedPublicKey,
		},
		authorizedKeys,
	)
}

func (suite *Ec2KeyPairsAuthorizedKeysSuite) TestGet_GracefulFailure() {
	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			mock.Anything,
		).
		Return(
			nil,
			fmt.Errorf("⛔"),
		).
		Once()

	authorizedKeys := suite.ec2KeyPairsAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{},
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func TestImdsAuthorizedKeysSuite(t *testing.T) {
	suite.Run(t, new(Ec2KeyPairsAuthorizedKeysSuite))
}
