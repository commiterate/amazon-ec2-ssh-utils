package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/user"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ssh"
)

const (
	protocol = "tcp"
	address  = "127.0.0.1:22"
)

type OpensshAuthorizedKeysSuite struct {
	suite.Suite
	ctx                      context.Context
	user                     *user.User
	imdsClient               *imds.Client
	ec2InstanceConnectClient *ec2instanceconnect.Client
	ec2KeyPairSshSigner      ssh.Signer
}

func (suite *OpensshAuthorizedKeysSuite) SetupSuite() {
	suite.ctx = context.Background()

	user, err := user.Current()
	if err != nil {
		suite.FailNow("Failed to get current user.", err)
	}
	suite.user = user

	cfg, err := config.LoadDefaultConfig(suite.ctx, config.WithEC2IMDSRegion())
	if err != nil {
		suite.FailNow("Failed to create AWS SDK configuration.", err)
	}
	suite.imdsClient = imds.NewFromConfig(cfg)
	suite.ec2InstanceConnectClient = ec2instanceconnect.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)

	ec2KeyPairPrivateKeySsmParameter, present := os.LookupEnv("EC2_KEY_PAIR_PRIVATE_KEY_SSM_PARAMETER")
	if !present {
		suite.FailNow("EC2 Key Pair private key SSM parameter environment variable isn't set.")
	}
	withDecryption := true
	getParameterOutput, err := ssmClient.GetParameter(suite.ctx, &ssm.GetParameterInput{
		Name:           &ec2KeyPairPrivateKeySsmParameter,
		WithDecryption: &withDecryption,
	})
	if err != nil {
		suite.FailNow("Failed to get EC2 Key Pair private key.", err)
	}
	ec2KeyPairOpenSshPrivateKey, err := ssh.ParseRawPrivateKey([]byte(*getParameterOutput.Parameter.Value))
	if err != nil {
		suite.FailNow("Failed to parse EC2 Key Pair private key.", err)
	}
	ec2KeyPairSshSigner, err := ssh.NewSignerFromKey(ec2KeyPairOpenSshPrivateKey)
	if err != nil {
		suite.FailNow("Failed to create SSH signer from EC2 Key Pair private key.", err)
	}
	suite.ec2KeyPairSshSigner = ec2KeyPairSshSigner
}

func (suite *OpensshAuthorizedKeysSuite) TestEc2InstanceConnect() {
	instanceIdentityDocumentOutput, err := suite.imdsClient.GetInstanceIdentityDocument(suite.ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		suite.FailNow("Failed to get instance identity document.", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}
	sshSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		suite.FailNow("Failed to create SSH signer from SSH private key.", err)
	}
	sshPublicKey := string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey()))

	_, err = suite.ec2InstanceConnectClient.SendSSHPublicKey(suite.ctx, &ec2instanceconnect.SendSSHPublicKeyInput{
		InstanceId:     &instanceIdentityDocumentOutput.InstanceID,
		InstanceOSUser: &suite.user.Username,
		SSHPublicKey:   &sshPublicKey,
	})
	if err != nil {
		suite.FailNow("Failed to send SSH public key.", err)
	}

	sshClient, err := ssh.Dial(protocol, address, &ssh.ClientConfig{
		User:            suite.user.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(sshSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		suite.FailNow("Failed to start SSH connection.", err)
	}
	defer func() { _ = sshClient.Close() }()
	sshSession, err := sshClient.NewSession()
	if err != nil {
		suite.FailNow("Failed to start SSH session.", err)
	}
	defer func() { _ = sshSession.Close() }()

	err = sshSession.Run("echo 'Hello!'")
	if err != nil {
		suite.FailNow("Failed to run command.", err)
	}
}

func (suite *OpensshAuthorizedKeysSuite) TestEc2KeyPairs() {
	sshClient, err := ssh.Dial(protocol, address, &ssh.ClientConfig{
		User:            suite.user.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(suite.ec2KeyPairSshSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		suite.FailNow("Failed to start SSH connection.")
	}
	defer func() { _ = sshClient.Close() }()
	sshSession, err := sshClient.NewSession()
	if err != nil {
		suite.FailNow("Failed to start SSH session.")
	}
	defer func() { _ = sshSession.Close() }()

	err = sshSession.Run("echo 'Hello!'")
	if err != nil {
		suite.FailNow("Failed to run command.", err)
	}
}

func TestAmazonEc2OpensshAuthorizedKeysSuite(t *testing.T) {
	suite.Run(t, new(OpensshAuthorizedKeysSuite))
}
