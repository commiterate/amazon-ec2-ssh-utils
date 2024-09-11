package imds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"
)

const (
	region     = "ap-northeast-1"
	domain     = "amazonaws.com"
	instanceId = "i-00000000000000000"
	callerId   = "arn:aws:iam::000000000000:role/Role"
	requestId  = "00000000-0000-0000-0000-000000000000"
)

var (
	user          = "ec2-user"
	rsaPssOptions = rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
)

type ImdsAuthorizedKeysSuite struct {
	suite.Suite
	ctx                context.Context
	imdsClient         *imdsInterface.MockImdsClient
	imdsAuthorizedKeys *ImdsAuthorizedKeys
}

func (suite *ImdsAuthorizedKeysSuite) SetupTest() {
	suite.ctx = context.Background()

	suite.imdsClient = imdsInterface.NewMockImdsClient(suite.T())

	imdsAuthorizedKeys, err := New(WithImdsClient(suite.imdsClient))
	if err != nil {
		suite.FailNow("Failed to create ImdsAuthorizedKeys.", err)
	}
	suite.imdsAuthorizedKeys = imdsAuthorizedKeys
}

func (suite *ImdsAuthorizedKeysSuite) TestNewOptions() {
	_, err := New()
	suite.Error(err, "ImdsClient should be required.")
}

func (suite *ImdsAuthorizedKeysSuite) TestGet_Success() {
	authorizedEc2KeyPairSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedEc2KeyPairSshPublicKey, err := ssh.NewPublicKey(authorizedEc2KeyPairSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to wrap SSH public key.", err)
	}

	authorizedEc2KeyPairPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedAuthorizedEc2KeyPairSshPublicKey))),
	)

	invalidEc2KeyPairPublicKey := fmt.Sprintf(
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
						authorizedEc2KeyPairPublicKey,
						"# Invalid key (invalid public key).",
						invalidEc2KeyPairPublicKey,
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	suite.
		imdsClient.
		EXPECT().
		GetInstanceIdentityDocument(
			suite.ctx,
			&imds.GetInstanceIdentityDocumentInput{},
		).
		Return(
			&imds.GetInstanceIdentityDocumentOutput{
				InstanceIdentityDocument: imds.InstanceIdentityDocument{
					Region:     region,
					InstanceID: instanceId,
				},
			},
			nil,
		).
		Once()

	currentTime := time.Now()

	ec2InstanceConnectSignerPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		suite.FailNow("Failed to create signer key pair.", err)
	}

	ec2InstanceConnectSignerCertificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     currentTime.Add(time.Hour),
		DNSNames:     []string{fmt.Sprintf("managed-ssh-signer.%s.%s", region, domain)},
	}

	ec2InstanceConnectSignerCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		ec2InstanceConnectSignerCertificateTemplate,
		ec2InstanceConnectSignerCertificateTemplate,
		&ec2InstanceConnectSignerPrivateKey.PublicKey,
		ec2InstanceConnectSignerPrivateKey,
	)
	if err != nil {
		suite.FailNow("Failed to create signer certificate.", err)
	}
	ec2InstanceConnectSignerCertificate, err := x509.ParseCertificate(ec2InstanceConnectSignerCertificateBytes)
	if err != nil {
		suite.FailNow("Failed to parse signer certificate.", err)
	}
	rootCertificatePool := x509.NewCertPool()
	rootCertificatePool.AddCert(ec2InstanceConnectSignerCertificate)

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "managed-ssh-keys/signer-cert"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(bytes.NewReader(ec2InstanceConnectSignerCertificateBytes)),
			},
			nil,
		).
		Once()

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "services/domain"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(domain)),
			},
			nil,
		).
		Once()

	ec2InstanceConnectOcspStaplePath := "staple"

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "managed-ssh-keys/signer-ocsp"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(ec2InstanceConnectOcspStaplePath)),
			},
			nil,
		).
		Once()

	ec2InstanceConnectOcspResponse, err := ocsp.CreateResponse(
		ec2InstanceConnectSignerCertificate,
		ec2InstanceConnectSignerCertificate,
		ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(0),
		},
		ec2InstanceConnectSignerPrivateKey,
	)
	if err != nil {
		suite.FailNow("Failed to create OCSP response.", err)
	}

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/signer-ocsp/%s", ec2InstanceConnectOcspStaplePath)},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(bytes.NewReader(ec2InstanceConnectOcspResponse)),
			},
			nil,
		)

	authorizedEc2InstanceConnectSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedEc2InstanceConnectSshPublicKey, err := ssh.NewPublicKey(authorizedEc2InstanceConnectSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to create SSH public key.", err)
	}

	authorizedEc2InstanceConnectPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedAuthorizedEc2InstanceConnectSshPublicKey))),
	)

	unauthorizedEc2InstanceConnectSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedUnauthorizedEc2InstanceConnectSshPublicKey, err := ssh.NewPublicKey(unauthorizedEc2InstanceConnectSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to create SSH public key.", err)
	}

	unauthorizedEc2InstanceConnectPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedUnauthorizedEc2InstanceConnectSshPublicKey))),
	)

	invalidEc2InstanceConnectPublicKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s {invalid public key} comment",
		ssh.KeyAlgoED25519,
	)

	authorizedEc2InstanceConnectPublicKeySignedData := strings.Join(
		[]string{
			"# Authorized key.",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(time.Hour).Unix()),
			fmt.Sprintf("#Instance=%s", instanceId),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			authorizedEc2InstanceConnectPublicKey,
		},
		"\n",
	)

	unauthorizedEc2InstanceConnectPublicKeySignedData := strings.Join(
		[]string{
			"# Unauthorized key (expired, mismatched instance + fingerprint).",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(-time.Hour).Unix()),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			unauthorizedEc2InstanceConnectPublicKey,
		},
		"\n",
	)

	invalidEc2InstanceConnectPublicKeySignedData := strings.Join(
		[]string{
			"# Invalid key (invalid timestamp + public key).",
			"#Timestamp=⏳",
			invalidEc2InstanceConnectPublicKey,
		},
		"\n",
	)

	authorizedEc2InstanceConnectPublicKeyDigest := sha256.New()
	authorizedEc2InstanceConnectPublicKeyDigest.Write([]byte(authorizedEc2InstanceConnectPublicKeySignedData))
	authorizedEc2InstanceConnectPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedEc2InstanceConnectPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	unauthorizedEc2InstanceConnectPublicKeyDigest := sha256.New()
	unauthorizedEc2InstanceConnectPublicKeyDigest.Write([]byte(unauthorizedEc2InstanceConnectPublicKeySignedData))
	unauthorizedEc2InstanceConnectPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		unauthorizedEc2InstanceConnectPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	invalidEc2InstanceConnectPublicKeyDigest := sha256.New()
	invalidEc2InstanceConnectPublicKeyDigest.Write([]byte(invalidEc2InstanceConnectPublicKeySignedData))
	invalidEc2InstanceConnectPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		invalidEc2InstanceConnectPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/active-keys/%s", user)},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(strings.Join(
					[]string{
						authorizedEc2InstanceConnectPublicKeySignedData,
						base64.StdEncoding.EncodeToString(authorizedEc2InstanceConnectPublicKeySignature),
						unauthorizedEc2InstanceConnectPublicKeySignedData,
						base64.StdEncoding.EncodeToString(unauthorizedEc2InstanceConnectPublicKeySignature),
						invalidEc2InstanceConnectPublicKeySignedData,
						base64.StdEncoding.EncodeToString(invalidEc2InstanceConnectPublicKeySignature),
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	fingerprint := ssh.FingerprintSHA256(wrappedAuthorizedEc2InstanceConnectSshPublicKey)
	authorizedKeys := suite.imdsAuthorizedKeys.Get(
		suite.ctx,
		&user,
		&fingerprint,
		rootCertificatePool,
	)

	suite.Equal(
		[]string{
			authorizedEc2KeyPairPublicKey,
			authorizedEc2InstanceConnectPublicKey,
		},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestGetEc2KeyPairAuthorizedKeys_GracefulFailure() {
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

	authorizedKeys := suite.imdsAuthorizedKeys.getEc2KeyPairAuthorizedKeys(suite.ctx)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestGetEc2InstanceConnectAuthorizedKeys_GracefulFailure() {
	suite.
		imdsClient.
		EXPECT().
		GetInstanceIdentityDocument(
			suite.ctx,
			mock.Anything,
		).
		Return(
			nil,
			fmt.Errorf("⛔"),
		).
		Once()

	authorizedKeys := suite.imdsAuthorizedKeys.getEc2InstanceConnectAuthorizedKeys(
		suite.ctx,
		&user,
		nil,
		nil,
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)

	suite.
		imdsClient.
		EXPECT().
		GetInstanceIdentityDocument(
			suite.ctx,
			mock.Anything,
		).
		Return(
			&imds.GetInstanceIdentityDocumentOutput{},
			nil,
		).
		Once()

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

	authorizedKeys = suite.imdsAuthorizedKeys.getEc2InstanceConnectAuthorizedKeys(
		suite.ctx,
		&user,
		nil,
		nil,
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestGetEc2InstanceConnectAuthorizedKeys_NoUser() {
	authorizedKeys := suite.imdsAuthorizedKeys.getEc2InstanceConnectAuthorizedKeys(
		suite.ctx,
		nil,
		nil,
		nil,
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_GracefulFailure() {
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

	authorizedKeys := suite.imdsAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		user,
		nil,
		nil,
		nil,
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_Fingerprint() {
	authorizedSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedSshPublicKey, err := ssh.NewPublicKey(authorizedSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to create SSH public key.", err)
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

	currentTime := time.Now()

	ec2InstanceConnectSignerPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		suite.FailNow("Failed to create signer key pair.", err)
	}

	ec2InstanceConnectSignerCertificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     currentTime.Add(time.Hour),
		DNSNames:     []string{fmt.Sprintf("managed-ssh-signer.%s.%s", region, domain)},
	}

	ec2InstanceConnectSignerCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		ec2InstanceConnectSignerCertificateTemplate,
		ec2InstanceConnectSignerCertificateTemplate,
		&ec2InstanceConnectSignerPrivateKey.PublicKey,
		ec2InstanceConnectSignerPrivateKey,
	)
	if err != nil {
		suite.FailNow("Failed to create signer certificate.", err)
	}
	ec2InstanceConnectSignerCertificate, err := x509.ParseCertificate(ec2InstanceConnectSignerCertificateBytes)
	if err != nil {
		suite.FailNow("Failed to parse signer certificate.", err)
	}

	authorizedPublicKeySignedData := strings.Join(
		[]string{
			"# Authorized key.",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(time.Hour).Unix()),
			fmt.Sprintf("#Instance=%s", instanceId),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			authorizedPublicKey,
		},
		"\n",
	)

	unauthorizedPublicKeySignedData := strings.Join(
		[]string{
			"# Unauthorized key (mismatched fingerprint).",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(time.Hour).Unix()),
			fmt.Sprintf("#Instance=%s", instanceId),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			unauthorizedPublicKey,
		},
		"\n",
	)

	authorizedPublicKeyDigest := sha256.New()
	authorizedPublicKeyDigest.Write([]byte(authorizedPublicKeySignedData))
	authorizedPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	unauthorizedPublicKeyDigest := sha256.New()
	unauthorizedPublicKeyDigest.Write([]byte(unauthorizedPublicKeySignedData))
	unauthorizedPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		unauthorizedPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/active-keys/%s", user)},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(strings.Join(
					[]string{
						authorizedPublicKeySignedData,
						base64.StdEncoding.EncodeToString(authorizedPublicKeySignature),
						unauthorizedPublicKeySignedData,
						base64.StdEncoding.EncodeToString(unauthorizedPublicKeySignature),
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	fingerprint := ssh.FingerprintSHA256(wrappedAuthorizedSshPublicKey)
	authorizedKeys := suite.imdsAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		user,
		&fingerprint,
		&imds.InstanceIdentityDocument{
			InstanceID: instanceId,
		},
		ec2InstanceConnectSignerCertificate,
	)

	suite.Equal(
		[]string{authorizedPublicKey},
		authorizedKeys,
	)
}

func (suite *ImdsAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_NoFingerprint() {
	authorizedSshPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		suite.FailNow("Failed to create SSH key pair.", err)
	}

	wrappedAuthorizedSshPublicKey, err := ssh.NewPublicKey(authorizedSshPublicKey)
	if err != nil {
		suite.FailNow("Failed to create SSH public key.", err)
	}

	authorizedKey := fmt.Sprintf(
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

	unauthorizedKey := fmt.Sprintf(
		"restrict,command=\"echo 'hello'\" %s comment",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrappedUnauthorizedSshPublicKey))),
	)

	currentTime := time.Now()

	ec2InstanceConnectSignerPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		suite.FailNow("Failed to create signer key pair.", err)
	}

	ec2InstanceConnectSignerCertificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     currentTime.Add(time.Hour),
		DNSNames:     []string{fmt.Sprintf("managed-ssh-signer.%s.%s", region, domain)},
	}

	ec2InstanceConnectSignerCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		ec2InstanceConnectSignerCertificateTemplate,
		ec2InstanceConnectSignerCertificateTemplate,
		&ec2InstanceConnectSignerPrivateKey.PublicKey,
		ec2InstanceConnectSignerPrivateKey,
	)
	if err != nil {
		suite.FailNow("Failed to create signer certificate.", err)
	}
	ec2InstanceConnectSignerCertificate, err := x509.ParseCertificate(ec2InstanceConnectSignerCertificateBytes)
	if err != nil {
		suite.FailNow("Failed to parse signer certificate.", err)
	}

	authorizedPublicKeySignedData := strings.Join(
		[]string{
			"# Authorized key.",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(time.Hour).Unix()),
			fmt.Sprintf("#Instance=%s", instanceId),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			authorizedKey,
		},
		"\n",
	)

	expiredPublicKeySignedData := strings.Join(
		[]string{
			"# Unauthorized key (expired).",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(-time.Hour).Unix()),
			fmt.Sprintf("#Instance=%s", instanceId),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			unauthorizedKey,
		},
		"\n",
	)

	mismatchedInstancePublicKeySignedData := strings.Join(
		[]string{
			"# Unauthorized key (mismatched instance).",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(time.Hour).Unix()),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			unauthorizedKey,
		},
		"\n",
	)

	authorizedPublicKeyDigest := sha256.New()
	authorizedPublicKeyDigest.Write([]byte(authorizedPublicKeySignedData))
	authorizedPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	expiredPublicKeyDigest := sha256.New()
	expiredPublicKeyDigest.Write([]byte(expiredPublicKeySignedData))
	expiredPublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		expiredPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	mismatchedInstancePublicKeyDigest := sha256.New()
	mismatchedInstancePublicKeyDigest.Write([]byte(mismatchedInstancePublicKeySignedData))
	mismatchedInstancePublicKeySignature, err := ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		mismatchedInstancePublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/active-keys/%s", user)},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(strings.Join(
					[]string{
						authorizedPublicKeySignedData,
						base64.StdEncoding.EncodeToString(authorizedPublicKeySignature),
						expiredPublicKeySignedData,
						base64.StdEncoding.EncodeToString(expiredPublicKeySignature),
						mismatchedInstancePublicKeySignedData,
						base64.StdEncoding.EncodeToString(mismatchedInstancePublicKeySignature),
					},
					"\n",
				))),
			},
			nil,
		).
		Once()

	authorizedKeys := suite.imdsAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		user,
		nil,
		&imds.InstanceIdentityDocument{
			InstanceID: instanceId,
		},
		ec2InstanceConnectSignerCertificate,
	)

	suite.Equal(
		[]string{authorizedKey},
		authorizedKeys,
	)
}

func TestImdsAuthorizedKeysSuite(t *testing.T) {
	suite.Run(t, new(ImdsAuthorizedKeysSuite))
}
