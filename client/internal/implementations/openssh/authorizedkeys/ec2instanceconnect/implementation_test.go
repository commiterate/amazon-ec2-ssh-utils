package ec2instanceconnect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/openssh/authorizedkeys"
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

type Ec2InstanceConnectAuthorizedKeysSuite struct {
	suite.Suite
	ctx                                 context.Context
	imdsClient                          *imdsInterface.MockImdsClient
	ec2InstanceConnectSignerPrivateKey  *rsa.PrivateKey
	ec2InstanceConnectSignerCertificate *x509.Certificate
	ec2InstanceConnectAuthorizedKeys    *Ec2InstanceConnectAuthorizedKeys
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) SetupTest() {
	suite.ctx = context.Background()

	suite.imdsClient = imdsInterface.NewMockImdsClient(suite.T())

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
		Maybe()

	ec2InstanceConnectSignerPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		suite.FailNow("Failed to create signer key pair.", err)
	}
	suite.ec2InstanceConnectSignerPrivateKey = ec2InstanceConnectSignerPrivateKey

	ec2InstanceConnectSignerCertificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{fmt.Sprintf("managed-ssh-signer.%s.%s", region, domain)},
	}

	ec2InstanceConnectSignerCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		ec2InstanceConnectSignerCertificateTemplate,
		ec2InstanceConnectSignerCertificateTemplate,
		&suite.ec2InstanceConnectSignerPrivateKey.PublicKey,
		suite.ec2InstanceConnectSignerPrivateKey,
	)
	if err != nil {
		suite.FailNow("Failed to create signer certificate.", err)
	}
	ec2InstanceConnectSignerCertificate, err := x509.ParseCertificate(ec2InstanceConnectSignerCertificateBytes)
	if err != nil {
		suite.FailNow("Failed to parse signer certificate.", err)
	}
	suite.ec2InstanceConnectSignerCertificate = ec2InstanceConnectSignerCertificate
	rootCertificatePool := x509.NewCertPool()
	rootCertificatePool.AddCert(suite.ec2InstanceConnectSignerCertificate)
	ec2InstanceConnectSignerCertificatePemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ec2InstanceConnectSignerCertificateBytes,
	})

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "managed-ssh-keys/signer-cert"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(bytes.NewReader(ec2InstanceConnectSignerCertificatePemBytes)),
			},
			nil,
		).
		Maybe()

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
		Maybe()

	ec2InstanceConnectSignerCertificateFingerprint := sha1.Sum(ec2InstanceConnectSignerCertificateBytes)
	ec2InstanceConnectSignerCertificateOcspStaplePath := strings.ToUpper(hex.EncodeToString(ec2InstanceConnectSignerCertificateFingerprint[:]))

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: "managed-ssh-keys/signer-ocsp"},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(strings.NewReader(ec2InstanceConnectSignerCertificateOcspStaplePath)),
			},
			nil,
		).
		Maybe()

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
	base64Ec2InstanceConnectOcspResponse := base64.StdEncoding.EncodeToString(ec2InstanceConnectOcspResponse)

	suite.
		imdsClient.
		EXPECT().
		GetMetadata(
			suite.ctx,
			&imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/signer-ocsp/%s", ec2InstanceConnectSignerCertificateOcspStaplePath)},
		).
		Return(
			&imds.GetMetadataOutput{
				Content: io.NopCloser(bytes.NewReader([]byte(base64Ec2InstanceConnectOcspResponse))),
			},
			nil,
		).
		Maybe()

	ec2InstanceConnectAuthorizedKeys, err := New(WithImdsClient(suite.imdsClient), WithRootCertificatePool(rootCertificatePool))
	if err != nil {
		suite.FailNow("Failed to create Ec2InstanceConnectAuthorizedKeys.", err)
	}
	suite.ec2InstanceConnectAuthorizedKeys = ec2InstanceConnectAuthorizedKeys
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestNewOptions() {
	_, err := New()
	suite.Error(err, "ImdsClient should be required.")
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestGet_Success() {
	currentTime := time.Now()

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

	invalidPublicKey := fmt.Sprintf(
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
			authorizedPublicKey,
		},
		"\n",
	)

	unauthorizedEc2InstanceConnectPublicKeySignedData := strings.Join(
		[]string{
			"# Unauthorized key (expired, mismatched instance + fingerprint).",
			fmt.Sprintf("#Timestamp=%d", currentTime.Add(-time.Hour).Unix()),
			fmt.Sprintf("#Caller=%s", callerId),
			fmt.Sprintf("#Request=%s", requestId),
			unauthorizedPublicKey,
		},
		"\n",
	)

	invalidEc2InstanceConnectPublicKeySignedData := strings.Join(
		[]string{
			"# Invalid key (invalid timestamp + public key).",
			"#Timestamp=⏳",
			invalidPublicKey,
		},
		"\n",
	)

	authorizedEc2InstanceConnectPublicKeyDigest := sha256.New()
	authorizedEc2InstanceConnectPublicKeyDigest.Write([]byte(authorizedEc2InstanceConnectPublicKeySignedData + "\n"))
	authorizedEc2InstanceConnectPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedEc2InstanceConnectPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	unauthorizedEc2InstanceConnectPublicKeyDigest := sha256.New()
	unauthorizedEc2InstanceConnectPublicKeyDigest.Write([]byte(unauthorizedEc2InstanceConnectPublicKeySignedData + "\n"))
	unauthorizedEc2InstanceConnectPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		unauthorizedEc2InstanceConnectPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	invalidEc2InstanceConnectPublicKeyDigest := sha256.New()
	invalidEc2InstanceConnectPublicKeyDigest.Write([]byte(invalidEc2InstanceConnectPublicKeySignedData + "\n"))
	invalidEc2InstanceConnectPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
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

	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{
			Fingerprint: ssh.FingerprintSHA256(wrappedAuthorizedSshPublicKey),
			User:        user,
		},
	)

	suite.Equal(
		[]string{
			authorizedPublicKey,
		},
		authorizedKeys,
	)
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestGet_GracefulFailure() {
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

	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{
			User: user,
		},
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestGet_NoUser() {
	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.Get(
		suite.ctx,
		authorizedkeys.GetOptions{},
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_GracefulFailure() {
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

	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		authorizedkeys.GetOptions{
			User: user,
		},
		nil,
		nil,
	)

	suite.Equal(
		[]string{},
		authorizedKeys,
	)
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_Fingerprint() {
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
	authorizedPublicKeyDigest.Write([]byte(authorizedPublicKeySignedData + "\n"))
	authorizedPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	unauthorizedPublicKeyDigest := sha256.New()
	unauthorizedPublicKeyDigest.Write([]byte(unauthorizedPublicKeySignedData + "\n"))
	unauthorizedPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
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
	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		authorizedkeys.GetOptions{
			Fingerprint: fingerprint,
			User:        user,
		},
		&imds.InstanceIdentityDocument{
			InstanceID: instanceId,
		},
		suite.ec2InstanceConnectSignerCertificate,
	)

	suite.Equal(
		[]string{authorizedPublicKey},
		authorizedKeys,
	)
}

func (suite *Ec2InstanceConnectAuthorizedKeysSuite) TestFilterEc2InstanceConnectPublicKeys_NoFingerprint() {
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
	authorizedPublicKeyDigest.Write([]byte(authorizedPublicKeySignedData + "\n"))
	authorizedPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		authorizedPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	expiredPublicKeyDigest := sha256.New()
	expiredPublicKeyDigest.Write([]byte(expiredPublicKeySignedData + "\n"))
	expiredPublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
		rand.Reader,
		expiredPublicKeyDigest.Sum(nil),
		&rsaPssOptions,
	)
	if err != nil {
		suite.FailNow("Failed to sign public key digest.", err)
	}

	mismatchedInstancePublicKeyDigest := sha256.New()
	mismatchedInstancePublicKeyDigest.Write([]byte(mismatchedInstancePublicKeySignedData + "\n"))
	mismatchedInstancePublicKeySignature, err := suite.ec2InstanceConnectSignerPrivateKey.Sign(
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

	authorizedKeys := suite.ec2InstanceConnectAuthorizedKeys.filterEc2InstanceConnectPublicKeys(
		suite.ctx,
		authorizedkeys.GetOptions{
			User: user,
		},
		&imds.InstanceIdentityDocument{
			InstanceID: instanceId,
		},
		suite.ec2InstanceConnectSignerCertificate,
	)

	suite.Equal(
		[]string{authorizedKey},
		authorizedKeys,
	)
}

func TestImdsAuthorizedKeysSuite(t *testing.T) {
	suite.Run(t, new(Ec2InstanceConnectAuthorizedKeysSuite))
}
