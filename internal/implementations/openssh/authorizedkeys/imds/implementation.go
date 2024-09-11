package imds

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	authorizedKeysInterface "github.com/commiterate/amazon-ec2-ssh-utils/internal/interfaces/openssh/authorizedkeys"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"
)

const (
	ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix = "#Timestamp="
	ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix          = "#Instance="
	ec2InstanceConnectPublicKeyMetadataCallerIdPrefix            = "#Caller="
	ec2InstanceConnectPublicKeyMetadataRequestIdPrefix           = "#Request="
)

type ImdsAuthorizedKeys struct {
	// IMDS client for retrieving public keys.
	//
	// Required.
	imdsClient imdsInterface.ImdsClient
}

// Check interface conformity.
var _ authorizedKeysInterface.AuthorizedKeys = (*ImdsAuthorizedKeys)(nil)

type Option func(*ImdsAuthorizedKeys)

func WithImdsClient(imdsClient imdsInterface.ImdsClient) Option {
	return func(self *ImdsAuthorizedKeys) {
		self.imdsClient = imdsClient
	}
}

func New(options ...Option) (*ImdsAuthorizedKeys, error) {
	imdsAuthorizedKeys := &ImdsAuthorizedKeys{}

	for _, option := range options {
		option(imdsAuthorizedKeys)
	}

	if imdsAuthorizedKeys.imdsClient == nil {
		return nil, fmt.Errorf("imdsClient is required.")
	}

	return imdsAuthorizedKeys, nil
}

func (self *ImdsAuthorizedKeys) Get(ctx context.Context, user *string, fingerprint *string, rootCertificatePool *x509.CertPool) []string {
	authorizedKeys := []string{}

	authorizedKeys = append(
		authorizedKeys,
		self.getEc2KeyPairAuthorizedKeys(ctx)...,
	)

	authorizedKeys = append(
		authorizedKeys,
		self.getEc2InstanceConnectAuthorizedKeys(ctx, user, fingerprint, rootCertificatePool)...,
	)

	return authorizedKeys
}

func (self *ImdsAuthorizedKeys) getEc2KeyPairAuthorizedKeys(ctx context.Context) []string {
	slog.Info("Getting EC2 Key Pair authorized public keys.")

	publicKeyOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "public-keys/0/openssh-key"})
	if err != nil {
		slog.Error("Couldn't get EC2 Key Pair public key. Skipping key.", "error", err)
		return []string{}
	}

	authorizedKeys := []string{}

	// The IMDS endpoint for EC2 Key Pair public keys returns OpenSSH authorized_keys file contents.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	publicKeyContent := bufio.NewScanner(publicKeyOutput.Content)
	for publicKeyContent.Scan() {
		line := publicKeyContent.Text()
		if !strings.HasPrefix(line, "#") {
			if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyContent.Bytes()); err != nil {
				slog.Error("Couldn't parse public key. Skipping key.", "error", err, "key", line)
			} else {
				authorizedKeys = append(authorizedKeys, line)
			}
		}
	}

	return authorizedKeys
}

func (self *ImdsAuthorizedKeys) getEc2InstanceConnectAuthorizedKeys(ctx context.Context, user *string, fingerprint *string, rootCertificatePool *x509.CertPool) []string {
	slog.Info("Getting EC2 Instance Connect authorized public keys.")

	if user == nil || *user == "" {
		slog.Error("No user specified for EC2 Instance Connect public keys. Skipping keys.")
		return []string{}
	}

	instanceIdentityDocumentOutput, err := self.imdsClient.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		slog.Error("Couldn't get instance identity document. Skipping keys.", "error", err)
		return []string{}
	}

	signerCertificate, err := self.getEc2InstanceConnectSignerCertificate(ctx, &instanceIdentityDocumentOutput.InstanceIdentityDocument, rootCertificatePool)
	if err != nil {
		slog.Error("Couldn't get the EC2 Instance Connect signer certificate. Skipping keys.", "error", err)
		return []string{}
	}

	return self.filterEc2InstanceConnectPublicKeys(ctx, *user, fingerprint, &instanceIdentityDocumentOutput.InstanceIdentityDocument, signerCertificate)
}

func (self *ImdsAuthorizedKeys) getEc2InstanceConnectSignerCertificate(ctx context.Context, instanceIdentityDocument *imds.InstanceIdentityDocument, rootCertificatePool *x509.CertPool) (*x509.Certificate, error) {
	signerCertificateBundleOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "managed-ssh-keys/signer-cert"})
	if err != nil {
		slog.Error("Couldn't get EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	signerCertificateBundleContent, err := io.ReadAll(signerCertificateBundleOutput.Content)
	if err != nil {
		slog.Error("Couldn't read EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	signerCertificateBundle, err := x509.ParseCertificates(signerCertificateBundleContent)
	if err != nil {
		slog.Error("Couldn't parse EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	domainOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "services/domain"})
	if err != nil {
		slog.Error("Couldn't get domain.", "error", err)
		return nil, err
	}

	domain, err := io.ReadAll(domainOutput.Content)
	if err != nil {
		slog.Error("Couldn't read domain.", "error", err)
		return nil, err
	}

	expectedDnsName := fmt.Sprintf("managed-ssh-signer.%s.%s", instanceIdentityDocument.Region, domain)

	leafSignerCertificate := signerCertificateBundle[0]
	intermediateSignerCertificateBundle := signerCertificateBundle[1:]
	intermediateSignerCertificatePool := x509.NewCertPool()
	for _, intermediateSignerCertificate := range intermediateSignerCertificateBundle {
		intermediateSignerCertificatePool.AddCert(intermediateSignerCertificate)
	}

	_, err = leafSignerCertificate.Verify(x509.VerifyOptions{
		DNSName:       expectedDnsName,
		Intermediates: intermediateSignerCertificatePool,
		Roots:         rootCertificatePool,
	})
	if err != nil {
		slog.Error("Couldn't verify signer certificate bundle.", "error", err)
		return nil, err
	}

	ocspStaplePathsOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "managed-ssh-keys/signer-ocsp"})
	if err != nil {
		slog.Error("Couldn't get OCSP staple paths.", "error", err)
		return nil, err
	}

	// TODO: Is the response a newline (like "public-keys") or space-delimited set of paths?
	ocspStaplePathsContent := bufio.NewScanner(ocspStaplePathsOutput.Content)
	for ocspStaplePathsContent.Scan() {
		path := ocspStaplePathsContent.Text()
		ocspStapleOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/signer-ocsp/%s", path)})
		if err != nil {
			slog.Error("Couldn't get OCSP staple.", "error", err)
			return nil, err
		}

		ocspStapleContent, err := io.ReadAll(ocspStapleOutput.Content)
		if err != nil {
			slog.Error("Couldn't read OCSP staple.", "error", err)
			return nil, err
		}

		for _, signerCertificate := range signerCertificateBundle {
			ocspResponse, err := ocsp.ParseResponse(ocspStapleContent, signerCertificate)
			if err != nil {
				slog.Error("Couldn't parse OCSP response.", "error", err)
				return nil, err
			}

			// TODO: Replace the hand-rolled OCSP verifier if the Go standard libraries add one.
			//
			// https://github.com/golang/go/issues/40017
			if ocspResponse.Status != ocsp.Good {
				switch ocspResponse.Status {
				case ocsp.Revoked:
					slog.Error("Signer certificate is revoked.", "revocationReason", ocspResponse.RevocationReason, "revokedAt", ocspResponse.RevokedAt)
				case ocsp.Unknown:
					slog.Error("Signer certificate is unknown.")
				default:
					slog.Error("Unexpected signer certificate status.", "status", ocspResponse.Status)
				}
				return nil, fmt.Errorf("Signer certificate status isn't good.")
			}
		}
	}

	return leafSignerCertificate, nil
}

type ec2InstanceConnectPublicKeyBlock struct {
	SignedData     []string
	ExpirationTime *time.Time
	InstanceId     *string
	CallerId       *string
	RequestId      *string
	PublicKey      *string
}

func (self *ImdsAuthorizedKeys) filterEc2InstanceConnectPublicKeys(ctx context.Context, user string, fingerprint *string, instanceIdentityDocument *imds.InstanceIdentityDocument, signerCertificate *x509.Certificate) []string {
	publicKeysOutput, err := self.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/active-keys/%s", user)})
	if err != nil {
		slog.Error("Couldn't get EC2 Instance Connect public keys. Skipping keys.", "error", err)
		return []string{}
	}

	authorizedKeys := []string{}

	currentTime := time.Now()
	publicKeyBlock := ec2InstanceConnectPublicKeyBlock{}

	// The IMDS endpoint for EC2 Instance Connect public keys returns OpenSSH authorized_keys file contents with public keys sandwiched by metadata comments and a base64-encoded signature.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	publicKeysContent := bufio.NewScanner(publicKeysOutput.Content)
	for publicKeysContent.Scan() {
		line := publicKeysContent.Text()

		if strings.HasPrefix(line, "#") {
			// Public key block started before a previous one ended.
			if publicKeyBlock.PublicKey != nil {
				publicKeyBlock = ec2InstanceConnectPublicKeyBlock{}
			}

			publicKeyBlock.SignedData = append(publicKeyBlock.SignedData, line)

			if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix) {
				expirationTimestamp, err := strconv.ParseInt(strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix), 10, 64)
				if err != nil {
					slog.Error("Couldn't parse expiration timestamp.", "metadatum", line)
				} else {
					expirationTime := time.Unix(expirationTimestamp, 0)
					publicKeyBlock.ExpirationTime = &expirationTime
				}
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix) {
				instanceId := strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix)
				publicKeyBlock.InstanceId = &instanceId
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataCallerIdPrefix) {
				callerId := strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataCallerIdPrefix)
				publicKeyBlock.CallerId = &callerId
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataRequestIdPrefix) {
				requestId := strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataRequestIdPrefix)
				publicKeyBlock.RequestId = &requestId
			}
		} else if publicKeyBlock.PublicKey == nil {
			publicKeyBlock.SignedData = append(publicKeyBlock.SignedData, line)

			publicKeyBlock.PublicKey = &line
		} else {
			if signature, err := base64.StdEncoding.DecodeString(line); err != nil {
				slog.Error("Couldn't decode signature. Skipping key.", "error", err, "signature", line, "block", publicKeyBlock)
			} else {
				if publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*publicKeyBlock.PublicKey)); err != nil {
					slog.Error("Couldn't parse public key. Skipping key.", "error", err, "block", publicKeyBlock)
				} else {
					if publicKeyBlock.ExpirationTime == nil || (*publicKeyBlock.ExpirationTime).Before(currentTime) {
						slog.Error("Public key is expired. Skipping key.", "block", publicKeyBlock)
					} else if publicKeyBlock.InstanceId == nil || *publicKeyBlock.InstanceId != instanceIdentityDocument.InstanceID {
						slog.Error("Public key is for another EC2 instance. Skipping key.", "block", publicKeyBlock)
					} else if fingerprint != nil && ssh.FingerprintSHA256(publicKey) != *fingerprint {
						// TODO: Consider configurable fingerprint hash algorithm? OpenSSH may change it again like it did from MD5 to SHA-256.
						slog.Error("Public key fingerprint doesn't match specified fingerprint. Skipping key.", "block", publicKeyBlock)
					} else {
						signedData := []byte(strings.Join(publicKeyBlock.SignedData, "\n"))
						if err := signerCertificate.CheckSignature(x509.SHA256WithRSAPSS, signedData, signature); err != nil {
							slog.Error("Public key block signature check failed. Skipping key.", "error", err, "signature", line, "block", publicKeyBlock)
						} else {
							authorizedKeys = append(authorizedKeys, *publicKeyBlock.PublicKey)
						}
					}
				}
			}

			// Public key block ended.
			publicKeyBlock = ec2InstanceConnectPublicKeyBlock{}
		}
	}

	return authorizedKeys
}
