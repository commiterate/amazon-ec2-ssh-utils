package ec2instanceconnect

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/openssh/authorizedkeys"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"
)

const (
	ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix = "#Timestamp="
	ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix          = "#Instance="
	ec2InstanceConnectPublicKeyMetadataCallerIdPrefix            = "#Caller="
	ec2InstanceConnectPublicKeyMetadataRequestIdPrefix           = "#Request="
)

type Ec2InstanceConnectAuthorizedKeys struct {
	// IMDS client for retrieving public keys.
	//
	// Required.
	imdsClient imdsInterface.ImdsClient
	// Root certificate pool is optional (intended for unit tests).
	rootCertificatePool *x509.CertPool
}

// Check interface conformity.
var _ authorizedkeys.AuthorizedKeys = (*Ec2InstanceConnectAuthorizedKeys)(nil)

type Option func(*Ec2InstanceConnectAuthorizedKeys)

func WithImdsClient(imdsClient imdsInterface.ImdsClient) Option {
	return func(eicak *Ec2InstanceConnectAuthorizedKeys) {
		eicak.imdsClient = imdsClient
	}
}

func WithRootCertificatePool(rootCertificatePool *x509.CertPool) Option {
	return func(eicak *Ec2InstanceConnectAuthorizedKeys) {
		eicak.rootCertificatePool = rootCertificatePool
	}
}

func New(options ...Option) (*Ec2InstanceConnectAuthorizedKeys, error) {
	ec2InstanceConnectAuthorizedKeys := &Ec2InstanceConnectAuthorizedKeys{}

	for _, option := range options {
		option(ec2InstanceConnectAuthorizedKeys)
	}

	if ec2InstanceConnectAuthorizedKeys.imdsClient == nil {
		return nil, fmt.Errorf("imdsClient is required")
	}

	return ec2InstanceConnectAuthorizedKeys, nil
}

func (eicak *Ec2InstanceConnectAuthorizedKeys) Get(ctx context.Context, opts authorizedkeys.GetOptions) []string {
	if opts.User == "" {
		slog.Warn("No user specified for EC2 Instance Connect public keys. Skipping keys.")
		return []string{}
	}

	instanceIdentityDocumentOutput, err := eicak.imdsClient.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		slog.Warn("Couldn't get instance identity document. Skipping keys.", "error", err)
		return []string{}
	}

	signerCertificate, err := eicak.getEc2InstanceConnectSignerCertificate(ctx, &instanceIdentityDocumentOutput.InstanceIdentityDocument)
	if err != nil {
		slog.Warn("Couldn't get the EC2 Instance Connect signer certificate. Skipping keys.", "error", err)
		return []string{}
	}

	return eicak.filterEc2InstanceConnectPublicKeys(ctx, opts, &instanceIdentityDocumentOutput.InstanceIdentityDocument, signerCertificate)
}

func (eicak *Ec2InstanceConnectAuthorizedKeys) getEc2InstanceConnectSignerCertificate(ctx context.Context, instanceIdentityDocument *imds.InstanceIdentityDocument) (*x509.Certificate, error) {
	signerCertificateBundleOutput, err := eicak.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "managed-ssh-keys/signer-cert"})
	if err != nil {
		slog.Error("Couldn't get EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	signerCertificateBundleContent, err := io.ReadAll(signerCertificateBundleOutput.Content)
	if err != nil {
		slog.Error("Couldn't read EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	signerCertificateBundleBlocks := []*pem.Block{}
	signerCertificateBundleBlock := &pem.Block{}
	for signerCertificateBundleBlock != nil {
		signerCertificateBundleBlock, signerCertificateBundleContent = pem.Decode(signerCertificateBundleContent)
		if signerCertificateBundleBlock != nil {
			signerCertificateBundleBlocks = append(signerCertificateBundleBlocks, signerCertificateBundleBlock)
		}
	}
	if len(signerCertificateBundleBlocks) == 0 {
		slog.Error("Couldn't decode EC2 Instance Connect signer certificate bundle.")
		return nil, fmt.Errorf("couldn't decode EC2 Instance Connect signer certificate bundle")
	}

	signerCertificateBundle := []*x509.Certificate{}
	for _, signerCertificateBundleBlock := range signerCertificateBundleBlocks {
		signerCertificate, err := x509.ParseCertificate(signerCertificateBundleBlock.Bytes)
		if err != nil {
			slog.Error("Couldn't parse EC2 Instance Connect signer certificate block.")
			return nil, err
		}
		signerCertificateBundle = append(signerCertificateBundle, signerCertificate)
	}

	domainOutput, err := eicak.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "services/domain"})
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
		Roots:         eicak.rootCertificatePool,
	})
	if err != nil {
		slog.Error("Couldn't verify EC2 Instance Connect signer certificate bundle.", "error", err)
		return nil, err
	}

	for _, signerCertificate := range signerCertificateBundle {
		// The IMDS endpoints for EC2 Instance Connect stapled OCSP responses return a base64-encoded stapled OCSP response.
		fingerprint := sha1.Sum(signerCertificate.Raw)
		base64StapledOcspResponseOutput, err := eicak.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/signer-ocsp/%s", strings.ToUpper(hex.EncodeToString(fingerprint[:])))})
		if err != nil {
			slog.Error("Couldn't get EC2 Instance Connect stapled OCSP response.", "error", err)
			return nil, err
		}

		base64StapledOcspResponseContent, err := io.ReadAll(base64StapledOcspResponseOutput.Content)
		if err != nil {
			slog.Error("Couldn't read EC2 Instance Connect stapled OCSP response.", "error", err)
			return nil, err
		}

		stapledOcspResponseContent, err := base64.StdEncoding.DecodeString(string(base64StapledOcspResponseContent))
		if err != nil {
			slog.Error("Couldn't decode EC2 Instance Connect stapled OCSP response.", "error", err)
			return nil, err
		}

		ocspResponse, err := ocsp.ParseResponse(stapledOcspResponseContent, nil)
		if err != nil {
			slog.Error("Couldn't parse EC2 Instance Connect OCSP response.", "error", err)
			return nil, err
		}

		if ocspResponse.Status != ocsp.Good {
			switch ocspResponse.Status {
			case ocsp.Revoked:
				slog.Error("EC2 Instance Connect signer certificate is revoked.", "revocationReason", ocspResponse.RevocationReason, "revokedAt", ocspResponse.RevokedAt)
			case ocsp.Unknown:
				slog.Error("EC2 Instance Connect signer certificate is unknown.")
			default:
				slog.Error("Unexpected EC2 Instance Connect signer certificate status.", "status", ocspResponse.Status)
			}
			return nil, fmt.Errorf("EC2 Instance Connect signer certificate status isn't good")
		}
	}

	return leafSignerCertificate, nil
}

type ec2InstanceConnectPublicKeyBlock struct {
	SignedData     []string
	ExpirationTime time.Time
	InstanceId     string
	CallerId       string
	RequestId      string
	PublicKey      string
}

func (eicak *Ec2InstanceConnectAuthorizedKeys) filterEc2InstanceConnectPublicKeys(ctx context.Context, opts authorizedkeys.GetOptions, instanceIdentityDocument *imds.InstanceIdentityDocument, signerCertificate *x509.Certificate) []string {
	publicKeysOutput, err := eicak.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("managed-ssh-keys/active-keys/%s", opts.User)})
	if err != nil {
		slog.Warn("Couldn't get EC2 Instance Connect public keys. Skipping keys.", "error", err)
		return []string{}
	}

	authorizedKeys := []string{}

	currentTime := time.Now()
	publicKeyBlock := ec2InstanceConnectPublicKeyBlock{}

	// The IMDS endpoint for EC2 Instance Connect public keys returns OpenSSH authorized_keys file contents with public keys sandwiched by metadata comments and a base64-encoded signature.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	// https://www.mankier.com/8/sshd#Authorized_keys_File_Format
	publicKeysContent := bufio.NewScanner(publicKeysOutput.Content)
	for publicKeysContent.Scan() {
		line := publicKeysContent.Text()

		if strings.HasPrefix(line, "#") {
			// Public key block started before a previous one ended.
			if publicKeyBlock.PublicKey != "" {
				publicKeyBlock = ec2InstanceConnectPublicKeyBlock{}
			}

			publicKeyBlock.SignedData = append(publicKeyBlock.SignedData, line)

			if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix) {
				expirationTimestamp, err := strconv.ParseInt(strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataExpirationTimestampPrefix), 10, 64)
				if err != nil {
					slog.Error("Couldn't parse EC2 Instance Connect expiration timestamp.", "metadatum", line)
				} else {
					publicKeyBlock.ExpirationTime = time.Unix(expirationTimestamp, 0)
				}
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix) {
				publicKeyBlock.InstanceId = strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataInstanceIdPrefix)
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataCallerIdPrefix) {
				publicKeyBlock.CallerId = strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataCallerIdPrefix)
			} else if strings.HasPrefix(line, ec2InstanceConnectPublicKeyMetadataRequestIdPrefix) {
				publicKeyBlock.RequestId = strings.TrimPrefix(line, ec2InstanceConnectPublicKeyMetadataRequestIdPrefix)
			}
		} else if publicKeyBlock.PublicKey == "" {
			publicKeyBlock.SignedData = append(publicKeyBlock.SignedData, line)

			publicKeyBlock.PublicKey = line
		} else {
			if signature, err := base64.StdEncoding.DecodeString(line); err != nil {
				slog.Warn("Couldn't decode EC2 Instance Connect public key block signature. Skipping key.", "error", err, "signature", line, "block", publicKeyBlock)
			} else {
				if publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyBlock.PublicKey)); err != nil {
					slog.Warn("Couldn't parse EC2 Instance Connect public key. Skipping key.", "error", err, "block", publicKeyBlock)
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

					if publicKeyBlock.ExpirationTime.Before(currentTime) {
						slog.Warn("EC2 Instance Connect public key is expired. Skipping key.", "block", publicKeyBlock)
					} else if publicKeyBlock.InstanceId != instanceIdentityDocument.InstanceID {
						slog.Warn("EC2 Instance Connect public key is for another EC2 instance. Skipping key.", "block", publicKeyBlock)
					} else if opts.Fingerprint != "" && publicKeyFingerprint != opts.Fingerprint {
						slog.Warn("EC2 Instance Connect public key fingerprint doesn't match specified fingerprint. Skipping key.", "block", publicKeyBlock)
					} else {
						// Each signed data line (including the last) is newline-terminated.
						signedData := []byte(strings.Join(publicKeyBlock.SignedData, "\n") + "\n")
						if err := signerCertificate.CheckSignature(x509.SHA256WithRSAPSS, signedData, signature); err != nil {
							slog.Warn("EC2 Instance Connect public key block signature check failed. Skipping key.", "error", err, "signature", line, "block", publicKeyBlock)
						} else {
							authorizedKeys = append(authorizedKeys, publicKeyBlock.PublicKey)
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
