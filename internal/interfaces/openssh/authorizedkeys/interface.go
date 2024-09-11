package authorizedkeys

import (
	"context"
	"crypto/x509"
)

type AuthorizedKeys interface {
	// Gets authorized keys for a user with an optional fingerprint. Keys are formatted as OpenSSH authorized_keys file lines.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	//
	// Root certificate pool is optional (intended for unit tests).
	Get(ctx context.Context, user *string, fingerprint *string, rootCertificatePool *x509.CertPool) []string
}
