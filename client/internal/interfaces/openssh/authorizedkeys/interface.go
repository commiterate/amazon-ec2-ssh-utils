package authorizedkeys

import (
	"context"
)

type GetOptions struct {
	Fingerprint string
	User        string
}

type AuthorizedKeys interface {
	// Get authorized keys formatted as OpenSSH `authorized_keys` file lines.
	//
	// https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
	Get(ctx context.Context, opts GetOptions) []string
}
