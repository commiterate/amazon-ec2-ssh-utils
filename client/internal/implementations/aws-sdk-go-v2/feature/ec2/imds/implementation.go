package imds

import (
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	imdsInterface "github.com/commiterate/amazon-ec2-ssh-utils/client/internal/interfaces/aws-sdk-go-v2/feature/ec2/imds"
)

// Implementation is external. Only check interface conformity.

// Check interface conformity.
var _ imdsInterface.ImdsClient = (*imds.Client)(nil)
