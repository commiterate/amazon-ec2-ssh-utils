package imds

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// The AWS SDK for Go v2 doesn't provide client interfaces we can use for testing. Creating our own.
//
// https://aws.github.io/aws-sdk-go-v2/docs/unit-testing
type ImdsClient interface {
	GetDynamicData(ctx context.Context, params *imds.GetDynamicDataInput, optFns ...func(*imds.Options)) (*imds.GetDynamicDataOutput, error)
	GetIAMInfo(ctx context.Context, params *imds.GetIAMInfoInput, optFns ...func(*imds.Options)) (*imds.GetIAMInfoOutput, error)
	GetInstanceIdentityDocument(ctx context.Context, params *imds.GetInstanceIdentityDocumentInput, optFns ...func(*imds.Options)) (*imds.GetInstanceIdentityDocumentOutput, error)
	GetMetadata(ctx context.Context, params *imds.GetMetadataInput, optFns ...func(*imds.Options)) (*imds.GetMetadataOutput, error)
	GetRegion(ctx context.Context, params *imds.GetRegionInput, optFns ...func(*imds.Options)) (*imds.GetRegionOutput, error)
	GetUserData(ctx context.Context, params *imds.GetUserDataInput, optFns ...func(*imds.Options)) (*imds.GetUserDataOutput, error)
}
