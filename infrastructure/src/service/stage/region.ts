// ⚠️ Only require superdomains.
import * as aws_cdk_lib from 'aws-cdk-lib'
import {
	aws_ec2,
	aws_iam,
	aws_imagebuilder,
	aws_logs,
	aws_resourcegroups,
	aws_s3,
	aws_ssm,
} from 'aws-cdk-lib'
import * as confbox from 'confbox'
import * as service from '../../service'
import * as utils_aws from '../../utils/aws'
import * as utils_domain from '../../utils/domain'
import * as utils_nix from '../../utils/nix'
import * as utils_platform from '../../utils/platform'

export const stacks = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_cdk_lib.Stack => {
	const [
		,
		,
		region,
	] = domainPath
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.cloudformation.stack',
	})
	const name = utils_aws.tagsToName(tags)
	// Stack IDs should be human-readable.
	return new aws_cdk_lib.Stack(service.app, utils_domain.domainPathName(domainPath), {
		description: 'amazon-ec2-ssh-utils region stratum.',
		env: {
			account: region.data.account,
			region: region.data.name,
		},
		stackName: name,
		tags: tags,
	})
})

export const resourceGroups = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_resourcegroups.CfnGroup => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.resource_groups.resource_group',
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_resourcegroups.CfnGroup(stacks(domainPath), name, {
		description: 'amazon-ec2-ssh-utils region domain.',
		// Resource group names should be human-readable.
		name: utils_domain.domainPathName(domainPath),
		resourceQuery: {
			query: {
				tagFilters: Object.entries(utils_aws.tags({
					domainPath,
				}))
					.map(([
						key,
						value,
					]) => {
						return {
							key,
							values: [
								value,
							],
						}
					}),
			},
			type: 'TAG_FILTERS_1_0',
		},
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const githubActionsOIDCProviders = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnOIDCProvider | undefined => {
	const [
		,
		stage,
	] = domainPath
	if (stage.data.pipeline) {
		const tags = utils_aws.tags({
			domainPath,
			resource: 'aws.iam.oidc_provider.github_actions',
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_iam.CfnOIDCProvider(stacks(domainPath), name, {
			clientIdList: [
				aws_iam.ServicePrincipal.servicePrincipalName('sts'),
			],
			tags: Object.entries(tags)
				.map(([
					key,
					value,
				]) => {
					return {
						key,
						value,
					}
				}),
			// https://github.blog/changelog/2023-06-27-github-actions-update-on-oidc-integration-with-aws
			thumbprintList: [
				'1c58a3a8518e8759bf075b76b750d4f2df264fcd',
				'6938fd4d98bab03faadb97b34396831e3780aea1',
			],
			url: 'https://token.actions.githubusercontent.com',
		})
	}
	else {
		return undefined
	}
})

export const githubActionsRoles = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnRole | undefined => {
	const [
		,
		stage,
	] = domainPath
	if (stage.data.pipeline) {
		const tags = utils_aws.tags({
			domainPath,
			resource: 'aws.iam.role.github_actions',
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_iam.CfnRole(stacks(domainPath), name, {
			assumeRolePolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Effect: 'Allow',
						Principal: {
							Federated: githubActionsOIDCProviders(domainPath)?.attrArn,
						},
						Action: 'sts:AssumeRoleWithWebIdentity',
						Condition: {
							StringEquals: {
								'token.actions.githubusercontent.com:aud': aws_iam.ServicePrincipal.servicePrincipalName('sts'),
								'token.actions.githubusercontent.com:sub': `repo:${service.pushedSelfNixFlakeReference.owner}/${service.pushedSelfNixFlakeReference.repo}:ref:refs/heads/main`,
							},
						},
					},
				],
			},
			description: 'amazon-ec2-ssh-utils GitHub Actions.',
			managedPolicyArns: [
				aws_iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess').managedPolicyArn,
			],
			roleName: name,
			tags: Object.entries(tags)
				.map(([
					key,
					value,
				]) => {
					return {
						key,
						value,
					}
				}),
		})
	}
	else {
		return undefined
	}
})

export const testKeyPairs = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_ec2.CfnKeyPair => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.ec2.key_pair.test',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_ec2.CfnKeyPair(stacks(domainPath), name, {
		keyFormat: 'pem',
		keyName: name,
		keyType: 'ed25519',
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderLogGroups = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_logs.CfnLogGroup => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.cloudwatch.log_group.image_builder',
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_logs.CfnLogGroup(stacks(domainPath), name, {
		logGroupName: name,
		retentionInDays: 30,
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderLogBuckets = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_s3.CfnBucket => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.s3.bucket.image_builder_log',
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_s3.CfnBucket(stacks(domainPath), name, {
		bucketName: name,
		lifecycleConfiguration: {
			rules: [
				{
					status: 'Enabled',
					abortIncompleteMultipartUpload: {
						daysAfterInitiation: 1,
					},
					expirationInDays: 30,
				},
			],
		},
		publicAccessBlockConfiguration: {
			blockPublicAcls: true,
			blockPublicPolicy: true,
			ignorePublicAcls: true,
			restrictPublicBuckets: true,
		},
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderInstanceRoles = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnRole => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.iam.role.image_builder_instance',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_iam.CfnRole(stacks(domainPath), name, {
		assumeRolePolicyDocument: {
			Version: '2012-10-17',
			Statement: [
				{
					Effect: 'Allow',
					Principal: {
						Service: aws_iam.ServicePrincipal.servicePrincipalName('ec2'),
					},
					Action: 'sts:AssumeRole',
				},
			],
		},
		description: 'amazon-ec2-ssh-utils Image Builder instance.',
		policies: [
			/*
			 * Derivative of the EC2InstanceProfileForImageBuilder + AmazonSSMManagedInstanceCore AWS-managed policies.
			 *
			 * Scopes down and stops Image Builder from creating CloudWatch log groups with infinite retention.
			 */
			{
				policyDocument: {
					Version: '2012-10-17',
					Statement: [
						// EC2InstanceProfileForImageBuilder subset.
						{
							Effect: 'Allow',
							Action: [
								'ec2:DescribeSnapshots',
								'ec2:DescribeVolumes',
							],
							Resource: '*',
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CreateSnapshot',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'snapshot',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'volume',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CreateTags',
							Resource: '*',
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': 'EC2 Image Builder',
									'ec2:CreateAction': 'CreateSnapshot',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 's3:GetObject',
							Resource: stacks(domainPath)
								.formatArn({
									service: 's3',
									region: '',
									account: '',
									resource: '*',
									resourceName: '*.ISO',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									's3:ResourceAccount': '${aws.PrincipalAccount}',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: [
								'imagebuilder:GetComponent',
								'imagebuilder:GetMarketplaceResource',
							],
							Resource: '*',
							Condition: {
								'ForAnyValue:StringEquals': {
									'kms:EncryptionContextKeys': 'aws:imagebuilder:arn',
									'aws:CalledVia': aws_iam.ServicePrincipal.servicePrincipalName('imagebuilder'),
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 's3:GetObject',
							Resource: stacks(domainPath)
								.formatArn({
									service: 's3',
									region: '',
									account: '',
									resource: 'ec2imagebuilder*',
									arnFormat: aws_cdk_lib.ArnFormat.NO_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									's3:ResourceAccount': '${aws:PrincipalAccount}',
								},
							},
						},
						// AmazonSSMManagedInstanceCore subset.
						{
							Effect: 'Allow',
							Action: [
								'ssm:UpdateInstanceInformation',
								'ssmmessages:CreateControlChannel',
								'ssmmessages:CreateDataChannel',
								'ssmmessages:OpenControlChannel',
								'ssmmessages:OpenDataChannel',
							],
							Resource: '*',
						},
						// EC2 Instance Connect.
						{
							Effect: 'Allow',
							Action: 'ec2-instance-connect:SendSSHPublicKey',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									resource: 'instance',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: Object.fromEntries(Object.entries(utils_aws.tags({
									domainPath,
								}))
									.map(([
										key,
										value,
									]) => [
										`aws:ResourceTag/${key}`,
										value,
									])),
							},
						},
						// Key pair.
						{
							Effect: 'Allow',
							Action: [
								'ssm:GetParameter',
								'ssm:GetParameters',
							],
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ssm',
									resource: 'parameter',
									resourceName: `ec2/keypair/${testKeyPairs(domainPath).attrKeyPairId}`,
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
						},
						// Logs CloudWatch log group.
						{
							Effect: 'Allow',
							Action: [
								'logs:CreateLogStream',
								'logs:PutLogEvents',
							],
							Resource: imageBuilderLogGroups(domainPath).attrArn,
						},
						// Logs S3 bucket.
						{
							Effect: 'Allow',
							Action: [
								's3:AbortMultipartUpload',
								's3:CompleteMultipartUpload',
								's3:CreateMultipartUpload',
								's3:PutObject',
								's3:UploadPart',
							],
							Resource: stacks(domainPath)
								.formatArn({
									service: 's3',
									region: '',
									account: '',
									resource: imageBuilderLogBuckets(domainPath).ref,
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									's3:ResourceAccount': stacks(domainPath).account,
								},
							},
						},
					],
				},
				policyName: 'inline',
			},
		],
		roleName: name,
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderInstanceProfiles = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnInstanceProfile => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.iam.instance_profile.image_builder_instance',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_iam.CfnInstanceProfile(stacks(domainPath), name, {
		instanceProfileName: name,
		roles: [
			imageBuilderInstanceRoles(domainPath).ref,
		],
	})
})

export const imageBuilderSecurityGroups = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_ec2.CfnSecurityGroup => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.ec2.security_group.image_builder',
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_ec2.CfnSecurityGroup(stacks(domainPath), name, {
		groupDescription: 'amazon-ec2-ssh-utils Image Builder.',
		groupName: name,
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderAllIpv4SecurityGroupEgresses = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_ec2.CfnSecurityGroupEgress => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.ec2.security_group_egress.image_builder_all_ipv4',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_ec2.CfnSecurityGroupEgress(stacks(domainPath), name, {
		groupId: imageBuilderSecurityGroups(domainPath).attrGroupId,
		ipProtocol: '-1',
		cidrIp: '0.0.0.0/0',
		description: 'All IPv4 traffic.',
	})
})

export const imageBuilderAllIpv6SecurityGroupEgresses = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_ec2.CfnSecurityGroupEgress => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.ec2.security_group_egress.image_builder_all_ipv6',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_ec2.CfnSecurityGroupEgress(stacks(domainPath), name, {
		groupId: imageBuilderSecurityGroups(domainPath).attrGroupId,
		ipProtocol: '-1',
		cidrIpv6: '::/0',
		description: 'All IPv6 traffic.',
	})
})

/**
 * Strict variant of `aws_ec2.CfnLaunchTemplate.LaunchTemplateDataProperty` for sharing between:
 *
 * - `aws_ec2.CfnLaunchTemplate`
 * - `aws_imagebuilder.CfnImageRecipe`
 * - `aws_imagebuilder.CfnInfrastructureConfiguration`
 */
interface StrictLaunchTemplateDataProperty extends aws_ec2.CfnLaunchTemplate.LaunchTemplateDataProperty {
	blockDeviceMappings: aws_ec2.CfnLaunchTemplate.BlockDeviceMappingProperty[]
	iamInstanceProfile: {
		name: string
	}
	imageId: string
	instanceType: string
	keyName: string
	metadataOptions: aws_ec2.CfnLaunchTemplate.MetadataOptionsProperty & {
		httpTokens: string
	}
	securityGroupIds: string[]
}

export const testManualLaunchTemplateData = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => StrictLaunchTemplateDataProperty => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): StrictLaunchTemplateDataProperty => {
		return {
			blockDeviceMappings: [
				{
					deviceName: (() => {
						switch (platform.supervisor) {
							case utils_platform.Supervisor.AMAZON_LINUX:
								return '/dev/xvda'
							case utils_platform.Supervisor.MACOS:
							case utils_platform.Supervisor.WINDOWS:
								return '/dev/sda1'
						}
					})(),
					ebs: {
						deleteOnTermination: true,
						volumeSize: 64,
						volumeType: 'gp3',
					},
				},
			],
			iamInstanceProfile: {
				name: imageBuilderInstanceProfiles(domainPath).ref,
			},
			imageId: (() => {
				switch (platform.supervisor) {
					case utils_platform.Supervisor.AMAZON_LINUX:
						return service.app.node.getContext(stacks(domainPath)
							.formatArn({
								service: 'ssm',
								account: '',
								resource: 'parameter',
								resourceName: (() => {
									switch (platform.hardware) {
										case utils_platform.Hardware.AARCH64:
											return 'aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64'
										case utils_platform.Hardware.X86_64:
											return 'aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
									}
								})(),
								arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
							}))
					case utils_platform.Supervisor.MACOS:
						return service.app.node.getContext(stacks(domainPath)
							.formatArn({
								service: 'ssm',
								account: '',
								resource: 'parameter',
								resourceName: (() => {
									switch (platform.hardware) {
										case utils_platform.Hardware.AARCH64:
											return 'aws/service/ec2-macos/sequoia/arm64_mac/latest/image_id'
										case utils_platform.Hardware.X86_64:
											return 'aws/service/ec2-macos/sequoia/x86_64_mac/latest/image_id'
									}
								})(),
								arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
							}))
					case utils_platform.Supervisor.WINDOWS:
						return service.app.node.getContext(stacks(domainPath)
							.formatArn({
								service: 'ssm',
								account: '',
								resource: 'parameter',
								resourceName: (() => {
									switch (platform.hardware) {
										case utils_platform.Hardware.X86_64:
											return 'aws/service/ami-windows-latest/Windows_Server-2025-English-Core-Base'
										default:
											throw new Error('No parent image for hardware!')
									}
								})(),
								arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
							}))
				}
			})(),
			instanceInitiatedShutdownBehavior: 'terminate',
			instanceType: utils_platform.instanceTypes(domainPath)(platform),
			keyName: testKeyPairs(domainPath).ref,
			metadataOptions: {
				httpEndpoint: 'enabled',
				httpProtocolIpv6: 'disabled',
				httpTokens: 'required',
				instanceMetadataTags: 'disabled',
			},
			securityGroupIds: [
				imageBuilderSecurityGroups(domainPath).attrGroupId,
			],
			tagSpecifications: [
				{
					resourceType: 'instance',
					tags: Object.entries(utils_aws.tags({
						platform,
						domainPath,
						resource: 'aws.ec2.instance.test_manual',
						time: service.selfNixFlakeRevision,
					}))
						.map(([
							key,
							value,
						]) => {
							return {
								key,
								value,
							}
						}),
				},
			],
		}
	})
})

/**
 * Manual testing launch templates.
 *
 * Comment out the test EC2 Image Builder recipes to deploy only these for manual debugging.
 */
export const testManualLaunchTemplates = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_ec2.CfnLaunchTemplate => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_ec2.CfnLaunchTemplate => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.ec2.launch_template.test_manual',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_ec2.CfnLaunchTemplate(stacks(domainPath), name, {
			launchTemplateData: testManualLaunchTemplateData(domainPath)(platform),
			launchTemplateName: name,
			tagSpecifications: [
				{
					resourceType: 'launch-template',
					tags: Object.entries(tags)
						.map(([
							key,
							value,
						]) => {
							return {
								key,
								value,
							}
						}),
				},
			],
		})
	})
})

export const testImageRecipes = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_imagebuilder.CfnImageRecipe => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_imagebuilder.CfnImageRecipe => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.image_builder.image_recipe.test',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		const launchTemplateData = testManualLaunchTemplateData(domainPath)(platform)
		return new aws_imagebuilder.CfnImageRecipe(stacks(domainPath), name, {
			additionalInstanceConfiguration: {
				// Keep the SSM agent for debugging with the SSM Session Manager web terminal.
				systemsManagerAgent: {
					uninstallAfterBuild: false,
				},
			},
			blockDeviceMappings: launchTemplateData.blockDeviceMappings,
			description: 'amazon-ec2-ssh-utils test.',
			name,
			parentImage: launchTemplateData.imageId,
			tags,
			version: '0.0.0',
		})
	})
})

export const testInfrastructureConfigurations = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_imagebuilder.CfnInfrastructureConfiguration => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_imagebuilder.CfnInfrastructureConfiguration => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.image_builder.infrastructure_configuration.test',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		const launchTemplateData = testManualLaunchTemplateData(domainPath)(platform)
		return new aws_imagebuilder.CfnInfrastructureConfiguration(stacks(domainPath), name, {
			description: 'amazon-ec2-ssh-utils test.',
			instanceMetadataOptions: {
				httpTokens: launchTemplateData.metadataOptions.httpTokens,
			},
			instanceProfileName: launchTemplateData.iamInstanceProfile.name,
			instanceTypes: [
				launchTemplateData.instanceType,
			],
			keyPair: launchTemplateData.keyName,
			logging: {
				s3Logs: {
					s3BucketName: imageBuilderLogBuckets(domainPath).ref,
				},
			},
			name,
			resourceTags: utils_aws.tags({
				platform,
				domainPath,
				resource: 'aws.ec2.instance.test_image_builder',
				time: service.selfNixFlakeRevision,
			}),
			securityGroupIds: launchTemplateData.securityGroupIds,
			tags,
			terminateInstanceOnFailure: true,
		})
	})
})

export const testDocuments = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_ssm.CfnDocument => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_ssm.CfnDocument => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.ssm.document.test',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_ssm.CfnDocument(stacks(domainPath), name, {
			content: {
				schemaVersion: '2.2',
				mainSteps: [
					(() => {
						switch (platform.supervisor) {
							case utils_platform.Supervisor.AMAZON_LINUX:
								return {
									action: 'aws:runShellScript',
									name: 'main',
									inputs: {
										/*
										 * We use the AWS-managed Amazon Linux AMIs.
										 *
										 * Assumptions:
										 *
										 * - Only Bash, GNU coreutils, the built-in Linux package manager (DNF), systemd, and the AWS SSM Agent are installed by default.
										 * - The AWS SSM Agent runs as root.
										 *
										 * Applications we use can be packaged as Nix or RPM packages.
										 * - Nix Packages
										 *   - Preferred format.
										 *   - Managed with the Nix package manager.
										 *   - Sourced from flakes in the flake registry (`nix registry`).
										 *     - We lock these with `nix registry add {flake ID} {flake reference}`.
										 *       - We control the revision with this project's flake.
										 *   - Installed with `nix profile install {flake ID}#{package}`.
										 * - RPM Packages
										 *   - Only use for Nix dependencies (e.g. cURL, Git).
										 *   - Managed with the built-in package manager (DNF).
										 *   - Sourced from the Amazon Linux repository.
										 *     - This is locked to a specific version by the AMI.
										 *   - Installed with `dnf install {package}`.
										 */
										runCommand: [
											// Install RPM packages.
											[
												'dnf',
												'install',
												'--assumeyes',
												// cURL.
												'curl-minimal',
												// Git.
												'git',
											].join(' '),
											// Install Nix.
											[
												'curl',
												'--fail',
												'--location',
												utils_nix.DETERMINATE_NIX_INSTALLER_URL,
												'--proto',
												'\'=https\'',
												'--show-error',
												'--silent',
												'--tlsv1.2',
												'|',
												'sh',
												'-s',
												'--',
												'install',
												'--no-confirm',
											].join(' '),
											'. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh',
											// Setup Nix flake registry.
											[
												'nix',
												'registry',
												'add',
												'nixpkgs',
												utils_nix.flakeReferenceToURL(utils_nix.getFlakeInput(service.nixFlakeMetadata, 'nixpkgs')),
											].join(' '),
											[
												'nix',
												'registry',
												'add',
												'system-manager',
												utils_nix.flakeReferenceToURL(utils_nix.getFlakeInput(service.nixFlakeMetadata, 'system-manager')),
											].join(' '),
											// Install Nix packages.
											[
												'nix',
												'profile',
												'install',
												// system-manager.
												'system-manager',
											].join(' '),
											// Apply system-manager configuration.
											[
												'system-manager',
												'switch',
												'--flake',
												`'${utils_nix.flakeReferenceToURL(service.pushedSelfNixFlakeReference)}#${service.platformToNixFlakeOutputKey(platform)}'`,
											].join(' '),
											// Run tests.
											`su -l ec2-user -c 'EC2_KEY_PAIR_PRIVATE_KEY_SSM_PARAMETER=${stacks(domainPath)
												.formatArn({
													service: 'ssm',
													resource: 'parameter',
													resourceName: `ec2/keypair/${testKeyPairs(domainPath).attrKeyPairId}`,
													arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
												})} amazon-ec2-ssh-utils-tests'`,
										],
										timeoutSeconds: 20 * 60,
									},
								}
							case utils_platform.Supervisor.MACOS:
								return {
									action: 'aws:runShellScript',
									name: 'main',
									inputs: {
										/*
										 * We use the AWS-managed macOS AMIs.
										 *
										 * Assumptions:
										 *
										 * - Only Zsh, GNU coreutils, the Homebrew package manager, launchd, and the AWS SSM Agent are installed by default.
										 * - The AWS SSM Agent runs as root.
										 *
										 * Applications we use can be packaged as Nix or Homebrew packages.
										 *
										 * - Nix Packages
										 *   - Preferred format.
										 *   - Managed with the Nix package manager.
										 *   - Sourced from flakes in the flake registry (`nix registry`).
										 *     - We lock these with `nix registry add {flake ID} {flake reference}`.
										 *       - We control the revision with this project's flake.
										 *   - Installed with `nix profile install {flake ID}#{package}`.
										 * - Homebrew Packages
										 *   - Only use for Nix dependencies (e.g. cURL, Git).
										 *   - Managed with the built-in package manager (Homebrew).
										 *   - Sourced from the Homebrew and aws/homebrew-aws repositories/taps.
										 *   - Installed with `brew install {package}`.
										 */
										runCommand: [
											// Install RPM packages.
											[
												'yes',
												'|',
												'brew',
												'install',
												// cURL.
												'curl',
												// Git.
												'git',
											].join(' '),
											// Install Nix.
											[
												'curl',
												'--fail',
												'--location',
												utils_nix.DETERMINATE_NIX_INSTALLER_URL,
												'--proto',
												'\'=https\'',
												'--show-error',
												'--silent',
												'--tlsv1.2',
												'|',
												'sh',
												'-s',
												'--',
												'install',
												'--no-confirm',
											].join(' '),
											'. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh',
											// Setup Nix flake registry.
											[
												'nix',
												'registry',
												'add',
												'nixpkgs',
												utils_nix.flakeReferenceToURL(utils_nix.getFlakeInput(service.nixFlakeMetadata, 'nixpkgs')),
											].join(' '),
											[
												'nix',
												'registry',
												'add',
												'nix-darwin',
												utils_nix.flakeReferenceToURL(utils_nix.getFlakeInput(service.nixFlakeMetadata, 'nix-darwin')),
											].join(' '),
											// Install Nix packages.
											[
												'nix',
												'profile',
												'install',
												// nix-darwin.
												'nix-darwin',
											].join(' '),
											// Apply nix-darwin configuration.
											[
												'darwin-rebuild',
												'switch',
												'--flake',
												`'${utils_nix.flakeReferenceToURL(service.pushedSelfNixFlakeReference)}#${service.platformToNixFlakeOutputKey(platform)}'`,
											].join(' '),
											// Run tests.
											`su -l ec2-user -c 'EC2_KEY_PAIR_PRIVATE_KEY_SSM_PARAMETER=${stacks(domainPath)
												.formatArn({
													service: 'ssm',
													resource: 'parameter',
													resourceName: `ec2/keypair/${testKeyPairs(domainPath).attrKeyPairId}`,
													arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
												})} amazon-ec2-ssh-utils-tests'`,
										],
										timeoutSeconds: 20 * 60,
									},
								}
							case utils_platform.Supervisor.WINDOWS:
								return {
									action: 'aws:runPowerShellScript',
									name: 'main',
									inputs: {
										/*
										 * We use the AWS-managed Windows Server AMIs.
										 *
										 * Assumptions:
										 *
										 * - Only PowerShell, the PowerShell base modules, WinGet package manager, Windows Services Manager, and the AWS SSM Agent are installed by default.
										 * - The AWS SSM Agent runs as SYSTEM.
										 *
										 * Applications we use can be packaged as WinGet packages.
										 *
										 * - WinGet Packages
										 *   - Preferred format.
										 *   - Managed with the WinGet package manager.
										 *   - Sourced from the winget-pkgs repository.
										 *   - Installed with `winget install --id {package}`.
										 */
										runCommand: ((): string[] => {
											const wingetDscConfigurationFile = 'configuration.dsc.yaml'
											return [
												[
													'@"',
													// TODO: Add WinGet DSC configuration file.
													'',
													`"@ | Out-File -FilePath ${wingetDscConfigurationFile}`,
												].join('\n'),
												`winget configure --disable-interactivity --file ${wingetDscConfigurationFile}`,
												`Remove-Item -Path ${wingetDscConfigurationFile}`,
												// Run tests.
												`$env:EC2_KEY_PAIR_PRIVATE_KEY_SSM_PARAMETER='${stacks(domainPath)
													.formatArn({
														service: 'ssm',
														resource: 'parameter',
														resourceName: `ec2/keypair/${testKeyPairs(domainPath).attrKeyPairId}`,
														arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
													})}'`,
												'amazon-ec2-ssh-utils-tests',
												'Remove-Item Env:\\EC2_KEY_PAIR_PRIVATE_KEY_SSM_PARAMETER',
											]
										})(),
										timeoutSeconds: 20 * 60,
									},
								}
						}
					})(),
				],
			},
			documentFormat: 'JSON',
			documentType: 'Command',
			name,
			tags: Object.entries(tags)
				.map(([
					key,
					value,
				]) => {
					return {
						key,
						value,
					}
				}),
			targetType: '/AWS::EC2::Instance',
			updateMethod: 'Replace',
		})
	})
})

export const testWorkflows = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_imagebuilder.CfnWorkflow => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_imagebuilder.CfnWorkflow => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.image_builder.workflow.test',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_imagebuilder.CfnWorkflow(stacks(domainPath), name, {
			data: confbox.stringifyYAML({
				name,
				schemaVersion: '1.0',
				steps: [
					{
						action: 'LaunchInstance',
						name: 'launchInstance',
						inputs: {
							waitFor: 'ssmAgent',
						},
						timeoutSeconds: 10 * 60,
					},
					{
						action: 'RunCommand',
						name: 'setupInstance',
						inputs: {
							'documentName': testDocuments(domainPath)(platform).ref,
							'instanceId.$': '$.stepOutputs.launchInstance.instanceId',
							'parameters': {},
						},
					},
					{
						action: ((): string => {
							switch (platform.supervisor) {
								case utils_platform.Supervisor.WINDOWS:
									return 'RunSysPrep'
								default:
									return 'SanitizeInstance'
							}
						})(),
						name: 'cleanupInstance',
						inputs: {
							'instanceId.$': '$.stepOutputs.launchInstance.instanceId',
						},
					},
					{
						action: 'CreateImage',
						name: 'createImage',
						inputs: {
							'instanceId.$': '$.stepOutputs.launchInstance.instanceId',
						},
					},
					{
						action: 'TerminateInstance',
						name: 'terminateInstance',
						inputs: {
							'instanceId.$': '$.stepOutputs.launchInstance.instanceId',
						},
						timeoutSeconds: 10 * 60,
					},
				],
				outputs: [
					{
						name: 'ImageId',
						value: '$.stepOutputs.createImage.imageId',
					},
				],
			}),
			description: 'amazon-ec2-ssh-utils test.',
			name,
			tags,
			type: 'BUILD',
			version: '0.0.0',
		})
	})
})

export const imageBuilderLifecycleRoles = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnRole => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.iam.role.image_builder_lifecycle',
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_iam.CfnRole(stacks(domainPath), name, {
		assumeRolePolicyDocument: {
			Version: '2012-10-17',
			Statement: [
				{
					Effect: 'Allow',
					Principal: {
						Service: aws_iam.ServicePrincipal.servicePrincipalName('imagebuilder'),
					},
					Action: 'sts:AssumeRole',
				},
			],
		},
		description: 'amazon-ec2-ssh-utils Image Builder lifecycle.',
		managedPolicyArns: [
			aws_iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/EC2ImageBuilderLifecycleExecutionPolicy').managedPolicyArn,
		],
		roleName: name,
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const imageBuilderRoles = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): aws_iam.CfnRole => {
	const tags = utils_aws.tags({
		domainPath,
		resource: 'aws.iam.role.image_builder',
		time: service.selfNixFlakeRevision,
	})
	const name = utils_aws.tagsToName(tags)
	return new aws_iam.CfnRole(stacks(domainPath), name, {
		assumeRolePolicyDocument: {
			Version: '2012-10-17',
			Statement: [
				{
					Effect: 'Allow',
					Principal: {
						Service: aws_iam.ServicePrincipal.servicePrincipalName('imagebuilder'),
					},
					Action: 'sts:AssumeRole',
				},
			],
		},
		description: 'amazon-ec2-ssh-utils Image Builder.',
		policies: [
			/*
			 * Derivative of the EC2InstanceProfileForImageBuilder + AmazonSSMManagedInstanceCore AWS-managed policies.
			 *
			 * Scopes down and stops Image Builder from creating CloudWatch log groups with infinite retention.
			 */
			{
				policyDocument: {
					Version: '2012-10-17',
					Statement: [
						/*
						 * Derivative of the AWSServiceRoleForImageBuilder AWS-managed policy.
						 *
						 * Scopes down and stops Image Builder from creating:
						 *
						 * - CloudWatch log groups with infinite retention.
						 * - ECR resources.
						 * - EventBridge resources.
						 * - IAM service-linked roles.
						 * - SNS messages.
						 *
						 * TODO: Scope down further.
						 */
						{
							Effect: 'Allow',
							Action: 'ec2:RegisterImage',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '',
									resource: 'image',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:RegisterImage',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '',
									resource: 'snapshot',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'aws:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:RunInstances',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '',
										resource: 'image',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '',
										resource: 'snapshot',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'key-pair',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'network-interface',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'security-group',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'subnet',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'license-manager',
										region: '*',
										account: '*',
										resource: 'license-configuration',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.COLON_RESOURCE_NAME,
									}),
							],
						},
						{
							Effect: 'Allow',
							Action: 'ec2:RunInstances',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'instance',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'volume',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': [
										'EC2 Fast Launch',
										'EC2 Image Builder',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'iam:PassRole',
							Resource: '*',
							Condition: {
								StringEquals: {
									'iam:PassedToService': [
										aws_iam.ServicePrincipal.servicePrincipalName('ec2'),
										aws_iam.ServicePrincipal.servicePrincipalName('vmie'),
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: [
								'ec2:StartInstances',
								'ec2:StopInstances',
								'ec2:TerminateInstances',
							],
							Resource: '*',
							Condition: {
								StringEquals: {
									'ec2:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: [
								'ec2:CopyImage',
								'ec2:CreateImage',
								'ec2:CreateLaunchTemplate',
								'ec2:DeregisterImage',
								'ec2:DescribeExportImageTasks',
								'ec2:DescribeHosts',
								'ec2:DescribeImages',
								'ec2:DescribeImportImageTasks',
								'ec2:DescribeInstanceAttribute',
								'ec2:DescribeInstanceStatus',
								'ec2:DescribeInstances',
								'ec2:DescribeInstanceTypeOfferings',
								'ec2:DescribeInstanceTypes',
								'ec2:DescribeSnapshots',
								'ec2:DescribeSubnets',
								'ec2:DescribeTags',
								'ec2:ModifyImageAttribute',
							],
							Resource: '*',
						},
						{
							Effect: 'Allow',
							Action: 'ec2:ModifySnapshotAttribute',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '',
									resource: 'snapshot',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'ec2:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CreateTags',
							Resource: '*',
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': [
										'EC2 Fast Launch',
										'EC2 Image Builder',
									],
									'ec2:CreateAction': [
										'CreateImage',
										'RunInstances',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CreateTags',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '',
										resource: 'image',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'export-image-task',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CreateTags',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '',
										resource: 'snapshot',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'launch-template',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
							Condition: {
								StringEquals: {
									'aws:RequestTag/CreatedBy': [
										'EC2 Fast Launch',
										'EC2 Image Builder',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'license-manager:UpdateLicenseSpecificationsForResource',
							Resource: '*',
						},
						{
							Effect: 'Allow',
							Action: [
								'ssm:AddTagsToResource',
								'ssm:DescribeAssociationExecutions',
								'ssm:DescribeInstanceAssociationsStatus',
								'ssm:DescribeInstanceInformation',
								'ssm:GetAutomationExecution',
								'ssm:GetCommandInvocation',
								'ssm:ListCommandInvocations',
								'ssm:ListCommands',
								'ssm:ListInventoryEntries',
								'ssm:SendAutomationSignal',
								'ssm:StopAutomationExecution',
							],
							Resource: '*',
						},
						{
							Effect: 'Allow',
							Action: 'ssm:SendCommand',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ssm',
										region: '*',
										account: '*',
										resource: 'document',
										resourceName: 'AWS-RunPowerShellScript',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ssm',
										region: '*',
										account: '*',
										resource: 'document',
										resourceName: 'AWS-RunShellScript',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ssm',
										region: '*',
										account: '*',
										resource: 'document',
										resourceName: 'AWSEC2-RunSysPrep',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 's3',
										region: '',
										account: '',
										resource: '*',
										arnFormat: aws_cdk_lib.ArnFormat.NO_RESOURCE_NAME,
									}),
								...Array.from(utils_platform.platforms(domainPath))
									.map((platform): string => stacks(domainPath)
										.formatArn({
											service: 'ssm',
											resource: 'document',
											resourceName: testDocuments(domainPath)(platform).ref,
											arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
										})),
							],
						},
						{
							Effect: 'Allow',
							Action: 'ssm:SendCommand',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '*',
									resource: 'instance',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'ssm:resourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ssm:StartAutomationExecution',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ssm',
									region: '*',
									account: '*',
									resource: 'automation-definition',
									resourceName: 'ImageBuilder*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
						},
						{
							Effect: 'Allow',
							Action: [
								'ssm:CreateAssociation',
								'ssm:DeleteAssociation',
							],
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'instance',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ssm',
										region: '*',
										account: '*',
										resource: 'association',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ssm',
										region: '*',
										account: '*',
										resource: 'document',
										resourceName: 'AWS-GatherSoftwareInventory',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
						},
						{
							Effect: 'Allow',
							Action: [
								'kms:Decrypt',
								'kms:Encrypt',
								'kms:GenerateDataKeyWithoutPlaintext',
								'kms:ReEncryptFrom',
								'kms:ReEncryptTo',
							],
							Resource: '*',
							Condition: {
								'ForAllValues:StringEquals': {
									'kms:EncryptionContextKeys': [
										'aws:ebs:id',
									],
								},
								'StringLike': {
									'kms:ViaService': [
										'ec2.*.amazonaws.com',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'kms:DescribeKey',
							Resource: '*',
							Condition: {
								StringLike: {
									'kms:ViaService': [
										'ec2.*.amazonaws.com',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'kms:CreateGrant',
							Resource: '*',
							Condition: {
								Bool: {
									'kms:GrantIsForAWSResource': true,
								},
								StringLike: {
									'kms:ViaService': [
										'ec2.*.amazonaws.com',
									],
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'sts:AssumeRole',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'iam',
									region: '',
									account: '*',
									resource: 'role',
									resourceName: 'EC2ImageBuilderDistributionCrossAccountRole',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
						},
						{
							Effect: 'Allow',
							Action: [
								'ec2:CreateLaunchTemplateVersion',
								'ec2:DescribeLaunchTemplates',
								'ec2:DescribeLaunchTemplateVersions',
								'ec2:ModifyLaunchTemplate',
							],
							Resource: '*',
						},
						{
							Effect: 'Allow',
							Action: 'ec2:ExportImage',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '',
									resource: 'image',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'ec2:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:ExportImage',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '*',
									resource: 'export-image-task',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
						},
						{
							Effect: 'Allow',
							Action: 'ec2:CancelExportTask',
							Resource: stacks(domainPath)
								.formatArn({
									service: 'ec2',
									region: '*',
									account: '*',
									resource: 'export-image-task',
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									'ec2:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						{
							Effect: 'Allow',
							Action: 'ec2:EnableFastLaunch',
							Resource: [
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '',
										resource: 'image',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
								stacks(domainPath)
									.formatArn({
										service: 'ec2',
										region: '*',
										account: '*',
										resource: 'launch-template',
										resourceName: '*',
										arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
									}),
							],
							Condition: {
								StringEquals: {
									'ec2:ResourceTag/CreatedBy': 'EC2 Image Builder',
								},
							},
						},
						// Logs CloudWatch log group.
						{
							Effect: 'Allow',
							Action: [
								'logs:CreateLogStream',
								'logs:PutLogEvents',
							],
							Resource: imageBuilderLogGroups(domainPath).attrArn,
						},
						// Logs S3 bucket.
						{
							Effect: 'Allow',
							Action: [
								's3:AbortMultipartUpload',
								's3:CompleteMultipartUpload',
								's3:CreateMultipartUpload',
								's3:PutObject',
								's3:UploadPart',
							],
							Resource: stacks(domainPath)
								.formatArn({
									service: 's3',
									region: '',
									account: '',
									resource: imageBuilderLogBuckets(domainPath).ref,
									resourceName: '*',
									arnFormat: aws_cdk_lib.ArnFormat.SLASH_RESOURCE_NAME,
								}),
							Condition: {
								StringEquals: {
									's3:ResourceAccount': stacks(domainPath).account,
								},
							},
						},
					],
				},
				policyName: 'inline',
			},
		],
		roleName: name,
		tags: Object.entries(tags)
			.map(([
				key,
				value,
			]) => {
				return {
					key,
					value,
				}
			}),
	})
})

export const testImages = utils_domain.mapDomainStratumPaths(utils_domain.SERVICE_DOMAIN, utils_domain.DomainType.REGION, (domainPath): (platform: utils_platform.Platform) => aws_imagebuilder.CfnImage => {
	return utils_platform.mapPlatforms(utils_platform.platforms(domainPath), (platform): aws_imagebuilder.CfnImage => {
		const tags = utils_aws.tags({
			platform,
			domainPath,
			resource: 'aws.image_builder.image.test',
			time: service.selfNixFlakeRevision,
		})
		const name = utils_aws.tagsToName(tags)
		return new aws_imagebuilder.CfnImage(stacks(domainPath), name, {
			deletionSettings: {
				executionRole: imageBuilderLifecycleRoles(domainPath).attrArn,
			},
			enhancedImageMetadataEnabled: false,
			executionRole: imageBuilderRoles(domainPath).attrArn,
			imageRecipeArn: testImageRecipes(domainPath)(platform).attrArn,
			imageScanningConfiguration: {
				imageScanningEnabled: false,
			},
			imageTestsConfiguration: {
				imageTestsEnabled: false,
			},
			infrastructureConfigurationArn: testInfrastructureConfigurations(domainPath)(platform).attrArn,
			loggingConfiguration: {
				logGroupName: imageBuilderLogGroups(domainPath).ref,
			},
			tags,
			workflows: [
				{
					workflowArn: testWorkflows(domainPath)(platform).attrArn,
				},
			],
		})
	})
})
