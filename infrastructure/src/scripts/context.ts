import * as fs from 'fs'
import * as aws_ssm from '@aws-sdk/client-ssm'

/*
 * Creates the `cdk.context.json` file.
 */

const regions: string[] = Array.from(new Set([
	'us-west-2',
]))

const ssmClient = (() => {
	const cache: {
		[key: string]: aws_ssm.SSMClient
	} = {}
	return (region: string): aws_ssm.SSMClient => {
		cache[region] = cache[region] ?? new aws_ssm.SSMClient({
			region: region,
		})
		return cache[region]
	}
})()

const ssmPublicParameters: {
	// SSM public parameter ARN to value.
	[key: string]: string
} = (await Promise.all(regions.map(region => ssmClient(region)
	.send(new aws_ssm.GetParametersCommand({
		Names: [
			// Amazon Linux 2023.
			'/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64',
			'/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
			// macOS 15 (Sequoia).
			'/aws/service/ec2-macos/sequoia/arm64_mac/latest/image_id',
			'/aws/service/ec2-macos/sequoia/x86_64_mac/latest/image_id',
			// Windows Server Core 2025.
			'/aws/service/ami-windows-latest/Windows_Server-2025-English-Core-Base',
		],
	}))))).flatMap(output => output.Parameters ?? [])
	.reduce((parameters: {
		[key: string]: string
	}, parameter) => {
		if (parameter.ARN !== undefined && parameter.Value !== undefined) {
			parameters[parameter.ARN] = parameter.Value
		}
		return parameters
	}, {})

fs.writeFileSync('cdk.context.json', JSON.stringify({
	...ssmPublicParameters,
}, null, '\t') + '\n')
