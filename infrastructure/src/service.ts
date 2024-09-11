import * as aws_cdk_lib from 'aws-cdk-lib'
import * as utils_nix from './utils/nix'
import * as utils_platform from './utils/platform'

// ⛔ There should be no service stratum resources.

/*
 * 🔖 Tips for Maintainability
 *
 * - Only use L1 constructs (i.e. `Cfn*` constructs). This:
 * 	- Gives predictable CloudFormation logical IDs.
 * 		- L1 construct IDs are the CloudFormation logical IDs.
 * 		- L2+ construct IDs are derived from chaining + hashing the IDs of the construct and its predecessors. This makes reorganizing constructs difficult.
 * 			- https://docs.aws.amazon.com/cdk/v2/guide/identifiers.html
 * 	- Gives predictable resources.
 * 		- L2+ constructs may magically create additional resources or unexpectedly modify existing resources.
 * 	- Gives access to new properties sooner since the constructs are auto-generated from CloudFormation resource specs.
 * 		- L2+ constructs are hand-written.
 * - Avoid context methods which need credentials (e.g. AMI lookup).
 * 	- Obviates the need for credentials during synthesis.
 * 		- Only one set of credentials is used for all context methods.
 * 			- If context methods are used for multiple accounts, one set of credentials needs access to multiple accounts unless synthesis is split.
 *
 * 🔖 Tips for Cross-Stack Resource References
 *
 * Cross-stack resource references should be by naming convention, not construct references. This prevents automatic stack exports (can cause deployment deadlock).
 *
 * IAM policies for cross-account access should use the following for namespace filtering to avoid circular dependencies:
 *
 * - `Principal` element.
 * 	- AWS account principals (i.e. AWS account IDs).
 * - `Resource` element.
 * 	- Resource ARNs with AWS account IDs (except for partitional resources like S3 buckets).
 * - `Condition` element.
 * 	- `StringEquals` or `StringLike` (for filtering by organization, organizational unit, or resource. Also by account for partitional resources like S3 buckets).
 *
 * Always have an AWS account ID somewhere in the policy to scope them to a specific AWS account.
 *
 * Avoid IAM identity principals in cross-account access policies since they transform to a unique ID. A recreated IAM identity with the same name will have a different unique ID.
 *
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
 *
 * Since they're transformed to a unique ID, the IAM identity principal must exist before it can be referenced in policies. Otherwise, policy creation will fail.
 */

export const app = new aws_cdk_lib.App({
	analyticsReporting: false,
})

console.info([
	'',
	'🔖 Templates must be synthesized with a clean working tree on a pushed commit for deploy time image builds to work.',
	'',
].join('\n'))

export const nixFlakeMetadata = utils_nix.getFlakeMetadata()

const selfNixFlakeReference = utils_nix.getFlakeInput(nixFlakeMetadata, 'self') as utils_nix.FlakeReference<utils_nix.FlakeType.GIT>

export const selfNixFlakeRevision: string = (selfNixFlakeReference.rev ?? selfNixFlakeReference.dirtyRev) as string

export const pushedSelfNixFlakeReference: utils_nix.FlakeReference<utils_nix.FlakeType.GITHUB> = {
	type: utils_nix.FlakeType.GITHUB,
	owner: 'commiterate',
	repo: 'amazon-ec2-ssh-utils',
	rev: selfNixFlakeRevision,
}

export function platformToNixFlakeOutputKey(platform: utils_platform.Platform): string {
	const hardware: string | undefined = (() => {
		switch (platform.hardware) {
			case utils_platform.Hardware.AARCH64:
				return 'aarch64'
			case utils_platform.Hardware.X86_64:
				return 'x86_64'
		}
	})()
	const supervisor: string | undefined = (() => {
		switch (platform.supervisor) {
			case utils_platform.Supervisor.AMAZON_LINUX:
				return 'linux'
			case utils_platform.Supervisor.MACOS:
				return 'darwin'
			default:
				return undefined
		}
	})()
	if (hardware === undefined || supervisor === undefined) {
		throw new ReferenceError('No flake output key for platform!')
	}
	return `${hardware}-${supervisor}-test`
}
