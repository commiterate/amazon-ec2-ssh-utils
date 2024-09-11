import * as node_buffer from 'node:buffer'
import * as node_crypto from 'node:crypto'
import * as confbox from 'confbox'
import * as domain from './domain'
import * as platform from './platform'

/**
 * AWS tags.
 *
 * Character length and type limits for keys and values depend on the service, but they're usually less limited than resource names.
 *
 * https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html#tag-conventions
 *
 * - Keys
 * 	- `[a-zA-Z0-9 .:_=+@\-\/]{1,128}`
 * - Values
 * 	- `[a-zA-Z0-9 .:_=+@\-\/]{0,256}`
 *
 * ⚠️ Tag keys and values are dynamic. We need runtime validation.
 */
export interface Tags {
	[key: string]: string
}

/**
 * Check if tags entries are valid.
 *
 * @param tags - Tags to check.
 * @returns Given tags.
 */
function checkTags(tags: Tags): Tags {
	if (!Object.entries(tags)
		.every(([
			key,
			value,
		]) => key.match(/^[a-zA-Z0-9 .:_=+@\-\/]{1,128}$/) && value.match(/^[a-zA-Z0-9 .:_=+@\-\/]{0,256}$/))) {
		throw new TypeError('Tags has invalid entries!')
	}
	return tags
}

/**
 * Return tags for a platform, domain path, resource, and time permutation.
 *
 * @param platform - Platform.
 * @param domainPath - Domain path.
 * @param resource - Resource name.
 * @param time - Logical time (e.g. Git revision).
 * @returns Tags.
 */
export function tags({
	platform,
	domainPath,
	resource,
	time,
}: {
	platform?: platform.Platform
	domainPath?: domain.DomainPath<domain.DomainType>
	resource?: string
	time?: string
}): Tags {
	const entries: [string, string][] = []
	const namespace = 'amazon-ec2-ssh-utils'
	if (platform !== undefined) {
		entries.push(...Object.entries(platform)
			.map(([
				key,
				value,
			]) => [
				[
					namespace,
					'platform',
					key,
				].join('.'),
				String(value),
			] as [string, string]))
	}
	if (domainPath !== undefined) {
		entries.push(...domainPath.map(domain => [
			[
				namespace,
				'domain',
				domain.type,
			].join('.'),
			domain.data.name,
		] as [string, string]))
	}
	if (resource !== undefined) {
		entries.push([
			[
				namespace,
				'resource',
			].join('.'),
			resource,
		])
	}
	if (time !== undefined) {
		entries.push([
			[
				namespace,
				'time',
			].join('.'),
			time,
		])
	}
	return checkTags(Object.fromEntries(entries))
}

/**
 * Return the name for tags.
 *
 * Resource names should be fully qualified (e.g. `{superdomain}.{subdomain}.{resource}`) to avoid collisions.
 *
 * AWS resource names, however, are usually up to 2ⁿ ± 1 characters with limited character types. For example:
 *
 * - S3 buckets
 * 	- `[a-z0-9][a-z0-9.\-]{2,62}`
 * - IAM roles
 * 	- `[a-zA-Z0-9.,_=+@\-]{1,64}`
 * - CloudFormation stacks
 * 	- `[a-zA-Z][a-zA-Z0-9\-]{1,127}`
 *
 * S3 buckets and Cloudformation stacks are the most limited.
 *
 * To circumvent this, we derive AWS resource names from tags by:
 *
 * 1. Sorting the tags by key.
 * 2. Writing them as YAML encoded in UTF-8.
 * 3. Finding the SHA3-224 hash in hexadecimal.
 * 4. Prefixing the hash with `sha3-`.
 *
 * This matches `sha3-[a-f0-9]{56}`.
 *
 * @param tags - Tags to name.
 * @returns Tags name.
 */
export function tagsToName(tags: Tags): string {
	const tagsHash = node_crypto.createHash('sha3-224')
		.update(node_buffer.Buffer.from(
			// Only serializer from confbox that can sort keys.
			confbox.stringifyYAML(
				tags,
				{
					// Sort keys to write reproducible YAML.
					sortKeys: true,
				},
			),
			'utf-8',
		))
		.digest('hex')
	return `sha3-${tagsHash}`
}
