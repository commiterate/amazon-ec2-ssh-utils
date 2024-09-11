import * as confbox from 'confbox'
import * as domain from './domain'

export enum Hardware {
	AARCH64 = 'AArch64',
	X86_64 = 'x86-64',
}

export enum Supervisor {
	AMAZON_LINUX = 'Amazon Linux',
	MACOS = 'macOS',
	WINDOWS = 'Windows',
}

export interface Platform {
	readonly hardware: Hardware
	readonly supervisor: Supervisor
}

/**
 * Return a platform's key representation.
 *
 * For indexing platform maps since objects can't be used as object keys.
 *
 * @param platform - Platform to keyify.
 * @returns Platform key.
 */
function platformKey(platform: Platform): string {
	// Only serializer from confbox that can sort keys.
	return confbox.stringifyYAML(
		platform,
		{
			// Sort keys to write reproducible YAML.
			sortKeys: true,
		},
	)
}

/**
 * Return a map of platform to the result of applying `f`.
 *
 * @param platforms - Platforms to map.
 * @param f - Platform map function.
 * @returns Platform map.
 */
export function mapPlatforms<T>(platforms: Set<Platform>, f: (platform: Platform) => T): (platform: Platform) => T {
	const map: {
		readonly [key: string]: T
	} = Object.fromEntries(Array.from(platforms)
		.map(platform => [
			platformKey(platform),
			f(platform),
		]))
	return (platform: Platform): T => {
		const value = map[platformKey(platform)]
		if (value === undefined) {
			throw new ReferenceError('Map does not contain platform!')
		}
		return value
	}
}

export const platforms = domain.mapDomainStratumPaths(domain.SERVICE_DOMAIN, domain.DomainType.REGION, ([]) => new Set([
	{
		hardware: Hardware.AARCH64,
		supervisor: Supervisor.AMAZON_LINUX,
	},
	{
		hardware: Hardware.X86_64,
		supervisor: Supervisor.AMAZON_LINUX,
	},
]))

export const instanceTypes = domain.mapDomainStratumPaths(domain.SERVICE_DOMAIN, domain.DomainType.REGION, (domainPath) => {
	return mapPlatforms(platforms(domainPath) ?? new Set(), (platform) => {
		switch (platform.supervisor) {
			case Supervisor.MACOS:
				switch (platform.hardware) {
					case Hardware.AARCH64:
						return 'mac2.metal'
					case Hardware.X86_64:
						return 'mac1.metal'
				}
			default:
				switch (platform.hardware) {
					case Hardware.AARCH64:
						return 't4g.xlarge'
					case Hardware.X86_64:
						return 't3a.xlarge'
				}
		}
	})
})
