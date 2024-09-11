import * as confbox from 'confbox'

/**
 * Domain type.
 */
export enum DomainType {
	SERVICE = 'service',
	STAGE = 'stage',
	REGION = 'region',
}

/**
 * Domain.
 *
 * ⚠️ TypeScript types can't encode unique domain strata types and absolute domain names (e.g. `{service}.{stage}.{region}`). We need runtime validation.
 */
export type Domain<T extends DomainType> = {
	readonly type: T
	readonly data: {
		/**
		 * Domain name.
		 */
		readonly name: string
	}
	readonly subdomains: Domain<T extends DomainType.SERVICE ? DomainType.STAGE : T extends DomainType.STAGE ? DomainType.REGION : never>[]
} & (T extends DomainType.SERVICE ? object : T extends DomainType.STAGE ? {
	readonly data: {
		/**
		 * Whether stacks are deployed with a CI/CD pipeline.
		 */
		readonly pipeline: boolean
	}
} : T extends DomainType.REGION ? {
	readonly data: {
		/**
		 * AWS account ID.
		 */
		readonly account: string
	}
} : never)

/**
 * Check if a domain has unique domain strata types and absolute domain names.
 *
 * @param domain - Domain to check.
 */
function checkDomain<T extends DomainType>(domain: Domain<T>): Domain<T> {
	/*
	 * This is an L-system + mapping function.
	 *
	 * - The L-system rewrites domain paths to their subdomain paths in each loop.
	 *
	 * https://en.wikipedia.org/wiki/L-system
	 */
	let domainStrataTypes: Set<DomainType> = new Set()
	let domainStratum: Domain<DomainType>[] = [
		domain as Domain<DomainType>,
	]
	while (domainStratum.length > 0) {
		const domainStratumTypes = new Set(domainStratum.map(domain => domain.type))
		// Unique absolute domain names is equal to unique subdomain names per domain.
		const hasUniqueSubdomainNamesPerDomain = domainStratum.map(domain => domain.subdomains.length == new Set(domain.subdomains.map(subdomain => subdomain.data.name)).size)
			.every(_ => _)
		if (domainStratumTypes.size === 1 && !domainStrataTypes.isSupersetOf(domainStratumTypes) && hasUniqueSubdomainNamesPerDomain) {
			domainStrataTypes = domainStrataTypes.union(domainStratumTypes)
			domainStratum = domainStratum.flatMap(domain => domain.subdomains)
		}
		else {
			throw new TypeError('Domain does not have unique domain strata types and or absolute domain names!')
		}
	}
	return domain
}

/**
 * Domain path.
 */
export type DomainPath<T extends DomainType> = readonly Domain<DomainType>[] & (T extends DomainType.SERVICE ? readonly [
	service: Domain<DomainType.SERVICE>,
] : T extends DomainType.STAGE ? readonly [
	service: Domain<DomainType.SERVICE>,
	stage: Domain<DomainType.STAGE>,
] : T extends DomainType.REGION ? readonly [
	service: Domain<DomainType.SERVICE>,
	stage: Domain<DomainType.STAGE>,
	region: Domain<DomainType.REGION>,
] : never)

/**
 * Return the name for a domain path.
 *
 * @param domainPath - Domain path to name.
 * @returns Domain path name.
 */
export function domainPathName(domainPath: DomainPath<DomainType>): string {
	return domainPath.map(domain => domain.data.name)
		.join('.')
}

/**
 * Return a domain path's key representation.
 *
 * For indexing domain path maps since objects can't be used as object keys.
 *
 * @param domainPath - Domain path to keyify.
 * @returns Domain path key.
 */
function domainPathKey<T extends DomainType>(domainPath: DomainPath<T>): string {
	// Only serializer from confbox that can sort keys.
	return confbox.stringifyYAML(
		domainPath,
		{
			// Sort keys to write reproducible YAML.
			sortKeys: true,
		},
	)
}

/**
 * Return a map of domain path at the `domainStratumType` to the result of applying `f`.
 *
 * @param domain - Domain to map over.
 * @param domainStratumType - Domain type stratum to map over.
 * @param f - Domain path map function.
 * @returns Domain path map.
 */
export function mapDomainStratumPaths<T extends DomainType, V>(domain: Domain<DomainType.SERVICE>, domainStratumType: T, f: (domainPath: DomainPath<T>) => V): (domainPath: DomainPath<T>) => V {
	/*
	 * This is an L-system + mapping function.
	 *
	 * - The L-system rewrites domain paths to their subdomain paths in each loop.
	 * - The domain stratum type limits the recursion depth.
	 * - The map function is applied to resulting domain paths.
	 *
	 * https://en.wikipedia.org/wiki/L-system
	 */
	let map: {
		readonly [key: string]: V
	} = {}
	const mapReader = (domainPath: DomainPath<T>): V => {
		const value = map[domainPathKey(domainPath)]
		if (value === undefined) {
			throw new ReferenceError('Map does not contain domain path!')
		}
		return value
	}
	let domainStratumPaths: DomainPath<DomainType>[] = [
		[
			domain,
		],
	]
	while (true) {
		if (domainStratumPaths.length > 0) {
			if (domainStratumPaths.at(-1)
				?.at(-1)?.type === domainStratumType) {
				map = Object.fromEntries(domainStratumPaths.map(domainPath => [
					domainPathKey(domainPath),
					f(domainPath as DomainPath<T>),
				]))
				return mapReader
			}
			else {
				domainStratumPaths = domainStratumPaths.flatMap((domainPath) => {
					return ((domainPath.at(-1) as unknown as Domain<DomainType>).subdomains.map(subdomain => [
						...domainPath,
						subdomain,
					]) as unknown as DomainPath<DomainType>[])
				})
				continue
			}
		}
		else {
			return mapReader
		}
	}
}

/**
 * Return a domain path trimmed to the `domainStratumType` stratum.
 *
 * @param domainPath - Domain path to trim.
 * @param domainStratumType - Domain type stratum to trim to.
 * @returns Trimmed domain path.
 */
export function trimDomainPath<T extends DomainType>(domainPath: DomainPath<DomainType>, domainStratumType: T): DomainPath<T> {
	let trimmedDomainPath = structuredClone(domainPath)
	while (trimmedDomainPath.length > 1 && (trimmedDomainPath.at(-1) as Domain<DomainType>).type !== domainStratumType) {
		trimmedDomainPath = trimmedDomainPath.slice(0, trimmedDomainPath.length - 1) as unknown as DomainPath<DomainType>
	}
	if (trimmedDomainPath.at(-1)?.type === domainStratumType) {
		return trimmedDomainPath as DomainPath<T>
	}
	else {
		throw new Error('Domain path does not contain domain stratum type!')
	}
}

export const SERVICE_DOMAIN: Domain<DomainType.SERVICE> = checkDomain({
	type: DomainType.SERVICE,
	data: {
		name: 'amazon-ec2-ssh-utils',
	},
	subdomains: [
		/*
		 * Alpha stage is for personal stacks.
		 *
		 * Substitute the stage name to a unique string like your alias and the accounts to your personal account.
		 */
		{
			type: DomainType.STAGE,
			data: {
				name: 'alpha',
				pipeline: false,
			},
			subdomains: [
				{
					type: DomainType.REGION,
					data: {
						name: 'us-west-2',
						account: '000000000000',
					},
					subdomains: [],
				},
			],
		},
		/*
		 * Beta+ stages are for pipeline stacks.
		 */
		{
			type: DomainType.STAGE,
			data: {
				name: 'beta',
				pipeline: true,
			},
			subdomains: [
				{
					type: DomainType.REGION,
					data: {
						name: 'us-west-2',
						account: '111111111111',
					},
					subdomains: [],
				},
			],
		},
	],
})
