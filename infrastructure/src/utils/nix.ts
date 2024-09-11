import * as child_process from 'node:child_process'

/*
 * Get from flake metadata if publishing is changed.
 *
 * https://github.com/DeterminateSystems/nix-installer/issues/1235
 */
const DETERMINATE_NIX_INSTALLER_RELEASE = 'v3.6.8'

export const DETERMINATE_NIX_INSTALLER_URL = `https://install.determinate.systems/nix/tag/${DETERMINATE_NIX_INSTALLER_RELEASE}`

/**
 * Flake type.
 */
export enum FlakeType {
	PATH = 'path',
	FILE = 'file',
	TARBALL = 'tarball',
	GIT = 'git',
	GITHUB = 'github',
	GITLAB = 'gitlab',
}

/**
 * Flake reference.
 *
 * https://nix.dev/manual/nix/stable/command-ref/new-cli/nix3-flake#flake-references
 */
export type FlakeReference<T extends FlakeType> = {
	readonly type: T
	readonly dir?: string
	readonly narHash?: string
	/**
	 * Only present on clean working trees.
	 */
	readonly rev?: string
	/**
	 * Only present on dirty working trees.
	 */
	readonly dirtyRev?: string
	/**
	 * Only present on clean working trees.
	 */
	readonly shortRev?: string
	/**
	 * Only present on dirty working trees.
	 */
	readonly dirtyShortRev?: string
	readonly ref?: string
	readonly revCount?: number
	readonly lastModified?: number
} & (T extends FlakeType.PATH ? {
	readonly path: string
} : T extends FlakeType.FILE ? {
	readonly url: string
} : T extends FlakeType.TARBALL ? {
	readonly url: string
} : T extends FlakeType.GIT ? {
	readonly url: string
} : T extends FlakeType.GITHUB ? {
	readonly owner: string
	readonly repo: string
} : T extends FlakeType.GITLAB ? {
	readonly owner: string
	readonly repo: string
} : never)

/**
 * Return the URL for a flake reference.
 *
 * @param flakeReference - Flake reference.
 * @returns Flake URL.
 */
export function flakeReferenceToURL<T extends FlakeType>(flakeReference: FlakeReference<T>): string {
	const nonParamKeys = new Set([
		// Undocumented key.
		'__final',
		'type',
		// https://github.com/NixOS/nix/issues/9303
		'narHash',
		'dirtyRev',
		'shortRev',
		'dirtyShortRev',
		'revCount',
		'lastModified',
	])
	const params = new Map(
		Object.entries(flakeReference)
			.filter(([
				key,
			]) => !nonParamKeys.has(key))
			.filter(([
				, value,
			]) => value !== undefined),
	)
	let baseUrl = ''
	const baseUrlParamKeys = new Set<string>()
	switch (flakeReference.type) {
		case FlakeType.PATH:
			const pathFlakeReference = flakeReference as FlakeReference<FlakeType.PATH>
			baseUrl = `${pathFlakeReference.type}:${pathFlakeReference.path}`;
			[
				'path',
			].forEach(key => baseUrlParamKeys.add(key))
			break
		case FlakeType.FILE:
		case FlakeType.TARBALL:
		case FlakeType.GIT:
			const gitFlakeReference = flakeReference as FlakeReference<FlakeType.FILE | FlakeType.TARBALL | FlakeType.GIT>
			baseUrl = `${gitFlakeReference.type}+${gitFlakeReference.url}`;
			[
				'url',
			].forEach(key => baseUrlParamKeys.add(key))
			break
		case FlakeType.GITHUB:
		case FlakeType.GITLAB:
			const gitlabFlakeReference = flakeReference as FlakeReference<FlakeType.GITHUB | FlakeType.GITLAB>
			/*
			 * `%2F` is URL-encoded `/`.
			 *
			 * https://github.com/NixOS/nix/pull/9163
			 */
			baseUrl = `${gitlabFlakeReference.type}:${gitlabFlakeReference.owner}${gitlabFlakeReference.type == 'gitlab' ? '%2F' : '/'}${gitlabFlakeReference.repo}`
			const commit = gitlabFlakeReference.rev || gitlabFlakeReference.ref
			if (commit !== undefined) {
				baseUrl += `/${commit}`
			}
			[
				'owner',
				'repo',
				'rev',
				'ref',
			].forEach(key => baseUrlParamKeys.add(key))
			break
	}
	const query = new Map(params.entries()
		.filter(([
			key,
		]) => !baseUrlParamKeys.has(key)))
	if (query.size > 0) {
		baseUrl += '?' + [
			...query.entries()
				.map(([
					key,
					value,
				]) => `${key}=${value}`),
		].join('&')
	}
	return baseUrl
}

/**
 * Flake lock.
 */
export interface FlakeLock {
	readonly nodes: {
		readonly [key: string]: {
			readonly inputs: {
				readonly [key: string]: string | string[]
			}
			readonly locked: FlakeReference<FlakeType>
			readonly original: FlakeReference<FlakeType>
		}
	}
	readonly root: string
	readonly version: 7
}

/**
 * Flake metadata.
 */
export interface FlakeMetadata {
	readonly original: FlakeReference<FlakeType>
	readonly originalUrl: string
	readonly resolved: FlakeReference<FlakeType>
	readonly resolvedUrl: string
	readonly locked: FlakeReference<FlakeType>
	/**
	 * The documentation says there should be a `lockedUrl`, but `url` functions as `lockedUrl` with clean working trees.
	 */
	readonly url: string
	readonly path: string
	readonly lastModified: number
	readonly locks: FlakeLock
	readonly description?: string
	/**
	 * Only present on clean working trees.
	 */
	readonly revision?: string
	/**
	 * Only present on dirty working trees.
	 */
	readonly dirtyRevision?: string
	readonly revCount?: number
}

/**
 * Return the metadata for a flake.
 *
 * https://nix.dev/manual/nix/stable/command-ref/new-cli/nix3-flake-metadata
 *
 * @param url - Flake URL.
 * @returns Output of `nix flake metadata --json [url]`.
 */
export function getFlakeMetadata(url?: string): FlakeMetadata {
	const command = [
		'nix',
		'--extra-experimental-features',
		'\'nix-command flakes\'',
		'flake',
		'metadata',
		'--json',
	]
	if (url !== undefined) {
		command.push(url)
	}
	return JSON.parse(child_process.execSync(command.join(' '))
		.toString('utf-8'))
}

/**
 * Return an input's flake reference from flake metadata.
 *
 * The special `"self"` input refers to the metadata's flake. This is like the special `self` input passed to a flake's `outputs` function.
 *
 * @param flakeMetadata - Flake metadata.
 * @param input - Flake input.
 * @returns Input's flake reference.
 */
export function getFlakeInput(flakeMetadata: FlakeMetadata, input: string): FlakeReference<FlakeType> {
	if (input === 'self') {
		return flakeMetadata.locked
	}
	else {
		// Filter transitive nodes.
		const inputs = new Set(Object.keys(flakeMetadata.locks.nodes['root']?.inputs || {}))
		if (inputs.has(input)) {
			return flakeMetadata.locks.nodes[input]?.locked as FlakeReference<FlakeType>
		}
		else {
			throw new ReferenceError('Flake does not contain input!')
		}
	}
}
