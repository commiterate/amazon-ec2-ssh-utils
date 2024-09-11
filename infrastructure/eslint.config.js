/**
 * ESLint configuration.
 *
 * https://eslint.org/docs/latest/use/configure/configuration-files
 */
import {
	fileURLToPath,
} from 'node:url'
import {
	includeIgnoreFile,
} from '@eslint/compat'
import stylistic from '@stylistic/eslint-plugin'
import * as import_eslint from 'eslint-plugin-import'
import typescript_eslint from 'typescript-eslint'

export default [
	includeIgnoreFile(fileURLToPath(new URL('../.gitignore', import.meta.url))),
	/**
	 * Formatting.
	 *
	 * https://eslint.style/packages/default
	 */
	stylistic.configs.customize({
		indent: 'tab',
	}),
	{
		plugins: {
			'@stylistic': stylistic,
		},
		rules: {
			'@stylistic/array-bracket-newline': [
				'error',
				{
					minItems: 1,
				},
			],
			'@stylistic/array-element-newline': [
				'error',
				'always',
			],
			'@stylistic/newline-per-chained-call': [
				'error',
				{
					ignoreChainWithDepth: 1,
				},
			],
			'@stylistic/object-curly-newline': [
				'error',
				{
					minProperties: 1,
				},
			],
			'@stylistic/object-property-newline': [
				'error',
				{
					allowAllPropertiesOnSameLine: false,
					allowMultiplePropertiesPerLine: false,
				},
			],
		},
	},
	import_eslint.flatConfigs.typescript,
	{
		plugins: {
			'@import': import_eslint,
		},
		rules: {
			'@import/order': [
				'error',
				{
					alphabetize: {
						order: 'asc',
						orderImportKind: 'asc',
						caseInsensitive: false,
					},
					named: true,
					warnOnUnassignedImports: true,
				},
			],
		},
	},
	/**
	 * Linting.
	 *
	 * https://eslint.org/docs/latest/rules
	 * https://typescript-eslint.io/rules
	 */
	...typescript_eslint.configs.strict,
]
