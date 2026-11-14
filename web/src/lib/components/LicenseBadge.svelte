<script>
	// A component's resolved license: the normalized SPDX expression with a badge
	// per ScanCode category, or the raw string marked "unresolved".
	import { t, labelOf } from '#lib/i18n.js';

	/** @type {{ c: { license?: string, license_expression?: string, license_ids?: string[], license_categories?: string[], license_resolved?: boolean|null } }} */
	let { c } = $props();

	/** @type {Record<string, string>} */
	const categoryClass = {
		Permissive: 'badge-success',
		'Public Domain': 'badge-success',
		'Copyleft Limited': 'badge-warning',
		Copyleft: 'badge-error',
		Commercial: 'badge-error',
		'Non-Commercial': 'badge-error',
		'Proprietary Free': 'badge-warning',
		'Free Restricted': 'badge-warning',
		'Source-available': 'badge-warning'
	};
	/** @param {string} cat */
	function licenseCategoryClass(cat) {
		return categoryClass[cat] ?? 'badge-ghost';
	}

	const shown = $derived(c.license_expression || c.license || '');
	const unresolved = $derived(c.license_resolved === false);
</script>

{#if shown}
	<span class="inline-flex flex-wrap items-center gap-1">
		<a
			class="link link-hover text-xs"
			title={c.license && c.license !== shown ? $t('badge.asStated', { license: c.license }) : ''}
			href={c.license_ids?.length === 1 ? `/licenses?id=${encodeURIComponent(c.license_ids[0])}` : undefined}
			>{shown}</a
		>
		{#each c.license_categories ?? [] as cat (cat)}
			<span class="badge badge-xs {licenseCategoryClass(cat)} whitespace-nowrap">{$labelOf('licenseCategory', cat)}</span>
		{/each}
		{#if unresolved}
			<span class="badge badge-xs badge-outline whitespace-nowrap" title={$t('badge.unresolvedTitle')}>{$t('badge.unresolved')}</span>
		{/if}
	</span>
{:else}
	<span class="text-xs text-base-content/50">—</span>
{/if}
