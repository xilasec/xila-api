<script>
	// Compact, colored severity counts for at-a-glance scanning. Only non-zero
	// severities render; nothing open shows a subtle "clean".
	import { t, labelOf } from '#lib/i18n.js';

	/** @type {{ counts?: Record<string, number>, emptyLabel?: string }} */
	let { counts = {}, emptyLabel = '' } = $props();

	/** @type {[string, import('#lib/i18n.js').MessageKey, string][]} */
	const ORDER = [
		['critical', 'dots.abbr.critical', 'bg-error/15 text-error'],
		['high', 'dots.abbr.high', 'bg-warning/15 text-warning'],
		['medium', 'dots.abbr.medium', 'bg-info/15 text-info'],
		['low', 'dots.abbr.low', 'bg-base-300 text-base-content/60']
	];
	const rows = $derived(ORDER.filter(([k]) => (counts?.[k] ?? 0) > 0));
</script>

{#if rows.length}
	<div class="flex flex-wrap gap-1">
		{#each rows as [k, abbr, cls] (k)}
			<span class="badge badge-sm border-0 font-semibold tabular-nums {cls}" title="{counts[k]} {$labelOf('severity', k)}">
				{counts[k]}<span class="ml-0.5 opacity-60">{$t(abbr)}</span>
			</span>
		{/each}
	</div>
{:else}
	<span class="text-xs text-success/80">{emptyLabel || $t('dots.clean')}</span>
{/if}
