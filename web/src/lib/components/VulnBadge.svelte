<script>
	// Whether a component (exact version, in its snapshot) is known vulnerable:
	// "clean", or the count coloured by the worst severity, with the ids on hover.
	import { severityClass } from '#lib/format.js';
	import { t } from '#lib/i18n.js';

	let { count = 0, severity = null, kev = false, vulns = [], compact = false } = $props();
	const size = $derived(compact ? 'badge-xs' : 'badge-sm');
</script>

{#if count > 0}
	<span class="inline-flex items-center gap-1 whitespace-nowrap" title={vulns.join(', ')}>
		<span class="badge {size} {severityClass(severity)}">{$t('badge.vulns', { count })}</span>
		{#if kev}<span class="badge {size} badge-error badge-outline" title={$t('badge.onKev')}>KEV</span>{/if}
	</span>
{:else}
	<span class="badge {size} badge-ghost text-success" title={$t('badge.cleanTitle')}>{$t('badge.clean')}</span>
{/if}
