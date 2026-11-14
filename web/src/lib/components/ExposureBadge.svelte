<script>
	// An asset's exposure (internet / internal / isolated); nothing when unknown.
	// Inferred values say so in the tooltip, with the evidence.
	import { t } from '$lib/i18n.js';

	/** @type {{ exposure?: string | null, source?: string | null, reason?: string, size?: 'xs' | 'sm' }} */
	let { exposure = null, source = null, reason = '', size = 'sm' } = $props();

	/** @type {Record<string, { cls: string, label: import('$lib/i18n.js').MessageKey, multiplier: number }>} */
	const STYLES = {
		internet: { cls: 'badge-error', label: 'exposure.internet', multiplier: 1.25 },
		internal: { cls: 'badge-info', label: 'exposure.internal', multiplier: 1 },
		isolated: { cls: 'badge-ghost', label: 'exposure.isolated', multiplier: 0.75 }
	};
	const style = $derived(exposure ? STYLES[exposure] : undefined);
	const title = $derived(
		style ? [$t('exposure.priority', { factor: style.multiplier }), source === 'inferred' ? $t('exposure.inferred') : $t('exposure.manual'), reason].filter(Boolean).join(' · ') : ''
	);
</script>

{#if style}
	<span class="badge {style.cls} badge-{size} whitespace-nowrap" {title}>
		{$t(style.label)}{#if source === 'inferred'}<span class="opacity-60 ml-1">·&nbsp;{$t('exposure.inferred')}</span>{/if}
	</span>
{/if}
