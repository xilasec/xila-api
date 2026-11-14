<script>
	import { severityClass, statusClass, criticalityClass } from '#lib/format.js';
	import { labelOf } from '#lib/i18n.js';

	/** @type {{ kind?: 'severity'|'status'|'criticality'|'scan'|'plain', value: string, size?: string }} */
	let { kind = 'plain', value, size = 'badge-sm' } = $props();

	const cls = $derived(
		kind === 'severity'
			? severityClass(value)
			: kind === 'status'
				? statusClass(value)
				: kind === 'criticality'
					? criticalityClass(value)
					: 'badge-ghost'
	);
</script>

<span class="badge {cls} {size} whitespace-nowrap {kind === 'status' && value === 'false_positive' ? '' : 'capitalize'}">{$labelOf(kind, value)}</span>
