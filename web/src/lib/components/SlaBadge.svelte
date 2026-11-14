<script>
	// Where a finding stands against its remediation deadline: "3d left",
	// "2d overdue", "paused", "met"/"missed". Renders nothing when no SLA applies.
	import { t } from '$lib/i18n.js';
	import { fmtDate } from '$lib/format.js';

	let { status, due = null, compact = false } = $props();

	const DAY = 86_400_000;
	/** @param {number} ms */
	function span(ms) {
		const abs = Math.abs(ms);
		if (abs >= DAY) return $t('sla.days', { count: Math.floor(abs / DAY) });
		return $t('sla.hours', { count: Math.max(1, Math.floor(abs / 3_600_000)) });
	}

	const view = $derived.by(() => {
		const left = due ? new Date(due).getTime() - Date.now() : 0;
		switch (status) {
			case 'breached':
				return { cls: 'badge-error', text: $t('sla.overdue', { span: span(left) }) };
			case 'due_soon':
				return { cls: 'badge-warning', text: $t('sla.left', { span: span(left) }) };
			case 'on_track':
				return { cls: 'badge-ghost', text: $t('sla.left', { span: span(left) }) };
			case 'paused':
				return { cls: 'badge-ghost opacity-60', text: $t('sla.paused') };
			case 'met':
				return { cls: 'badge-success badge-outline', text: $t('sla.met') };
			case 'missed':
				return { cls: 'badge-error badge-outline', text: $t('sla.missed') };
			default:
				return null;
		}
	});
	const title = $derived(
		due ? $t('sla.dueTitle', { date: fmtDate(due) }) + (status === 'paused' ? ' ' + $t('sla.clockPaused') : '') : 'SLA'
	);
</script>

{#if view}
	<span class="badge {compact ? 'badge-xs' : 'badge-sm'} whitespace-nowrap {view.cls}" {title}>{view.text}</span>
{:else if !compact}
	<span class="text-base-content/30">—</span>
{/if}
