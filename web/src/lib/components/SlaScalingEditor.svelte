<script>
	// Instance-wide switch: scale every SLA window by the project's business
	// criticality. The matrix is computed by the server (the same function the
	// findings use), so what's shown is exactly what deadlines get.
	//
	// settings: { scale_by_criticality, factors: {critical, high, medium, low}, matrix }
	// onsave:   async ({ scale_by_criticality, factors }) => void
	import { t, labelOf } from '$lib/i18n.js';

	let { settings, onsave } = $props();

	/** @type {[string, import('$lib/i18n.js').MessageKey][]} */
	const CRITS = [
		['critical', 'scaling.crit.critical'],
		['high', 'scaling.crit.high'],
		['medium', 'scaling.crit.medium'],
		['low', 'scaling.crit.low']
	];
	const SEVS = [
		['critical_days', 'critical'],
		['high_days', 'high'],
		['medium_days', 'medium'],
		['low_days', 'low'],
		['info_days', 'info']
	];

	let form = $state(/** @type {{ on: boolean, factors: Record<string, any> }} */ ({ on: false, factors: {} }));
	let busy = $state(false);
	$effect(() => {
		form = { on: !!settings?.scale_by_criticality, factors: { ...(settings?.factors ?? {}) } };
	});
	const dirty = $derived(
		form.on !== !!settings?.scale_by_criticality ||
			CRITS.some(([k]) => Number(form.factors[k]) !== settings?.factors?.[k])
	);

	async function save() {
		busy = true;
		try {
			await onsave({
				scale_by_criticality: form.on,
				factors: Object.fromEntries(CRITS.map(([k]) => [k, Number(form.factors[k])]))
			});
		} finally {
			busy = false;
		}
	}
</script>

<label class="label cursor-pointer justify-start gap-3">
	<input type="checkbox" class="toggle toggle-primary toggle-sm" bind:checked={form.on} />
	<span class="label-text font-medium">{$t('scaling.toggleLabel')}</span>
</label>
<p class="text-xs text-base-content/50">{$t('scaling.note')}</p>

<div class="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
	{#each CRITS as [k, labelKey] (k)}
		<label class="form-control">
			<span class="label-text text-xs">{$t(labelKey)}</span>
			<label class="input input-bordered input-sm flex items-center gap-1 {form.on ? '' : 'opacity-50'}">
				<span class="text-xs text-base-content/40">×</span>
				<input type="number" min="0.1" max="10" step="0.05" bind:value={form.factors[k]} class="w-full" disabled={!form.on} />
			</label>
		</label>
	{/each}
</div>

{#if settings?.matrix}
	<div class="mt-4 overflow-x-auto">
		<div class="mb-1 text-xs text-base-content/50">
			{$t('scaling.daysNote')}{settings.scale_by_criticality ? '' : $t('scaling.scalingOffNote')}{dirty ? $t('scaling.saveToUpdate') : ''}
		</div>
		<table class="table table-xs">
			<thead>
				<tr><th>{$t('scaling.colProjectCriticality')}</th>{#each SEVS as [, sev] (sev)}<th class="text-right">{$labelOf('severity', sev)}</th>{/each}</tr>
			</thead>
			<tbody>
				{#each CRITS as [k, labelKey] (k)}
					<tr>
						<td>{$t(labelKey)}</td>
						{#each SEVS as [sk] (sk)}
							<td class="text-right tabular-nums">{settings.matrix[k]?.[sk] ?? '—'}</td>
						{/each}
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<div class="mt-3">
	<button class="btn btn-primary btn-sm" disabled={busy || !dirty} onclick={save}>
		{#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
		{$t('scaling.saveButton')}
	</button>
</div>
