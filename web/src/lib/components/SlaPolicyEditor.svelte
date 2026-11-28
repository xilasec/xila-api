<script>
	// Edits one scope's SLA policy (days to remediate per severity). Shows the
	// policy in force and where it comes from; saving writes this scope's own
	// policy, resetting removes it so the enclosing scope applies again.
	//
	// policy:   { scope, critical_days, high_days, medium_days, low_days, info_days }
	// own:      the scope this editor writes ('project' | 'org' | 'global')
	// onsave:   async (days) => void
	// onreset:  async () => void
	import { t, labelOf } from '#lib/i18n.js';

	let { policy, own, onsave, onreset } = $props();

	const FIELDS = [
		['critical_days', 'critical'],
		['high_days', 'high'],
		['medium_days', 'medium'],
		['low_days', 'low'],
		['info_days', 'info']
	];
	// Exploit-aware windows (M13 13.4): a shorter deadline for a KEV or
	// weaponized-exploit finding than its severity window would give.
	/** @type {[string, import('#lib/i18n.js').MessageKey][]} */
	const EXPLOIT_FIELDS = [
		['kev_days', 'slaed.kevDays'],
		['exploited_days', 'slaed.exploitedDays']
	];
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const INHERITED = { project: 'slaed.inherit.project', org: 'slaed.inherit.org', global: 'slaed.inherit.global' };
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const SCOPE_LABEL = {
		project: 'slaed.scope.project',
		org: 'slaed.scope.org',
		global: 'slaed.scope.global',
		default: 'slaed.scope.default'
	};
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const SAVE_LABEL = { project: 'slaed.save.project', org: 'slaed.save.org', global: 'slaed.save.global' };

	let form = $state(/** @type {Record<string, any>} */ ({}));
	let busy = $state(false);
	$effect(() => {
		form = Object.fromEntries(
			[...FIELDS, ...EXPLOIT_FIELDS].map(([k]) => [k, policy?.[k] ?? ''])
		);
		useKevDue = !!policy?.use_kev_due_date;
	});
	let useKevDue = $state(false);

	const isOwn = $derived(policy?.scope === own);

	async function save() {
		busy = true;
		try {
			const days = /** @type {Record<string, any>} */ (
				Object.fromEntries(
					[...FIELDS, ...EXPLOIT_FIELDS].map(([k]) => [k, form[k] === '' || form[k] === null ? null : Number(form[k])])
				)
			);
			days.use_kev_due_date = useKevDue;
			await onsave(days);
		} finally {
			busy = false;
		}
	}
	async function reset() {
		busy = true;
		try {
			await onreset();
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex flex-wrap items-center gap-2 text-sm">
	<span class="text-base-content/60">{$t('slaed.inForce')}</span>
	<span class="badge {isOwn ? 'badge-primary' : 'badge-ghost'}">{SCOPE_LABEL[policy?.scope] ? $t(SCOPE_LABEL[policy?.scope]) : '—'}</span>
	{#if !isOwn}<span class="text-xs text-base-content/50">{$t('slaed.inherited')}</span>{/if}
</div>

<div class="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-5">
	{#each FIELDS as [k, sev] (k)}
		<label class="form-control">
			<span class="label-text text-xs capitalize">{$labelOf('severity', sev)}</span>
			<label class="input input-bordered input-sm flex items-center gap-1">
				<input type="number" min="1" max="3650" placeholder={$t('slaed.none')} bind:value={form[k]} class="w-full" />
				<span class="text-xs text-base-content/40">{$t('slaed.days')}</span>
			</label>
		</label>
	{/each}
</div>
<p class="mt-2 text-xs text-base-content/50">
	{$t('slaed.blankNote')}
</p>
<div class="mt-4 border-t border-base-200 pt-3">
	<span class="label-text text-xs font-medium">{$t('slaed.exploitTitle')}</span>
	<div class="mt-2 grid grid-cols-2 gap-3 sm:grid-cols-5">
		{#each EXPLOIT_FIELDS as [k, lbl] (k)}
			<label class="form-control">
				<span class="label-text text-xs">{$t(lbl)}</span>
				<label class="input input-bordered input-sm flex items-center gap-1">
					<input type="number" min="1" max="3650" placeholder={$t('slaed.none')} bind:value={form[k]} class="w-full" />
					<span class="text-xs text-base-content/40">{$t('slaed.days')}</span>
				</label>
			</label>
		{/each}
	</div>
	<label class="mt-2 flex items-center gap-2 text-xs">
		<input type="checkbox" class="checkbox checkbox-sm" bind:checked={useKevDue} />
		<span>{$t('slaed.useKevDue')}</span>
	</label>
</div>
{#if policy?.applied}
	<div class="mt-2 rounded-box bg-info/10 px-3 py-2 text-xs">
		<span class="font-medium">{$t('slaed.scaled', { criticality: $labelOf('criticality', policy.criticality) })}</span>
		{$t('slaed.findingsGet', { windows: FIELDS.map(([k, sev]) => `${$labelOf('severity', sev)} ${policy.applied[k] ?? '—'}`).join(' · ') })}
		<span class="text-base-content/60">{$t('slaed.setByAdmin')}</span>
	</div>
{/if}

<div class="mt-3 flex gap-2">
	<button class="btn btn-primary btn-sm" disabled={busy} onclick={save}>{SAVE_LABEL[own] ? $t(SAVE_LABEL[own]) : $t('common.save')}</button>
	{#if isOwn}
		<button class="btn btn-ghost btn-sm" disabled={busy} onclick={reset}>{$t('slaed.useInstead', { scope: INHERITED[own] ? $t(INHERITED[own]) : '' })}</button>
	{/if}
</div>
