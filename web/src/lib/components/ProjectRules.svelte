<script>
	// A project's own triage rules and vulnerability policies, and its opt-out
	// of global ones (M13 13.10). Owners manage them (the server enforces it);
	// everyone on the project sees them.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import { blankSide, sideBody, sideChips } from '#lib/rules.js';
	import TriageSideActions from '#lib/components/TriageSideActions.svelte';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
	/** @type {{ id: string, label: import('#lib/i18n.js').MessageKey }[]} */
	const ACTIONS = [
		{ id: 'none', label: 'triagerules.actNone' },
		{ id: 'false_positive', label: 'triagerules.actFalsePositive' },
		{ id: 'wont_fix', label: 'triagerules.actWontFix' },
		{ id: 'risk_accepted', label: 'triagerules.actRiskAccepted' },
		{ id: 'set_severity', label: 'triagerules.actSetSeverity' }
	];
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const STATES = {
		not_affected: 'vulnpol.analysisNotAffected',
		false_positive: 'vulnpol.analysisFalsePositive',
		exploitable: 'vulnpol.analysisExploitable',
		in_triage: 'vulnpol.analysisInTriage'
	};

	let settings = $state(/** @type {{ skip_global_rules: boolean, allow_skip_global_rules: boolean } | null} */ (null));
	let rules = $state(/** @type {any[]} */ ([]));
	let policies = $state(/** @type {any[]} */ ([]));
	let users = $state(/** @type {{ id: string, email: string }[]} */ ([]));
	let busy = $state(false);

	const blankRule = () => ({ name: '', action: 'none', new_severity: 'low', severities: /** @type {string[]} */ ([]), expression: '', reason: '', ...blankSide() });
	let ruleForm = $state(blankRule());
	const blankPolicy = () => ({ name: '', condition: '', state: 'not_affected', mode: 'apply' });
	let policyForm = $state(blankPolicy());

	async function load() {
		try {
			[settings, rules, policies] = await Promise.all([
				api.getProjectTriageSettings(projectId),
				api.listProjectRules(projectId),
				api.listProjectVulnPolicies(projectId)
			]);
			const people = await api.projectAssignees(projectId).catch(() => []);
			users = people.map((/** @type {any} */ p) => ({ id: p.user_id, email: p.email }));
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	$effect(() => {
		if (projectId) load();
	});

	/** @param {Event} e */
	async function toggleSkip(e) {
		const skip = /** @type {HTMLInputElement} */ (e.currentTarget).checked;
		try {
			settings = await api.setProjectTriageSettings(projectId, skip);
		} catch (err) {
			notify(errorMessage(err));
			await load();
		}
	}

	/** @param {string} s */
	function toggleSeverity(s) {
		ruleForm.severities = ruleForm.severities.includes(s) ? ruleForm.severities.filter((v) => v !== s) : [...ruleForm.severities, s];
	}

	/** @param {SubmitEvent} e */
	async function addRule(e) {
		e.preventDefault();
		busy = true;
		try {
			/** @type {Record<string, any>} */
			const body = { name: ruleForm.name, enabled: true, action: ruleForm.action, severities: ruleForm.severities,
				expression: ruleForm.expression.trim(), reason: ruleForm.reason, ...sideBody(ruleForm) };
			if (ruleForm.action === 'set_severity') body.new_severity = ruleForm.new_severity;
			await api.createProjectRule(projectId, body);
			ruleForm = blankRule();
			notify($t('prules.ruleSaved'), 'success');
			rules = await api.listProjectRules(projectId);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {any} r */
	async function toggleRule(r) {
		try {
			await api.updateProjectRule(projectId, r.id, { ...r, enabled: !r.enabled });
			rules = await api.listProjectRules(projectId);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} r */
	async function removeRule(r) {
		if (!confirm($t('prules.deleteConfirm', { name: r.name }))) return;
		try {
			await api.deleteProjectRule(projectId, r.id);
			rules = rules.filter((x) => x.id !== r.id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function apply() {
		busy = true;
		try {
			const out = await api.applyProjectRules(projectId);
			notify($t('prules.applied', { count: out.applied }), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function addPolicy(e) {
		e.preventDefault();
		busy = true;
		try {
			await api.createProjectVulnPolicy(projectId, {
				name: policyForm.name, enabled: true, condition: policyForm.condition, mode: policyForm.mode,
				analysis: { state: policyForm.state }
			});
			policyForm = blankPolicy();
			notify($t('prules.policySaved'), 'success');
			policies = await api.listProjectVulnPolicies(projectId);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {any} p */
	async function removePolicy(p) {
		try {
			await api.deleteProjectVulnPolicy(projectId, p.id);
			policies = policies.filter((x) => x.id !== p.id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} r */
	const thenLabel = (r) => {
		const act = r.action === 'set_severity' ? $t('triagerules.actionSetSeverity', { severity: r.new_severity })
			: $t(ACTIONS.find((a) => a.id === r.action)?.label ?? 'triagerules.actNone');
		return [act, ...sideChips(r, $t)].join(' · ');
	};
</script>

<p class="mb-3 text-sm text-base-content/60">{$t('prules.intro')}</p>

{#if settings}
	<label class="label cursor-pointer justify-start gap-2 mb-4" title={settings.allow_skip_global_rules ? '' : $t('prules.skipNotAllowed')}>
		<input type="checkbox" class="toggle toggle-sm" checked={settings.skip_global_rules} onchange={toggleSkip}
			disabled={!settings.allow_skip_global_rules && !settings.skip_global_rules} />
		<span class="label-text">{$t('prules.skipGlobal')}</span>
		{#if !settings.allow_skip_global_rules}<span class="text-xs text-base-content/50">{$t('prules.skipNotAllowed')}</span>{/if}
	</label>
{/if}

<div class="flex items-center justify-between mb-2">
	<h2 class="text-lg font-semibold">{$t('prules.rules')}</h2>
	<button class="btn btn-ghost btn-sm" onclick={apply} disabled={busy}>{$t('prules.apply')}</button>
</div>
{#if rules.length === 0}
	<p class="text-sm text-base-content/60 mb-3">{$t('prules.noRules')}</p>
{:else}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-3">
		<table class="table table-sm">
			<tbody>
				{#each rules as r (r.id)}
					<tr>
						<td><input type="checkbox" class="toggle toggle-xs" checked={r.enabled} onchange={() => toggleRule(r)} /></td>
						<td class="font-medium">{r.name}{#if r.approval_status === 'pending'} <span class="badge badge-warning badge-sm">{$t('prules.pending')}</span>{/if}</td>
						<td class="text-xs">{r.severities?.length ? r.severities.join(', ') : ''}{r.expression ? ` ⟨${r.expression}⟩` : ''}</td>
						<td><span class="badge badge-ghost badge-sm">{thenLabel(r)}</span></td>
						<td class="text-right"><button class="btn btn-ghost btn-xs" onclick={() => removeRule(r)}>{$t('common.delete')}</button></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
<form onsubmit={addRule} class="bg-base-100 rounded-box shadow-sm p-4 mb-6 grid gap-3 md:grid-cols-2">
	<label class="form-control">
		<span class="label-text mb-1">{$t('triagerules.nameLabel')}</span>
		<input bind:value={ruleForm.name} required class="input input-bordered input-sm" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('triagerules.actionLabel')}</span>
		<div class="flex gap-2">
			<select bind:value={ruleForm.action} class="select select-bordered select-sm flex-1">
				{#each ACTIONS as a (a.id)}<option value={a.id}>{$t(a.label)}</option>{/each}
			</select>
			{#if ruleForm.action === 'set_severity'}
				<select bind:value={ruleForm.new_severity} class="select select-bordered select-sm">
					{#each SEVERITIES as s (s)}<option value={s}>{$labelOf('severity', s)}</option>{/each}
				</select>
			{/if}
		</div>
	</label>
	<div class="form-control">
		<span class="label-text mb-1">{$t('triagerules.severitiesLabel')}</span>
		<div class="flex flex-wrap gap-1">
			{#each SEVERITIES as s (s)}
				<button type="button" class="btn btn-xs" class:btn-primary={ruleForm.severities.includes(s)} onclick={() => toggleSeverity(s)}>{$labelOf('severity', s)}</button>
			{/each}
		</div>
	</div>
	<label class="form-control">
		<span class="label-text mb-1">{$t('triagerules.reasonLabel')}</span>
		<input bind:value={ruleForm.reason} class="input input-bordered input-sm" />
	</label>
	<label class="form-control md:col-span-2">
		<span class="label-text mb-1">{$t('triagerules.expressionLabel')}</span>
		<input bind:value={ruleForm.expression} class="input input-bordered input-sm font-mono" placeholder={'finding.status == "confirmed"'} />
	</label>
	<TriageSideActions bind:form={ruleForm} {users} />
	<div class="md:col-span-2 flex justify-end">
		<button class="btn btn-primary btn-sm" disabled={busy}>{$t('prules.addRule')}</button>
	</div>
</form>

<h2 class="text-lg font-semibold mb-2">{$t('prules.policies')}</h2>
{#if policies.length === 0}
	<p class="text-sm text-base-content/60 mb-3">{$t('prules.noPolicies')}</p>
{:else}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-3">
		<table class="table table-sm">
			<tbody>
				{#each policies as p (p.id)}
					<tr>
						<td class="font-medium">{p.name}</td>
						<td class="font-mono text-xs">{p.condition}</td>
						<td class="text-xs">{p.analysis?.state && STATES[p.analysis.state] ? $t(STATES[p.analysis.state]) : ''}</td>
						<td class="text-xs">{p.mode === 'log' ? $t('vulnpol.modeLog') : $t('vulnpol.modeApply')}</td>
						<td class="text-right"><button class="btn btn-ghost btn-xs" onclick={() => removePolicy(p)}>{$t('common.delete')}</button></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
<form onsubmit={addPolicy} class="bg-base-100 rounded-box shadow-sm p-4 grid gap-3 md:grid-cols-2">
	<label class="form-control">
		<span class="label-text mb-1">{$t('triagerules.nameLabel')}</span>
		<input bind:value={policyForm.name} required class="input input-bordered input-sm" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('vulnpol.analysisStateLabel')}</span>
		<select bind:value={policyForm.state} class="select select-bordered select-sm">
			{#each Object.entries(STATES) as [value, label] (value)}<option {value}>{$t(label)}</option>{/each}
		</select>
	</label>
	<label class="form-control md:col-span-2">
		<span class="label-text mb-1">{$t('vulnpol.conditionLabel')}</span>
		<input bind:value={policyForm.condition} required class="input input-bordered input-sm font-mono" placeholder={$t('vulnpol.conditionPlaceholder')} />
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('vulnpol.modeLabel')}</span>
		<select bind:value={policyForm.mode} class="select select-bordered select-sm">
			<option value="apply">{$t('vulnpol.modeApply')}</option>
			<option value="log">{$t('vulnpol.modeLog')}</option>
		</select>
	</label>
	<div class="flex items-end justify-end">
		<button class="btn btn-primary btn-sm" disabled={busy}>{$t('prules.addPolicy')}</button>
	</div>
</form>
