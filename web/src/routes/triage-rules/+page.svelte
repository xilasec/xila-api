<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Badge from '#lib/components/Badge.svelte';
	import { fmtDate } from '#lib/format.js';

	let rules = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);
	let applying = $state(false);
	// Dry-run result: { title, total, findings } — null when closed.
	let preview = $state(/** @type {{ title: string, total: number, findings: any[] } | null} */ (null));
	let previewing = $state(false);

	const CATEGORIES = ['', 'sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license', 'cloud', 'kubernetes'];
	const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
	const CRITICALITIES = ['low', 'medium', 'high', 'critical'];
	/** @type {{ id: string, label: import('#lib/i18n.js').MessageKey }[]} */
	const ACTIONS = [
		{ id: 'false_positive', label: 'triagerules.actFalsePositive' },
		{ id: 'risk_accepted', label: 'triagerules.actRiskAccepted' },
		{ id: 'wont_fix', label: 'triagerules.actWontFix' },
		{ id: 'set_severity', label: 'triagerules.actSetSeverity' },
		{ id: 'set_custom_field', label: 'triagerules.actSetCustomField' }
	];
	// Finding custom fields a set_custom_field rule can set.
	let cfFields = $state(/** @type {any[]} */ ([]));
	$effect(() => {
		api.listCustomFields({ entity: 'finding' }).then((f) => (cfFields = f)).catch(() => (cfFields = []));
	});

	const blank = () => ({
		name: '',
		enabled: true,
		action: 'false_positive',
		new_severity: 'low',
		custom_field: '',
		custom_value: '',
		scanner: '',
		category: '',
		severities: /** @type {string[]} */ ([]),
		rule_id: '',
		cve_in: '',
		path_regex: '',
		package_regex: '',
		dep_scope: '',
		dep_transitive: false,
		min_epss: '',
		kev: false,
		project_criticality: /** @type {string[]} */ ([]),
		expression: '',
		reason: '',
		sort_order: 0,
		continue: false
	});
	let form = $state(blank());

	async function load() {
		loading = true;
		try {
			rules = await api.listRules();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {string} s */
	function toggleSeverity(s) {
		form.severities = form.severities.includes(s)
			? form.severities.filter((x) => x !== s)
			: [...form.severities, s];
	}

	/** @param {string} c */
	function toggleCriticality(c) {
		form.project_criticality = form.project_criticality.includes(c)
			? form.project_criticality.filter((x) => x !== c)
			: [...form.project_criticality, c];
	}

	// formBody turns the form into the API's rule shape.
	function formBody() {
		/** @type {Record<string, any>} */
		const body = {
			...form,
			cve_in: form.cve_in
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean),
			min_epss: form.min_epss === '' || form.min_epss === null ? null : Number(form.min_epss),
			sort_order: Number(form.sort_order) || 0
		};
		if (body.action !== 'set_severity') delete body.new_severity;
		if (body.action !== 'set_custom_field') {
			delete body.custom_field;
			delete body.custom_value;
		} else {
			const def = cfFields.find((f) => f.key === body.custom_field);
			const v = /** @type {any} */ (body.custom_value);
			body.custom_value = v === '' || v === null ? null : def?.type === 'number' ? Number(v) : String(v);
		}
		return body;
	}

	/** @param {SubmitEvent} e */
	async function create(e) {
		e.preventDefault();
		saving = true;
		try {
			const out = await api.createRule(formBody());
			form = blank();
			notify(
				out.approval_status === 'pending' ? $t('triagerules.submittedPending') : $t('triagerules.createdApplied'),
				'success'
			);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} rule */
	async function toggle(rule) {
		try {
			const out = await api.updateRule(rule.id, { ...rule, enabled: !rule.enabled });
			if (out.approval_status === 'pending') notify($t('triagerules.editSubmitted'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	/** @param {any} rule */
	async function remove(rule) {
		if (!confirm($t('triagerules.deleteConfirm', { name: rule.name }))) return;
		try {
			await api.deleteRule(rule.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	async function applyBacklog() {
		applying = true;
		try {
			const { applied } = await api.applyRules();
			notify($t('triagerules.appliedBacklog', { count: applied }), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			applying = false;
		}
	}

	/** @param {string} title @param {() => Promise<any>} fn */
	async function runPreview(title, fn) {
		previewing = true;
		try {
			const res = await fn();
			preview = { title, total: res.total, findings: res.findings ?? [] };
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			previewing = false;
		}
	}
	const previewForm = () => runPreview(form.name || $t('triagerules.nameholder'), () => api.previewRule(formBody()));
	/** @param {any} r */
	const previewRule = (r) => runPreview(r.name, () => api.previewStoredRule(r.id));

	/** @param {any} rule @param {boolean} approve */
	async function review(rule, approve) {
		if (!approve && !confirm($t('triagerules.rejectConfirm', { name: rule.name }))) return;
		try {
			await (approve ? api.approveRule(rule.id) : api.rejectRule(rule.id));
			notify(approve ? $t('triagerules.approved') : $t('triagerules.rejected'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @type {Record<string, string>} */
	const approvalTone = { pending: 'badge-warning', approved: 'badge-success', rejected: 'badge-error' };
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const approvalLabel = { pending: 'triagerules.approvalPending', approved: 'triagerules.approvalApproved', rejected: 'triagerules.approvalRejected' };

	/** @param {any} r */
	const conditionSummary = (r) => {
		const parts = [];
		if (r.scanner) parts.push($t('triagerules.condScanner', { value: r.scanner }));
		if (r.category) parts.push($t('triagerules.condCategory', { value: r.category }));
		if (r.severities?.length) parts.push($t('triagerules.condSeverities', { values: r.severities.join(',') }));
		if (r.rule_id) parts.push($t('triagerules.condRule', { value: r.rule_id }));
		if (r.cve_in?.length) parts.push($t('triagerules.condCve', { values: r.cve_in.join(',') }));
		if (r.path_regex) parts.push($t('triagerules.condPath', { value: r.path_regex }));
		if (r.package_regex) parts.push($t('triagerules.condPackage', { value: r.package_regex }));
		if (r.dep_scope) parts.push($t('triagerules.condScope', { value: r.dep_scope }));
		if (r.dep_transitive) parts.push($t('triagerules.condTransitive'));
		if (r.min_epss != null) parts.push($t('triagerules.condEpss', { value: r.min_epss }));
		if (r.kev) parts.push($t('triagerules.condKev'));
		if (r.project_criticality?.length) parts.push($t('triagerules.condCriticality', { values: r.project_criticality.join(',') }));
		if (r.expression) parts.push(`⟨${r.expression}⟩`);
		return parts.length ? parts.join(' · ') : $t('triagerules.anyFinding');
	};
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const ACTION_LABEL = Object.fromEntries(ACTIONS.map((a) => [a.id, a.label]));
	/** @param {any} r */
	const actionLabel = (r) =>
		r.action === 'set_severity'
			? $t('triagerules.actionSetSeverity', { severity: r.new_severity })
			: r.action === 'set_custom_field'
				? $t('triagerules.actionSetCustomField', { field: r.custom_field, value: r.custom_value ?? $t('triagerules.clearOption') })
				: $t(ACTION_LABEL[r.action]);
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('triagerules.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('triagerules.intro')}
		</p>
	</div>
	<button class="btn btn-ghost btn-sm" onclick={applyBacklog} disabled={applying}>
		{#if applying}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('triagerules.applyBacklog')}
	</button>
</div>

<form onsubmit={create} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
	<Field label={$t('triagerules.nameLabel')} required>
		<input bind:value={form.name} required placeholder={$t('triagerules.nameholder')} class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('triagerules.actionLabel')} required>
		<div class="flex gap-2">
			<select bind:value={form.action} class="select select-bordered select-sm flex-1">
				{#each ACTIONS as a}<option value={a.id}>{$t(a.label)}</option>{/each}
			</select>
			{#if form.action === 'set_severity'}
				<select bind:value={form.new_severity} class="select select-bordered select-sm">
					{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
				</select>
			{/if}
			{#if form.action === 'set_custom_field'}
				{@const def = cfFields.find((f) => f.key === form.custom_field)}
				<select bind:value={form.custom_field} required class="select select-bordered select-sm" aria-label={$t('triagerules.customFieldAria')}>
					<option value="">{$t('triagerules.fieldPlaceholder')}</option>
					{#each cfFields as f (f.id)}<option value={f.key}>{f.label}</option>{/each}
				</select>
				{#if def?.type === 'enum'}
					<select bind:value={form.custom_value} class="select select-bordered select-sm" aria-label={$t('triagerules.valueAria')}>
						<option value="">{$t('triagerules.clearOption')}</option>
						{#each def.options as o}<option value={o}>{o}</option>{/each}
					</select>
				{:else}
					<input bind:value={form.custom_value} placeholder={$t('triagerules.valuePlaceholder')} aria-label={$t('triagerules.valueAria')}
						class="input input-bordered input-sm w-40" />
				{/if}
			{/if}
		</div>
	</Field>

	<Field label={$t('triagerules.scannerLabel')}>
		<input bind:value={form.scanner} placeholder={$t('triagerules.scannerPlaceholder')} class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('triagerules.categoryLabel')}>
		<select bind:value={form.category} class="select select-bordered select-sm w-full">
			{#each CATEGORIES as c}<option value={c}>{c ? $labelOf('category', c) : $t('triagerules.categoryAny')}</option>{/each}
		</select>
	</Field>

	<Field label={$t('triagerules.severitiesLabel')}>
		<div class="flex flex-wrap gap-1">
			{#each SEVERITIES as s}
				<button type="button" class="btn btn-xs" class:btn-primary={form.severities.includes(s)} onclick={() => toggleSeverity(s)}>{$labelOf('severity', s)}</button>
			{/each}
		</div>
	</Field>
	<Field label={$t('triagerules.ruleIdLabel')} hint={$t('triagerules.ruleIdHint')}>
		<input bind:value={form.rule_id} placeholder={$t('triagerules.ruleIdPlaceholder')} class="input input-bordered input-sm w-full" />
	</Field>

	<Field label={$t('triagerules.cveLabel')}>
		<input bind:value={form.cve_in} placeholder="CVE-2021-1, CVE-2022-2" class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('triagerules.reasonLabel')}>
		<input bind:value={form.reason} placeholder={$t('triagerules.reasonPlaceholder')} class="input input-bordered input-sm w-full" />
	</Field>

	<Field label={$t('triagerules.pathRegexLabel')}>
		<input bind:value={form.path_regex} placeholder="^test/|_test\.go$" class="input input-bordered input-sm w-full font-mono" />
	</Field>
	<Field label={$t('triagerules.packageRegexLabel')}>
		<input bind:value={form.package_regex} placeholder="^@internal/" class="input input-bordered input-sm w-full font-mono" />
	</Field>
	<Field label={$t('triagerules.depScopeLabel')}>
		<select bind:value={form.dep_scope} class="select select-bordered select-sm w-full">
			<option value="">{$t('triagerules.anyScope')}</option>
			<option value="runtime">{$t('triagerules.scopeRuntime')}</option>
			<option value="dev">{$t('triagerules.scopeDev')}</option>
			<option value="optional">{$t('triagerules.scopeOptional')}</option>
		</select>
	</Field>
	<Field label={$t('triagerules.onlyTransitiveLabel')}>
		<label class="label cursor-pointer justify-start gap-2">
			<input type="checkbox" bind:checked={form.dep_transitive} class="checkbox checkbox-sm" />
			<span class="label-text text-xs">{$t('triagerules.onlyTransitiveHint')}</span>
		</label>
	</Field>

	<Field label={$t('triagerules.minEpssLabel')} hint={$t('triagerules.minEpssHint')}>
		<input type="number" min="0" max="1" step="0.01" bind:value={form.min_epss} placeholder="0.1" class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('triagerules.kevLabel')}>
		<label class="label cursor-pointer justify-start gap-2">
			<input type="checkbox" bind:checked={form.kev} class="checkbox checkbox-sm" />
			<span class="label-text text-xs">{$t('triagerules.kevHint')}</span>
		</label>
	</Field>
	<Field label={$t('triagerules.criticalityLabel')}>
		<div class="flex flex-wrap gap-1">
			{#each CRITICALITIES as c}
				<button type="button" class="btn btn-xs" class:btn-primary={form.project_criticality.includes(c)} onclick={() => toggleCriticality(c)}>{$labelOf('criticality', c)}</button>
			{/each}
		</div>
	</Field>
	<Field label={$t('triagerules.expressionLabel')} hint={$t('triagerules.expressionHint')}>
		<textarea bind:value={form.expression} rows="2" spellcheck="false"
			placeholder={'finding.cvss >= 9 && "internet-facing" in finding.tags'}
			class="textarea textarea-bordered textarea-sm w-full font-mono"></textarea>
		<span class="label-text-alt text-base-content/50 mt-1">
			{$t('triagerules.expressionFields', { finding: 'finding', project: 'project' })}
		</span>
	</Field>

	<Field label={$t('triagerules.orderLabel')} hint={$t('triagerules.orderHint')}>
		<input bind:value={form.sort_order} type="number" class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('triagerules.continueLabel')}>
		<label class="label cursor-pointer justify-start gap-2">
			<input type="checkbox" bind:checked={form.continue} class="checkbox checkbox-sm" />
			<span class="label-text text-xs">{$t('triagerules.continueHint')}</span>
		</label>
	</Field>

	<div class="md:col-span-2 flex justify-end gap-2">
		<button type="button" class="btn btn-ghost btn-sm" onclick={previewForm} disabled={previewing}>
			{#if previewing}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('triagerules.previewButton')}
		</button>
		<button class="btn btn-primary btn-sm" disabled={saving}>
			{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('triagerules.addButton')}
		</button>
	</div>
</form>

{#if preview}
	<div class="bg-base-100 rounded-box shadow-sm p-4 mb-5">
		<div class="flex items-center justify-between mb-2">
			<h2 class="font-semibold">
				{$t('triagerules.previewTitle', { title: preview.title, count: preview.total })}
				{#if preview.total > preview.findings.length}<span class="text-xs text-base-content/60">{$t('triagerules.previewShowing', { count: preview.findings.length })}</span>{/if}
			</h2>
			<button class="btn btn-ghost btn-xs" onclick={() => (preview = null)}>{$t('triagerules.closeButton')}</button>
		</div>
		<p class="text-xs text-base-content/60 mb-2">{$t('triagerules.dryRunNote')}</p>
		{#if preview.findings.length === 0}
			<p class="text-sm text-base-content/60">{$t('triagerules.noneWouldChange')}</p>
		{:else}
			<div class="overflow-x-auto max-h-96">
				<table class="table table-xs">
					<thead><tr><th>{$t('triagerules.colFinding')}</th><th>{$t('triagerules.colSeverity')}</th><th>{$t('triagerules.colStatus')}</th></tr></thead>
					<tbody>
						{#each preview.findings as f (f.id)}
							<tr>
								<td><a class="link link-hover" href="/findings/{f.id}">{f.title}</a></td>
								<td>
									<Badge kind="severity" value={f.severity} />
									{#if f.new_severity !== f.severity}→ <Badge kind="severity" value={f.new_severity} />{/if}
								</td>
								<td>
									<Badge kind="status" value={f.status} />
									{#if f.new_status !== f.status}→ <Badge kind="status" value={f.new_status} />{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}

<State {loading} empty={!loading && rules.length === 0} emptyText={$t('triagerules.empty')} />
{#if !loading && rules.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('triagerules.colOn')}</th><th>{$t('triagerules.colName')}</th><th>{$t('triagerules.colWhen')}</th><th>{$t('triagerules.colThen')}</th><th>{$t('triagerules.colApproval')}</th><th>{$t('triagerules.colHits')}</th><th>{$t('triagerules.colLastHit')}</th><th></th></tr></thead>
			<tbody>
				{#each rules as r (r.id)}
					<tr class="hover" class:opacity-50={!r.enabled}>
						<td>
							<input type="checkbox" class="toggle toggle-sm toggle-primary" checked={r.enabled} onchange={() => toggle(r)} />
						</td>
						<td class="font-medium"><span class="text-base-content/40 tabular-nums mr-1" title={$t('triagerules.orderLabel')}>{r.sort_order}</span>{r.name}</td>
						<td class="text-xs text-base-content/60">{conditionSummary(r)}</td>
						<td>
							<span class="badge badge-ghost badge-sm">{actionLabel(r)}</span>
							{#if r.continue}<span class="badge badge-outline badge-sm ml-1" title={$t('triagerules.continueHint')}>{$t('triagerules.continueBadge')}</span>{/if}
						</td>
						<td><span class="badge badge-sm {approvalTone[r.approval_status] ?? 'badge-ghost'}">{approvalLabel[r.approval_status] ? $t(approvalLabel[r.approval_status]) : r.approval_status}</span></td>
						<td class="tabular-nums">{r.hit_count ?? 0}</td>
						<td class="text-xs whitespace-nowrap">{fmtDate(r.last_hit_at)}</td>
						<td class="text-right whitespace-nowrap">
							{#if r.approval_status === 'pending'}
								<button class="btn btn-success btn-xs" onclick={() => review(r, true)} title={$t('triagerules.approveTitle')}>{$t('triagerules.approveButton')}</button>
								<button class="btn btn-ghost btn-xs" onclick={() => review(r, false)}>{$t('triagerules.rejectButton')}</button>
							{/if}
							<button class="btn btn-ghost btn-xs" onclick={() => previewRule(r)} disabled={previewing}>{$t('triagerules.previewRowButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(r)}>{$t('triagerules.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
