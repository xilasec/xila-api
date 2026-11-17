<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Badge from '#lib/components/Badge.svelte';

	let policies = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);
	let editingID = $state(/** @type {string | null} */ (null));
	/** @type {{ title: string, total: number, findings: any[] } | null} */
	let preview = $state(null);
	let previewing = $state(false);

	let projects = $state(/** @type {any[]} */ ([]));
	onMount(() => {
		api.listProjects().then((p) => (projects = p)).catch(() => {});
	});

	const ANALYSIS_STATES = ['', 'not_affected', 'false_positive', 'exploitable', 'in_triage'];
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const ANALYSIS_LABEL = {
		'': 'vulnpol.analysisNone',
		not_affected: 'vulnpol.analysisNotAffected',
		false_positive: 'vulnpol.analysisFalsePositive',
		exploitable: 'vulnpol.analysisExploitable',
		in_triage: 'vulnpol.analysisInTriage'
	};
	const SEVERITIES = ['', 'info', 'low', 'medium', 'high', 'critical'];

	const blank = () => ({
		name: '',
		description: '',
		enabled: true,
		condition: '',
		priority: 0,
		analysis_state: '',
		justification: '',
		details: '',
		rating_severity: '',
		cvss_vector: '',
		cvss_score: '',
		valid_from: '',
		valid_until: '',
		scope: 'global',
		project_ids: /** @type {string[]} */ ([]),
		tag: '',
		mode: 'apply'
	});
	let form = $state(blank());

	async function load() {
		loading = true;
		try {
			policies = await api.listVulnPolicies();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {string} id */
	function toggleProject(id) {
		form.project_ids = form.project_ids.includes(id) ? form.project_ids.filter((p) => p !== id) : [...form.project_ids, id];
	}

	function formBody() {
		/** @type {Record<string, any>} */
		const body = {
			name: form.name,
			description: form.description,
			enabled: form.enabled,
			condition: form.condition,
			priority: Number(form.priority) || 0,
			scope: form.scope,
			project_ids: form.scope === 'projects' ? form.project_ids : [],
			tag: form.scope === 'tag' ? form.tag : '',
			mode: form.mode,
			valid_from: form.valid_from || null,
			valid_until: form.valid_until || null,
			analysis: form.analysis_state
				? { state: form.analysis_state, justification: form.justification, details: form.details }
				: null,
			rating: form.rating_severity
				? {
						severity: form.rating_severity,
						cvss_vector: form.cvss_vector,
						cvss_score: form.cvss_score === '' ? null : Number(form.cvss_score)
					}
				: null
		};
		return body;
	}

	function resetForm() {
		form = blank();
		editingID = null;
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			if (editingID) {
				await api.updateVulnPolicy(editingID, formBody());
				notify($t('vulnpol.updated'), 'success');
			} else {
				await api.createVulnPolicy(formBody());
				notify($t('vulnpol.createdApplied'), 'success');
			}
			resetForm();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} p */
	function edit(p) {
		editingID = p.id;
		form = {
			name: p.name,
			description: p.description,
			enabled: p.enabled,
			condition: p.condition,
			priority: p.priority,
			analysis_state: p.analysis?.state ?? '',
			justification: p.analysis?.justification ?? '',
			details: p.analysis?.details ?? '',
			rating_severity: p.rating?.severity ?? '',
			cvss_vector: p.rating?.cvss_vector ?? '',
			cvss_score: p.rating?.cvss_score ?? '',
			valid_from: p.valid_from ? p.valid_from.slice(0, 16) : '',
			valid_until: p.valid_until ? p.valid_until.slice(0, 16) : '',
			scope: p.scope,
			project_ids: [...(p.project_ids ?? [])],
			tag: p.tag ?? '',
			mode: p.mode
		};
		preview = null;
	}

	/** @param {any} p */
	async function toggle(p) {
		try {
			await api.updateVulnPolicy(p.id, { ...p, enabled: !p.enabled });
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} p */
	async function remove(p) {
		if (!confirm($t('vulnpol.deleteConfirm', { name: p.name }))) return;
		try {
			await api.deleteVulnPolicy(p.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
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
	const previewForm = () => runPreview(form.name || $t('vulnpol.nameholder'), () => api.previewVulnPolicy(formBody()));
	/** @param {any} p */
	const previewStored = (p) => runPreview(p.name, () => api.previewStoredVulnPolicy(p.id));

	let evaluating = $state(false);
	async function evaluateNow() {
		evaluating = true;
		try {
			const { applied } = await api.evaluateVulnPolicies();
			notify($t('vulnpol.evaluated', { count: applied }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			evaluating = false;
		}
	}

	async function exportBundle() {
		try {
			await api.exportVulnPolicyBundle();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	let importText = $state('');
	let importDryRun = $state(true);
	/** @type {{ policies: any[] } | null} */
	let importResult = $state(null);
	async function importBundle() {
		if (!importText.trim()) return;
		try {
			const res = await api.importVulnPolicyBundle(importText, importDryRun);
			importResult = res;
			if (!importDryRun) {
				notify($t('vulnpol.importApplied', { count: res.policies?.length ?? 0 }), 'success');
				importText = '';
				await load();
			}
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {File} file */
	async function onImportFile(file) {
		importText = await file.text();
	}

	/** @param {any} p */
	const effectSummary = (p) => {
		const parts = [];
		if (p.analysis?.state) parts.push($t(ANALYSIS_LABEL[p.analysis.state] ?? 'vulnpol.analysisNone'));
		if (p.rating?.severity) parts.push($t('vulnpol.ratingArrow', { severity: p.rating.severity }));
		return parts.length ? parts.join(' · ') : $t('vulnpol.analysisNone');
	};
</script>

<div class="flex items-center justify-between mb-2 flex-wrap gap-2">
	<div>
		<h1 class="text-xl font-bold">{$t('vulnpol.title')}</h1>
		<p class="text-base-content/60 text-sm">{$t('vulnpol.intro')}</p>
	</div>
	<button class="btn btn-ghost btn-sm" onclick={evaluateNow} disabled={evaluating}>
		{#if evaluating}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('vulnpol.evaluateNow')}
	</button>
</div>

<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
	<Field label={$t('vulnpol.nameLabel')} required>
		<input bind:value={form.name} required placeholder={$t('vulnpol.nameholder')} class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('vulnpol.priorityLabel')} hint={$t('vulnpol.priorityHint')}>
		<input bind:value={form.priority} type="number" class="input input-bordered input-sm w-full" />
	</Field>

	<div class="md:col-span-2">
		<Field label={$t('vulnpol.conditionLabel')} hint={$t('vulnpol.conditionHint')} required>
			<textarea bind:value={form.condition} required rows="2" placeholder={$t('vulnpol.conditionPlaceholder')}
				class="textarea textarea-bordered textarea-sm w-full font-mono"></textarea>
		</Field>
	</div>

	<Field label={$t('vulnpol.descriptionLabel')}>
		<input bind:value={form.description} class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('vulnpol.modeLabel')} hint={form.mode === 'log' ? $t('vulnpol.modeLogHint') : ''}>
		<select bind:value={form.mode} class="select select-bordered select-sm w-full">
			<option value="apply">{$t('vulnpol.modeApply')}</option>
			<option value="log">{$t('vulnpol.modeLog')}</option>
		</select>
	</Field>

	<Field label={$t('vulnpol.analysisStateLabel')}>
		<select bind:value={form.analysis_state} class="select select-bordered select-sm w-full">
			{#each ANALYSIS_STATES as s (s)}
				<option value={s}>{$t(ANALYSIS_LABEL[s])}</option>
			{/each}
		</select>
	</Field>
	<Field label={$t('vulnpol.ratingSeverityLabel')}>
		<select bind:value={form.rating_severity} class="select select-bordered select-sm w-full">
			{#each SEVERITIES as s (s)}
				<option value={s}>{s === '' ? $t('vulnpol.ratingNone') : s}</option>
			{/each}
		</select>
	</Field>

	{#if form.analysis_state}
		<Field label={$t('vulnpol.justificationLabel')}>
			<input bind:value={form.justification} class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('vulnpol.detailsLabel')}>
			<input bind:value={form.details} class="input input-bordered input-sm w-full" />
		</Field>
	{/if}
	{#if form.rating_severity}
		<Field label={$t('vulnpol.cvssVectorLabel')}>
			<input bind:value={form.cvss_vector} class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<Field label={$t('vulnpol.cvssScoreLabel')}>
			<input bind:value={form.cvss_score} type="number" min="0" max="10" step="0.1" class="input input-bordered input-sm w-full" />
		</Field>
	{/if}

	<Field label={$t('vulnpol.validFromLabel')}>
		<input bind:value={form.valid_from} type="datetime-local" class="input input-bordered input-sm w-full" />
	</Field>
	<Field label={$t('vulnpol.validUntilLabel')}>
		<input bind:value={form.valid_until} type="datetime-local" class="input input-bordered input-sm w-full" />
	</Field>

	<Field label={$t('vulnpol.scopeLabel')}>
		<select bind:value={form.scope} class="select select-bordered select-sm w-full">
			<option value="global">{$t('vulnpol.scopeGlobal')}</option>
			<option value="projects">{$t('vulnpol.scopeProjects')}</option>
			<option value="tag">{$t('vulnpol.scopeTag')}</option>
		</select>
	</Field>
	{#if form.scope === 'tag'}
		<Field label={$t('vulnpol.tagLabel')}>
			<input bind:value={form.tag} placeholder={$t('vulnpol.tagPlaceholder')} class="input input-bordered input-sm w-full" />
		</Field>
	{:else if form.scope === 'projects'}
		<div>
			<span class="label-text font-medium">{$t('vulnpol.projectsLabel')}</span>
			<div class="flex flex-wrap gap-2 mt-1 max-h-32 overflow-y-auto">
				{#each projects as p (p.id)}
					<label class="label cursor-pointer gap-1 py-0">
						<input type="checkbox" class="checkbox checkbox-xs" checked={form.project_ids.includes(p.id)} onchange={() => toggleProject(p.id)} />
						<span class="label-text text-sm">{p.name}</span>
					</label>
				{/each}
			</div>
		</div>
	{/if}

	<div class="md:col-span-2 flex justify-end gap-2">
		<button type="button" class="btn btn-ghost btn-sm" onclick={previewForm} disabled={!form.condition || previewing}>
			{#if previewing}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('vulnpol.previewButton')}
		</button>
		{#if editingID}
			<button type="button" class="btn btn-ghost btn-sm" onclick={resetForm}>{$t('vulnpol.cancelButton')}</button>
		{/if}
		<button class="btn btn-primary btn-sm" disabled={saving}>
			{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}
			{editingID ? $t('vulnpol.saveButton') : $t('vulnpol.addButton')}
		</button>
	</div>
</form>

{#if preview}
	<div class="bg-base-100 rounded-box shadow-sm p-4 mb-5">
		<div class="flex items-center justify-between mb-2">
			<h2 class="font-semibold">
				{preview.title} {$t('vulnpol.previewShowing', { count: preview.findings.length })} / {preview.total}
			</h2>
			<button class="btn btn-ghost btn-xs" onclick={() => (preview = null)}>{$t('vulnpol.closeButton')}</button>
		</div>
		<p class="text-xs text-base-content/60 mb-2">{$t('vulnpol.dryRunNote')}</p>
		{#if preview.findings.length === 0}
			<p class="text-base-content/50 text-sm">{$t('vulnpol.noneWouldChange')}</p>
		{:else}
			<div class="overflow-x-auto">
				<table class="table table-sm">
					<thead>
						<tr>
							<th>{$t('vulnpol.colFinding')}</th>
							<th>{$t('vulnpol.colSeverity')}</th>
							<th>{$t('vulnpol.colStatus')}</th>
						</tr>
					</thead>
					<tbody>
						{#each preview.findings as f (f.finding_id)}
							<tr>
								<td>{f.title} <span class="text-base-content/50">({f.package_name}@{f.package_version})</span></td>
								<td>
									<Badge kind="severity" value={f.current_severity} />
									{#if f.set_severity && f.set_severity !== f.current_severity}→ <Badge kind="severity" value={f.set_severity} />{/if}
								</td>
								<td>
									<Badge kind="status" value={f.current_status} />
									{#if f.set_status && f.set_status !== f.current_status}→ <Badge kind="status" value={f.set_status} />{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}

<State {loading} empty={!loading && policies.length === 0} emptyText={$t('vulnpol.empty')} />
{#if !loading && policies.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-5">
		<table class="table table-sm">
			<thead>
				<tr>
					<th>{$t('vulnpol.colOn')}</th>
					<th>{$t('vulnpol.colName')}</th>
					<th>{$t('vulnpol.colPriority')}</th>
					<th>{$t('vulnpol.colCondition')}</th>
					<th>{$t('vulnpol.colEffect')}</th>
					<th>{$t('vulnpol.colMode')}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each policies as p (p.id)}
					<tr>
						<td><input type="checkbox" class="toggle toggle-xs" checked={p.enabled} onchange={() => toggle(p)} /></td>
						<td class="font-medium">{p.name}</td>
						<td>{p.priority}</td>
						<td class="font-mono text-xs max-w-xs truncate" title={p.condition}>{p.condition}</td>
						<td class="text-xs">{effectSummary(p)}</td>
						<td>{p.mode === 'log' ? $t('vulnpol.modeLog') : $t('vulnpol.modeApply')}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => previewStored(p)}>{$t('vulnpol.previewRowButton')}</button>
							<button class="btn btn-ghost btn-xs" onclick={() => edit(p)}>{$t('vulnpol.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(p)}>{$t('vulnpol.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<div class="bg-base-100 rounded-box shadow-sm p-4">
	<h2 class="font-semibold mb-2">{$t('vulnpol.bundleTitle')}</h2>
	<p class="text-sm text-base-content/60 mb-3">{$t('vulnpol.bundleIntro')}</p>
	<div class="flex flex-wrap items-center gap-2 mb-3">
		<button class="btn btn-ghost btn-sm" onclick={exportBundle}>{$t('vulnpol.exportButton')}</button>
		<input type="file" accept=".yaml,.yml,.json"
			onchange={(e) => { const f = /** @type {HTMLInputElement} */ (e.target).files?.[0]; if (f) onImportFile(f); }}
			class="file-input file-input-bordered file-input-sm" />
	</div>
	{#if importText}
		<textarea bind:value={importText} rows="6" class="textarea textarea-bordered textarea-sm w-full font-mono mb-2"></textarea>
		<label class="label cursor-pointer gap-2 justify-start mb-2">
			<input type="checkbox" class="checkbox checkbox-sm" bind:checked={importDryRun} />
			<span class="label-text">{$t('vulnpol.dryRunToggle')}</span>
		</label>
		<div>
			<button class="btn btn-primary btn-sm" onclick={importBundle}>
				{importDryRun ? $t('vulnpol.importDryRunButton') : $t('vulnpol.importButton')}
			</button>
		</div>
		{#if importResult}
			<p class="text-sm text-base-content/70 mt-2">
				{$t('vulnpol.importDryRunResult', { count: importResult.policies?.length ?? 0 })}
			</p>
		{/if}
	{/if}
</div>
