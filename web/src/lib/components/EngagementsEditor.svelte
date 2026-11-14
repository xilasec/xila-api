<script>
	// A project's engagements (DefectDojo-style): time-boxed security work —
	// a pentest, an audit, a CI/CD pipeline. Scans uploaded with
	// ?engagement_id= are its tests; manual findings can be filed under it.
	// Viewing needs project viewer; creating, editing and reporting need editor.
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { fmtDate, fmtDateOnly } from '$lib/format.js';
	import { t, labelOf } from '$lib/i18n.js';
	import Badge from '$lib/components/Badge.svelte';
	import Field from '$lib/components/Field.svelte';
	import State from '$lib/components/State.svelte';
	import ManualFindingDialog from '$lib/components/ManualFindingDialog.svelte';
	import ReportMenu from '$lib/components/ReportMenu.svelte';

	/** @type {{ projectId: string, onchanged?: () => void }} */
	let { projectId, onchanged = () => {} } = $props();

	/** @typedef {import('$lib/i18n.js').MessageKey} MessageKey */
	const STATUSES = ['not_started', 'in_progress', 'on_hold', 'completed', 'cancelled'];
	/** @type {Record<string, MessageKey>} */
	const STATUS_KEY = {
		not_started: 'eng.status.not_started',
		in_progress: 'eng.status.in_progress',
		on_hold: 'eng.status.on_hold',
		completed: 'eng.status.completed',
		cancelled: 'eng.status.cancelled'
	};
	/** @type {Record<string, MessageKey>} */
	const KIND_KEY = { interactive: 'eng.kindInteractive', ci_cd: 'eng.kindCiCd' };
	const SEVS = ['critical', 'high', 'medium', 'low'];
	const blank = () => ({ name: '', kind: 'interactive', status: 'in_progress', description: '', lead_id: '', starts_on: '', ends_on: '' });

	let engagements = $state(/** @type {any[]} */ ([]));
	let assignees = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let editing = $state(/** @type {string | null} */ (null)); // null | 'new' | engagement id
	let form = $state(blank());
	let busy = $state(false);
	let selected = $state(/** @type {any} */ (null)); // engagement detail (with scans)
	let selFindings = $state(/** @type {any[]} */ ([]));
	let dialog = $state(/** @type {any} */ (undefined));
	let showArchived = $state(false);

	async function load() {
		try {
			engagements = await api.listEngagements(projectId, showArchived);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	$effect(() => {
		projectId;
		showArchived;
		loading = true;
		load().finally(() => (loading = false));
		api.projectAssignees(projectId).then((a) => (assignees = a)).catch(() => (assignees = []));
	});

	function openNew() {
		form = blank();
		editing = 'new';
	}

	/** @param {any} e */
	function openEdit(e) {
		form = { name: e.name, kind: e.kind, status: e.status, description: e.description, lead_id: e.lead_id ?? '', starts_on: e.starts_on ?? '', ends_on: e.ends_on ?? '' };
		editing = e.id;
	}

	/** @param {SubmitEvent} ev */
	async function save(ev) {
		ev.preventDefault();
		busy = true;
		const body = { ...form, lead_id: form.lead_id || null, starts_on: form.starts_on || null, ends_on: form.ends_on || null };
		try {
			const out = editing === 'new' ? await api.createEngagement(projectId, body) : await api.updateEngagement(/** @type {string} */ (editing), body);
			editing = null;
			await load();
			if (selected?.id === out.id) await select(out);
			notify($t('eng.saved'), 'success');
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('eng.editForbidden') : errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {any} e */
	async function remove(e) {
		if (!confirm($t('eng.archiveConfirm', { name: e.name }))) return;
		try {
			await api.archive('engagements', e.id);
			if (selected?.id === e.id) selected = null;
			await load();
			notify($t('eng.archivedToast'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} e */
	async function restore(e) {
		try {
			await api.restore('engagements', e.id);
			await load();
			notify($t('eng.restoredToast'), 'success');
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('eng.restoreForbidden') : errorMessage(err));
		}
	}

	/** @param {any} e */
	async function select(e) {
		try {
			const [detail, res] = await Promise.all([
				api.getEngagement(e.id),
				api.listFindings(projectId, { engagement_id: e.id, limit: 200 })
			]);
			selected = detail;
			selFindings = res.findings ?? [];
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function reported() {
		await load();
		if (selected) await select(selected);
		onchanged();
	}
</script>

<div class="flex items-center gap-2 mb-3">
	<p class="text-sm text-base-content/60">
		{$t('eng.introPrefix')} <code>engagement_id</code> (CLI <code>--engagement</code>) {$t('eng.introSuffix')}
	</p>
	<button class="btn btn-sm btn-outline ml-auto" onclick={() => dialog.open()}>{$t('proj.reportFinding')}</button>
	<button class="btn btn-sm btn-primary" onclick={openNew}>{$t('eng.newEngagement')}</button>
</div>

{#if editing}
	<form class="bg-base-100 rounded-box shadow-sm p-4 mb-4 grid grid-cols-2 gap-3 max-w-3xl" onsubmit={save}>
		<Field label={$t('home.name')} required><input class="input input-bordered input-sm" bind:value={form.name} required maxlength="200" placeholder="Q3 external pentest" /></Field>
		<Field label={$t('eng.fieldLead')}>
			<select class="select select-bordered select-sm" bind:value={form.lead_id}>
				<option value="">{$t('common.noneDash')}</option>
				{#each assignees as a (a.user_id)}<option value={a.user_id}>{a.email}</option>{/each}
			</select>
		</Field>
		<Field label={$t('eng.fieldType')}>
			<select class="select select-bordered select-sm" bind:value={form.kind}>
				{#each Object.keys(KIND_KEY) as k}<option value={k}>{$t(KIND_KEY[k])}</option>{/each}
			</select>
		</Field>
		<Field label={$t('finding.status')}>
			<select class="select select-bordered select-sm" bind:value={form.status}>
				{#each STATUSES as s}<option value={s}>{$t(STATUS_KEY[s])}</option>{/each}
			</select>
		</Field>
		<Field label={$t('eng.fieldStarts')}><input type="date" class="input input-bordered input-sm" bind:value={form.starts_on} /></Field>
		<Field label={$t('eng.fieldEnds')}><input type="date" class="input input-bordered input-sm" bind:value={form.ends_on} /></Field>
		<div class="col-span-2">
			<Field label={$t('writeup.description')}><textarea class="textarea textarea-bordered textarea-sm h-20 w-full" bind:value={form.description}></textarea></Field>
		</div>
		<div class="col-span-2 flex gap-2 justify-end">
			<button type="button" class="btn btn-sm" onclick={() => (editing = null)}>{$t('common.cancel')}</button>
			<button class="btn btn-sm btn-primary" disabled={busy}>{editing === 'new' ? $t('common.create') : $t('common.save')}</button>
		</div>
	</form>
{/if}

<label class="label cursor-pointer justify-start gap-2 mb-2">
	<input type="checkbox" class="toggle toggle-sm" bind:checked={showArchived} />
	<span class="label-text">{$t('eng.archived')}</span>
</label>
<State {loading} empty={!loading && engagements.length === 0} emptyText={showArchived ? $t('eng.noArchived') : $t('eng.noEngagements')} />

{#if !loading && engagements.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-4">
		<table class="table table-sm">
			<thead><tr><th>{$t('home.name')}</th><th>{$t('eng.fieldType')}</th><th>{$t('finding.status')}</th><th>{$t('eng.colDates')}</th><th>{$t('eng.fieldLead')}</th><th>{$t('proj.tab.scans')}</th><th>{$t('eng.colOpen')}</th><th></th></tr></thead>
			<tbody>
				{#each engagements as e (e.id)}
					<tr class="hover cursor-pointer" class:bg-base-200={selected?.id === e.id} onclick={() => select(e)}>
						<td class="font-medium">{e.name}</td>
						<td class="text-xs">{$t(KIND_KEY[e.kind] ?? KIND_KEY.interactive)}</td>
						<td><span class="badge badge-sm badge-ghost">{$t(STATUS_KEY[e.status] ?? STATUS_KEY.not_started)}</span></td>
						<td class="text-xs">{e.starts_on ?? '—'} → {e.ends_on ?? '—'}</td>
						<td class="text-xs">{e.lead_email ?? '—'}</td>
						<td>{e.stats?.scans ?? 0}</td>
						<td class="text-xs">
							{#each SEVS as s}{#if e.stats?.open?.[s]}<span class="mr-1"><Badge kind="severity" value={s} /> {e.stats.open[s]}</span>{/if}{/each}
							{#if !SEVS.some((s) => e.stats?.open?.[s])}—{/if}
						</td>
						<td class="text-right whitespace-nowrap">
							{#if e.archived_at}
								<span class="badge badge-sm badge-warning">{$t('eng.archivedBadge', { date: fmtDateOnly(e.archived_at) })}</span>
								<button class="btn btn-ghost btn-xs" onclick={(ev) => { ev.stopPropagation(); restore(e); }}>{$t('common.restore')}</button>
							{:else}
								<button class="btn btn-ghost btn-xs" onclick={(ev) => { ev.stopPropagation(); openEdit(e); }}>{$t('common.edit')}</button>
								<button class="btn btn-ghost btn-xs text-error" onclick={(ev) => { ev.stopPropagation(); remove(e); }}>{$t('common.archive')}</button>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if selected}
	<div class="bg-base-100 rounded-box shadow-sm p-4 space-y-4">
		<div class="flex items-center gap-2">
			<h3 class="font-semibold">{selected.name}</h3>
			<span class="text-xs text-base-content/50">{$t('eng.testsFindings', { findings: selected.stats?.findings ?? 0, scans: selected.stats?.scans ?? 0 })}</span>
			<span class="ml-auto"><ReportMenu label={$t('eng.report')} open={(opts) => api.openProjectReport(projectId, { ...opts, engagement_id: selected?.id })} /></span>
			<button class="btn btn-ghost btn-xs" onclick={() => (selected = null)}>{$t('home.closeButton')}</button>
		</div>
		{#if selected.description}<p class="text-sm whitespace-pre-line">{selected.description}</p>{/if}
		<div>
			<h4 class="text-sm font-medium mb-1">{$t('eng.tests')}</h4>
			{#if selected.scans?.length}
				<table class="table table-xs">
					<thead><tr><th>{$t('proj.colScanner')}</th><th>{$t('finding.branch')}</th><th>{$t('proj.colStatus')}</th><th>{$t('findings.title')}</th><th>{$t('proj.colWhen')}</th></tr></thead>
					<tbody>
						{#each selected.scans as s (s.id)}
							<tr><td>{s.scanner}</td><td>{s.branch || '—'}</td><td>{$labelOf('scan', s.status)}</td>
								<td>{Object.values(s.summary ?? {}).reduce((a, b) => a + b, 0)}</td><td>{fmtDate(s.created_at)}</td></tr>
						{/each}
					</tbody>
				</table>
			{:else}<p class="text-sm text-base-content/50">{$t('eng.noTests')}</p>{/if}
		</div>
		<div>
			<div class="flex items-center mb-1">
				<h4 class="text-sm font-medium">{$t('findings.title')}</h4>
				<button class="btn btn-xs btn-outline ml-auto" onclick={() => dialog.open()}>{$t('eng.reportFindingHere')}</button>
			</div>
			{#if selFindings.length}
				<table class="table table-xs">
					<thead><tr><th>{$t('findings.colSeverity')}</th><th>{$t('findings.colTitle')}</th><th>{$t('proj.colScanner')}</th><th>{$t('findings.colStatus')}</th></tr></thead>
					<tbody>
						{#each selFindings as f (f.id)}
							<tr class="hover cursor-pointer" onclick={() => (location.href = `/findings/${f.id}`)}>
								<td><Badge kind="severity" value={f.severity} /></td><td class="max-w-md truncate">{f.title}</td>
								<td>{f.scanner}</td><td><Badge kind="status" value={f.status} /></td>
							</tr>
						{/each}
					</tbody>
				</table>
			{:else}<p class="text-sm text-base-content/50">{$t('eng.noFindings')}</p>{/if}
		</div>
	</div>
{/if}

<ManualFindingDialog bind:this={dialog} {projectId} {engagements} engagementId={selected?.id ?? ''} oncreated={reported} />
