<script>
	// PSIRT (admin): CSAF 2.0 security advisories about our own products.
	// Draft → publish (each republish bumps the version) → withdraw.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import State from '$lib/components/State.svelte';
	import Field from '$lib/components/Field.svelte';

	let loading = $state(true);
	let error = $state('');
	let list = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let editing = $state(/** @type {any} */ (null)); // null = list view; {} = new
	let saving = $state(false);
	let preview = $state(/** @type {any} */ (null));
	const blank = () => ({
		project_id: '', title: '', product_name: '', summary: '', details: '', cve: '', cwe: '', cwe_name: '',
		cvss_vector: '', affected: '', fixed: '', remediation: '', ack_names: '', ack_org: ''
	});
	let form = $state(blank());

	async function load() {
		loading = true;
		error = '';
		try {
			[list, projects] = await Promise.all([api.listPSIRT(), api.listProjects()]);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {string} s @returns {any[]} */
	function refs(s) {
		return s.split(',').map((x) => x.trim()).filter(Boolean)
			.map((x) => (/^[<>=~^]/.test(x) ? { range: x } : { version: x }));
	}
	/** @param {any[]} r */
	const refText = (r) => (r ?? []).map((x) => x.range || x.version || '').join(', ');

	/** @param {any} a */
	function open(a) {
		editing = a ?? {};
		preview = null;
		form = a
			? {
					project_id: a.project_id, title: a.title, product_name: a.product_name, summary: a.summary, details: a.details,
					cve: a.cve, cwe: a.cwe, cwe_name: a.cwe_name, cvss_vector: a.cvss_vector,
					affected: refText(a.affected), fixed: refText(a.fixed), remediation: a.remediation,
					ack_names: (a.acknowledgments?.[0]?.names ?? []).join(', '), ack_org: a.acknowledgments?.[0]?.organization ?? ''
				}
			: blank();
	}

	function body() {
		const ack = form.ack_names || form.ack_org
			? [{ names: form.ack_names.split(',').map((s) => s.trim()).filter(Boolean), organization: form.ack_org }]
			: [];
		return {
			project_id: form.project_id, title: form.title, product_name: form.product_name, summary: form.summary,
			details: form.details, cve: form.cve.trim(), cwe: form.cwe.trim(), cwe_name: form.cwe_name.trim(),
			cvss_vector: form.cvss_vector.trim(), affected: refs(form.affected), fixed: refs(form.fixed),
			remediation: form.remediation, acknowledgments: ack
		};
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			editing = editing?.id ? await api.updatePSIRT(editing.id, body()) : await api.createPSIRT(body());
			notify($t('psirt.saved'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	async function showPreview() {
		try {
			preview = await api.previewPSIRT(editing.id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function publish() {
		const note = prompt(editing.version ? $t('psirt.revisionNotePrompt') : $t('psirt.revisionNoteDefault'), editing.version ? '' : $t('psirt.initialRelease'));
		if (note === null) return;
		try {
			editing = await api.publishPSIRT(editing.id, note);
			notify($t('psirt.published', { version: editing.version }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function withdraw() {
		const note = prompt($t('psirt.withdrawPrompt'));
		if (!note) return;
		try {
			editing = await api.withdrawPSIRT(editing.id, note);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function remove() {
		if (!confirm($t('psirt.deleteDraftConfirm'))) return;
		try {
			await api.deletePSIRT(editing.id);
			editing = null;
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {string} s */
	const tone = (s) => (s === 'published' ? 'badge-success' : s === 'withdrawn' ? 'badge-ghost' : 'badge-warning');
	/** @type {Record<string, import('$lib/i18n.js').MessageKey>} */
	const STATE_LABEL = { draft: 'psirt.stateDraft', published: 'psirt.statePublished', withdrawn: 'psirt.stateWithdrawn' };
	/** @param {string} s */
	const stateLabel = (s) => $t(STATE_LABEL[s] ?? 'psirt.stateDraft');

	onMount(load);
</script>

<div class="flex items-center justify-between mb-4">
	<div>
		<h1 class="text-2xl font-bold">{$t('psirt.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('psirt.introPre')} <code>PSIRT_PUBLIC</code> {$t('psirt.introMid')} <code>/.well-known/csaf/</code>.
		</p>
	</div>
	{#if !editing}<button class="btn btn-primary btn-sm" onclick={() => open(null)}>{$t('psirt.newButton')}</button>{/if}
</div>

{#if editing}
	<div class="mb-3 flex items-center gap-2">
		<button class="btn btn-ghost btn-sm" onclick={() => (editing = null)}>{$t('psirt.backButton')}</button>
		{#if editing.id}
			<span class="font-mono text-sm">{editing.tracking_id}</span>
			<span class="badge {tone(editing.state)}">{stateLabel(editing.state)}</span>
			{#if editing.version}<span class="badge badge-outline">v{editing.version}</span>{/if}
			{#if editing.unpublished_changes}<span class="badge badge-warning badge-outline">{$t('psirt.unpublishedChanges')}</span>{/if}
		{/if}
	</div>
	<form onsubmit={save} class="card bg-base-100 shadow-sm">
		<div class="card-body grid gap-3 md:grid-cols-2">
			<Field label={$t('psirt.productLabel')} required>
				<select bind:value={form.project_id} required class="select select-bordered select-sm w-full">
					<option value="" disabled>{$t('psirt.choose')}</option>
					{#each projects as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
				</select>
			</Field>
			<Field label={$t('psirt.productNameLabel')} hint={$t('psirt.productNameHint')}>
				<input bind:value={form.product_name} class="input input-bordered input-sm w-full" />
			</Field>
			<div class="md:col-span-2"><Field label={$t('psirt.titleLabel')} required>
				<input bind:value={form.title} required class="input input-bordered input-sm w-full" />
			</Field></div>
			<div class="md:col-span-2"><Field label={$t('psirt.summaryLabel')} required>
				<textarea bind:value={form.summary} required rows="2" class="textarea textarea-bordered textarea-sm w-full"></textarea>
			</Field></div>
			<div class="md:col-span-2"><Field label={$t('psirt.detailsLabel')}>
				<textarea bind:value={form.details} rows="3" class="textarea textarea-bordered textarea-sm w-full"></textarea>
			</Field></div>
			<Field label={$t('psirt.cveLabel')}><input bind:value={form.cve} placeholder="CVE-2026-…" class="input input-bordered input-sm w-full font-mono" /></Field>
			<Field label={$t('psirt.cvssVectorLabel')}><input bind:value={form.cvss_vector} placeholder="CVSS:3.1/AV:N/…" class="input input-bordered input-sm w-full font-mono" /></Field>
			<Field label={$t('psirt.cweLabel')}><input bind:value={form.cwe} placeholder="CWE-79" class="input input-bordered input-sm w-full font-mono" /></Field>
			<Field label={$t('psirt.cweNameLabel')} hint={$t('psirt.cweNameHint')}><input bind:value={form.cwe_name} class="input input-bordered input-sm w-full" /></Field>
			<Field label={$t('psirt.affectedLabel')} hint={$t('psirt.affectedHint')}>
				<input bind:value={form.affected} class="input input-bordered input-sm w-full font-mono" />
			</Field>
			<Field label={$t('psirt.fixedLabel')} hint={$t('psirt.fixedHint')}>
				<input bind:value={form.fixed} class="input input-bordered input-sm w-full font-mono" />
			</Field>
			<div class="md:col-span-2"><Field label={$t('psirt.remediationLabel')}>
				<textarea bind:value={form.remediation} rows="2" class="textarea textarea-bordered textarea-sm w-full"></textarea>
			</Field></div>
			<Field label={$t('psirt.ackNamesLabel')} hint={$t('psirt.ackNamesHint')}><input bind:value={form.ack_names} class="input input-bordered input-sm w-full" /></Field>
			<Field label={$t('psirt.orgLabel')}><input bind:value={form.ack_org} class="input input-bordered input-sm w-full" /></Field>
			<div class="md:col-span-2 flex flex-wrap justify-end gap-2">
				{#if editing.id}
					<button type="button" class="btn btn-ghost btn-sm" onclick={showPreview}>{$t('psirt.previewButton')}</button>
					{#if editing.state === 'draft'}<button type="button" class="btn btn-ghost btn-sm text-error" onclick={remove}>{$t('psirt.deleteDraftButton')}</button>{/if}
					{#if editing.state === 'published'}
						<button type="button" class="btn btn-ghost btn-sm" onclick={() => api.downloadPSIRT(editing.id, `${editing.tracking_id.toLowerCase()}.json`)}>{$t('psirt.downloadButton')}</button>
						<button type="button" class="btn btn-ghost btn-sm text-error" onclick={withdraw}>{$t('psirt.withdrawButton')}</button>
					{/if}
					{#if editing.state !== 'withdrawn'}
						<button type="button" class="btn btn-secondary btn-sm" onclick={publish}>{editing.version ? $t('psirt.republishButton') : $t('psirt.publishButton')}</button>
					{/if}
				{/if}
				<button class="btn btn-primary btn-sm" disabled={saving}>{$t('psirt.saveDraftButton')}</button>
			</div>
		</div>
	</form>
	{#if preview}
		<pre class="mt-4 max-h-96 overflow-auto rounded-box bg-base-200 p-3 text-xs">{JSON.stringify(preview, null, 2)}</pre>
	{/if}
{:else}
	<State {loading} {error} empty={!loading && !error && list.length === 0} emptyText={$t('psirt.empty')} />
	{#if !loading && list.length > 0}
		<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
			<table class="table table-sm">
				<thead><tr><th>{$t('psirt.colId')}</th><th>{$t('psirt.colTitle')}</th><th>{$t('psirt.colProduct')}</th><th>{$t('psirt.colCve')}</th><th>{$t('psirt.colState')}</th><th>{$t('psirt.colVersion')}</th></tr></thead>
				<tbody>
					{#each list as a (a.id)}
						<tr class="hover cursor-pointer" onclick={() => open(a)}>
							<td class="font-mono text-xs">{a.tracking_id}</td>
							<td class="font-medium">{a.title}</td>
							<td>{a.product_name || a.project_name}</td>
							<td class="font-mono text-xs">{a.cve}</td>
							<td><span class="badge badge-sm {tone(a.state)}">{stateLabel(a.state)}</span>{#if a.unpublished_changes} <span class="badge badge-xs badge-warning badge-outline">{$t('psirt.editedBadge')}</span>{/if}</td>
							<td>{a.version || ''}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
{/if}
