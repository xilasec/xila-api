<script>
	// Stored, versioned VEX documents (M13 13.14): configure once, publish on
	// demand. Publishing re-renders from current data and appends a revision
	// only when the content actually changed.
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { api, errorMessage } from '#lib/api.js';
	import { notify, me } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Icon from '#lib/components/Icon.svelte';

	let loading = $state(true);
	let error = $state('');
	let list = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let editing = $state(/** @type {any} */ (null)); // null = list view; {} = new
	let saving = $state(false);
	let publishing = $state(false);
	let expanded = $state(/** @type {Record<string, boolean>} */ ({}));
	let revisionsCache = $state(/** @type {Record<string, any[]>} */ ({}));

	const blank = () => ({
		format: 'openvex', spec_version: '', scope_kind: 'project', project_id: '', branch: '', branches: '',
		vuln_id: '', author: '', publisher_name: '', publisher_namespace: '', publisher_contact: ''
	});
	let form = $state(blank());

	async function load() {
		loading = true;
		error = '';
		try {
			[list, projects] = await Promise.all([api.listVexDocuments(), api.listProjects()]);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {any} d */
	function open(d) {
		editing = d ?? {};
		form = d
			? {
					format: d.format, spec_version: d.spec_version || '', scope_kind: d.scope_kind, project_id: d.project_id || '',
					branch: d.scope_kind === 'project' ? (d.targets?.[0]?.branch ?? '') : '',
					branches: d.scope_kind === 'versions' ? (d.targets ?? []).map((/** @type {any} */ t) => t.branch || t.version_id).join(', ') : '',
					vuln_id: d.vuln_id || '', author: d.author || '', publisher_name: d.publisher_name || '',
					publisher_namespace: d.publisher_namespace || '', publisher_contact: d.publisher_contact || ''
				}
			: blank();
	}

	function body() {
		/** @type {any} */
		const d = {
			format: form.format, spec_version: form.format === 'cyclonedx' ? form.spec_version : '',
			scope_kind: form.scope_kind, author: form.author.trim(), publisher_name: form.publisher_name.trim(),
			publisher_namespace: form.publisher_namespace.trim(), publisher_contact: form.publisher_contact.trim()
		};
		if (form.scope_kind === 'vulnerability') {
			d.vuln_id = form.vuln_id.trim();
		} else {
			d.project_id = form.project_id;
			d.targets =
				form.scope_kind === 'project'
					? [{ branch: form.branch.trim() }]
					: form.branches.split(',').map((/** @type {string} */ s) => s.trim()).filter(Boolean).map((/** @type {string} */ b) => ({ branch: b }));
		}
		return d;
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			editing = editing?.id ? await api.updateVexDocument(editing.id, body()) : await api.createVexDocument(body());
			notify($t('vexDocs.saved'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	async function publish() {
		publishing = true;
		try {
			const res = await api.publishVexDocument(editing.id);
			editing = res.document;
			delete revisionsCache[editing.id];
			notify(res.changed ? $t('vexDocs.published', { version: editing.version }) : $t('vexDocs.unchanged'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			publishing = false;
		}
	}

	async function remove() {
		if (!confirm($t('vexDocs.deleteConfirm'))) return;
		try {
			await api.deleteVexDocument(editing.id);
			editing = null;
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} d */
	async function toggleRevisions(d) {
		expanded[d.id] = !expanded[d.id];
		if (expanded[d.id] && !revisionsCache[d.id]) {
			try {
				revisionsCache[d.id] = await api.listVexDocumentRevisions(d.id);
			} catch (err) {
				notify(errorMessage(err));
			}
		}
	}

	/** @param {any} rev @param {any} d */
	function download(rev, d) {
		api.downloadVexDocumentRevision(d.id, rev.number, `${d.document_id}-r${rev.number}.json`).catch((err) => notify(errorMessage(err)));
	}

	/** @param {any} d */
	function projectName(d) {
		return projects.find((p) => p.id === d.project_id)?.name ?? d.project_slug ?? d.project_id;
	}
	/** @param {any} d */
	function scopeLabel(d) {
		if (d.scope_kind === 'vulnerability') return `${d.vuln_id} (${$t('vexDocs.scopeAllProjects')})`;
		if (d.scope_kind === 'versions') return `${projectName(d)} (${$t('vexDocs.scopeNVersions', { count: (d.targets ?? []).length })})`;
		const branch = d.targets?.[0]?.branch;
		return `${projectName(d)} (${branch || $t('vexDocs.scopeDefaultBranch')})`;
	}

	onMount(async () => {
		await load();
		// Seeded from a project's VEX tab "create document" button.
		const seedProject = page.url.searchParams.get('seed_project');
		if (seedProject) {
			open(null);
			form.project_id = seedProject;
			form.branch = page.url.searchParams.get('seed_branch') ?? '';
		}
	});
</script>

<div class="flex items-center justify-between mb-4">
	<div>
		<h1 class="text-2xl font-bold">{$t('vexDocs.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('vexDocs.intro')}</p>
	</div>
	{#if !editing}<button class="btn btn-primary btn-sm" onclick={() => open(null)}>{$t('vexDocs.newButton')}</button>{/if}
</div>

{#if editing}
	<div class="mb-3 flex items-center gap-2">
		<button class="btn btn-ghost btn-sm" onclick={() => (editing = null)}>{$t('vexDocs.backButton')}</button>
		{#if editing.id}
			<span class="font-mono text-sm">{editing.document_id}</span>
			{#if editing.version}<span class="badge badge-outline">v{editing.version}</span>{/if}
		{/if}
	</div>
	<form onsubmit={save} class="card bg-base-100 shadow-sm">
		<div class="card-body grid gap-3 md:grid-cols-2">
			<Field label={$t('vexDocs.formatLabel')} required>
				<select bind:value={form.format} class="select select-bordered select-sm w-full">
					<option value="openvex">OpenVEX</option>
					<option value="csaf">CSAF 2.0</option>
					<option value="cyclonedx">CycloneDX</option>
				</select>
			</Field>
			{#if form.format === 'cyclonedx'}
				<Field label={$t('vexDocs.specVersionLabel')} hint={$t('vexDocs.specVersionHint')}>
					<select bind:value={form.spec_version} class="select select-bordered select-sm w-full">
						<option value="">1.6</option>
						<option value="1.7">1.7</option>
					</select>
				</Field>
			{/if}
			<Field label={$t('vexDocs.scopeLabel')} required>
				<select bind:value={form.scope_kind} class="select select-bordered select-sm w-full" disabled={form.format === 'cyclonedx'}>
					<option value="project">{$t('vexDocs.scopeProject')}</option>
					<option value="versions">{$t('vexDocs.scopeVersions')}</option>
					{#if $me?.is_admin}<option value="vulnerability">{$t('vexDocs.scopeVulnerability')}</option>{/if}
				</select>
			</Field>
			{#if form.scope_kind === 'vulnerability'}
				<Field label={$t('vexDocs.vulnIdLabel')} hint={$t('vexDocs.vulnIdHint')} required>
					<input bind:value={form.vuln_id} placeholder="CVE-2026-…" class="input input-bordered input-sm w-full font-mono" />
				</Field>
			{:else}
				<Field label={$t('vexDocs.projectLabel')} required>
					<select bind:value={form.project_id} required class="select select-bordered select-sm w-full">
						<option value="" disabled>{$t('vexDocs.choose')}</option>
						{#each projects as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
					</select>
				</Field>
				{#if form.scope_kind === 'project'}
					<Field label={$t('vexDocs.branchLabel')} hint={$t('vexDocs.branchHint')}>
						<input bind:value={form.branch} class="input input-bordered input-sm w-full" />
					</Field>
				{:else}
					<Field label={$t('vexDocs.branchesLabel')} hint={$t('vexDocs.branchesHint')}>
						<input bind:value={form.branches} class="input input-bordered input-sm w-full" />
					</Field>
				{/if}
			{/if}
			<Field label={$t('vexDocs.authorLabel')} hint={$t('vexDocs.authorHint')}>
				<input bind:value={form.author} class="input input-bordered input-sm w-full" />
			</Field>
			<Field label={$t('vexDocs.publisherNameLabel')}>
				<input bind:value={form.publisher_name} class="input input-bordered input-sm w-full" />
			</Field>
			<Field label={$t('vexDocs.publisherNamespaceLabel')} hint={$t('vexDocs.publisherNamespaceHint')}>
				<input bind:value={form.publisher_namespace} class="input input-bordered input-sm w-full" />
			</Field>
			<Field label={$t('vexDocs.publisherContactLabel')}>
				<input bind:value={form.publisher_contact} class="input input-bordered input-sm w-full" />
			</Field>
			<div class="md:col-span-2 flex flex-wrap justify-end gap-2">
				{#if editing.id}
					<button type="button" class="btn btn-ghost btn-sm" onclick={remove}>{$t('vexDocs.deleteButton')}</button>
					<button type="button" class="btn btn-sm" disabled={publishing} onclick={publish}>
						{#if publishing}<span class="loading loading-spinner loading-xs"></span>{/if}
						{$t('vexDocs.publishButton')}
					</button>
				{/if}
				<button type="submit" class="btn btn-primary btn-sm" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}
					{$t('vexDocs.saveButton')}
				</button>
			</div>
		</div>
	</form>
	{#if editing.id}
		<div class="mt-4">
			<h2 class="mb-2 font-semibold">{$t('vexDocs.revisionsTitle')}</h2>
			<State empty={!(editing.revisions ?? []).length} emptyText={$t('vexDocs.noRevisions')} />
			{#if (editing.revisions ?? []).length > 0}
				<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
					<table class="table table-sm">
						<thead><tr><th>{$t('vexDocs.colRevisionNumber')}</th><th>{$t('vexDocs.colPublishedAt')}</th><th></th></tr></thead>
						<tbody>
							{#each editing.revisions as rev (rev.number)}
								<tr class="hover">
									<td>{rev.number}</td>
									<td class="text-xs">{new Date(rev.published_at).toLocaleString()}</td>
									<td class="text-right">
										<button class="btn btn-ghost btn-xs" onclick={() => download(rev, editing)}>{$t('common.download')}</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{/if}
{:else}
	<State {loading} {error} empty={!loading && !error && list.length === 0} emptyText={$t('vexDocs.empty')} />
	{#if !loading && list.length > 0}
		<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
			<table class="table table-sm">
				<thead>
					<tr>
						<th></th>
						<th>{$t('vexDocs.colDocument')}</th>
						<th>{$t('vexDocs.colScope')}</th>
						<th>{$t('vexDocs.colFormat')}</th>
						<th>{$t('vexDocs.colVersion')}</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each list as d (d.id)}
						<tr class="hover cursor-pointer" onclick={() => open(d)}>
							<td onclick={(e) => e.stopPropagation()}>
								<button class="btn btn-ghost btn-xs" onclick={() => toggleRevisions(d)} aria-label={$t('vexDocs.revisionsTitle')}>
									<Icon name="chevron" class="h-3 w-3 transition-transform {expanded[d.id] ? 'rotate-90' : ''}" />
								</button>
							</td>
							<td class="font-mono text-xs">{d.document_id}</td>
							<td class="text-xs">{scopeLabel(d)}</td>
							<td class="text-xs">{d.format}</td>
							<td>{#if d.version}<span class="badge badge-outline badge-sm">v{d.version}</span>{:else}<span class="badge badge-ghost badge-sm">{$t('vexDocs.unpublished')}</span>{/if}</td>
							<td class="text-right" onclick={(e) => e.stopPropagation()}>
								<button class="btn btn-ghost btn-xs" onclick={() => open(d)}>{$t('common.edit')}</button>
							</td>
						</tr>
						{#if expanded[d.id]}
							<tr>
								<td colspan="6" class="bg-base-200/40">
									{#if !revisionsCache[d.id]}
										<span class="loading loading-spinner loading-xs"></span>
									{:else if revisionsCache[d.id].length === 0}
										<span class="text-xs text-base-content/50">{$t('vexDocs.noRevisions')}</span>
									{:else}
										<table class="table table-xs">
											<thead><tr><th>{$t('vexDocs.colRevisionNumber')}</th><th>{$t('vexDocs.colPublishedAt')}</th><th></th></tr></thead>
											<tbody>
												{#each revisionsCache[d.id] as rev (rev.number)}
													<tr>
														<td>{rev.number}</td>
														<td>{new Date(rev.published_at).toLocaleString()}</td>
														<td class="text-right">
															<button class="btn btn-ghost btn-xs" onclick={() => download(rev, d)}>{$t('common.download')}</button>
														</td>
													</tr>
												{/each}
											</tbody>
										</table>
									{/if}
								</td>
							</tr>
						{/if}
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
{/if}
