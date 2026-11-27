<script>
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, errorMessage } from '#lib/api.js';
	import { me, notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import { fmtDate } from '#lib/format.js';

	const LIMIT = 50;
	const sp = page.url.searchParams;

	let tab = $state(sp.get('tab') === 'groups' ? 'groups' : 'catalog');

	// --- catalog ---
	let q = $state({ q: sp.get('q') ?? '', category: sp.get('category') ?? '', osi: sp.get('osi') ?? '' });
	let licenses = $state(/** @type {any[]} */ ([]));
	let categories = $state(/** @type {string[]} */ ([]));
	let listVersion = $state('');
	let total = $state(0);
	let meta = $state({ limit: LIMIT, offset: 0, count: 0, has_more: false });
	let loading = $state(true);
	// The license shown in the side panel (?id=), with the groups it's in.
	let detail = $state(/** @type {any} */ (null));

	async function loadCatalog(offset = 0) {
		loading = true;
		try {
			const res = await api.listLicenses({ ...q, limit: LIMIT, offset });
			licenses = res.licenses ?? [];
			categories = res.categories ?? [];
			listVersion = res.list_version;
			total = res.total;
			meta = res.pagination;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	function syncURL() {
		const params = new URLSearchParams();
		if (tab === 'groups') params.set('tab', 'groups');
		for (const k of /** @type {const} */ (['q', 'category', 'osi'])) if (q[k]) params.set(k, q[k]);
		if (detail) params.set('id', detail.id);
		goto('?' + params.toString(), { shallow: true, replace: true });
	}

	/** @param {SubmitEvent} e */
	function search(e) {
		e.preventDefault();
		syncURL();
		loadCatalog(0);
	}

	/** @param {string} id */
	async function showLicense(id, fromUser = true) {
		try {
			detail = await api.getLicense(id);
			if (fromUser) syncURL();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	function closeDetail() {
		detail = null;
		syncURL();
	}

	// --- groups ---
	let groups = $state(/** @type {any[]} */ ([]));
	let builtin = $state(/** @type {any[]} */ ([]));
	let groupsLoading = $state(false);
	let builtinMembers = $state(/** @type {any} */ (null)); // { category, license_ids } when expanded
	const blank = () => ({ id: '', name: '', description: '', ids: '' });
	let form = $state(blank());
	let saving = $state(false);

	async function loadGroups() {
		groupsLoading = true;
		try {
			const res = await api.listLicenseGroups();
			groups = res.groups ?? [];
			builtin = res.builtin ?? [];
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			groupsLoading = false;
		}
	}

	/** @param {string} ref */
	async function showBuiltin(ref) {
		try {
			builtinMembers = await api.getLicenseGroup(ref);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} g */
	function editGroup(g) {
		form = { id: g.id, name: g.name, description: g.description, ids: g.license_ids.join(', ') };
	}

	/** @param {SubmitEvent} e */
	async function saveGroup(e) {
		e.preventDefault();
		saving = true;
		const body = {
			name: form.name,
			description: form.description,
			license_ids: form.ids.split(/[\s,]+/).filter(Boolean)
		};
		try {
			if (form.id) await api.updateLicenseGroup(form.id, body);
			else await api.createLicenseGroup(body);
			notify(form.id ? $t('lic.groupSaved') : $t('lic.groupCreated'), 'success');
			form = blank();
			await loadGroups();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} g */
	async function deleteGroup(g) {
		if (!confirm($t('lic.confirmDeleteGroup', { name: g.name }))) return;
		try {
			await api.deleteLicenseGroup(g.id);
			if (form.id === g.id) form = blank();
			await loadGroups();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {string} t */
	function switchTab(t) {
		tab = t;
		syncURL();
		if (t === 'groups' && groups.length === 0 && builtin.length === 0) loadGroups();
	}

	// Initial load runs from the URL; no shallow goto here (the router isn't ready).
	onMount(() => {
		loadCatalog(0);
		if (tab === 'groups') loadGroups();
		const id = sp.get('id');
		if (id) showLicense(id, false);
	});

	/** @param {string} cat */
	const badgeFor = (cat) =>
		/** @type {Record<string, string>} */ ({
			Permissive: 'badge-success',
			'Public Domain': 'badge-success',
			'Copyleft Limited': 'badge-warning',
			Copyleft: 'badge-error',
			Commercial: 'badge-error',
			'Non-Commercial': 'badge-error'
		})[cat] ?? 'badge-ghost';
</script>

<div class="mb-5 flex flex-wrap items-end justify-between gap-3">
	<div>
		<h1 class="text-2xl font-bold">{$t('lic.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('lic.subtitle', { version: listVersion ? '\u00a0' + listVersion : '' })}
		</p>
	</div>
	<div role="tablist" class="tabs tabs-box">
		<button role="tab" class="tab" class:tab-active={tab === 'catalog'} onclick={() => switchTab('catalog')}>{$t('lic.tabCatalog')}</button>
		<button role="tab" class="tab" class:tab-active={tab === 'groups'} onclick={() => switchTab('groups')}>{$t('lic.tabGroups')}</button>
	</div>
</div>

{#if detail}
	<div class="card bg-base-100 shadow-sm mb-5">
		<div class="card-body">
			<div class="flex items-start justify-between gap-3">
				<div>
					<h2 class="card-title font-mono">{detail.id}</h2>
					<p class="text-sm">{detail.name || '—'}</p>
				</div>
				<button class="btn btn-ghost btn-sm" onclick={closeDetail}>✕</button>
			</div>
			<div class="flex flex-wrap gap-2 text-xs">
				{#if detail.kind === 'exception'}<span class="badge badge-outline">{$t('lic.exception')}</span>{/if}
				{#if detail.category}<span class="badge {badgeFor(detail.category)}">{$labelOf('licenseCategory', detail.category)}</span>{/if}
				{#if detail.osi_approved}<span class="badge badge-info">{$t('lic.osiApproved')}</span>{/if}
				{#if detail.fsf_libre}<span class="badge badge-info badge-outline">{$t('lic.fsfLibre')}</span>{/if}
				{#if detail.deprecated}<span class="badge badge-warning badge-outline">{$t('lic.deprecatedId')}</span>{/if}
			</div>
			<p class="text-sm">
				{$t('lic.inGroups')}
				{#each detail.groups as g, i (g.id)}{i ? ', ' : ''}<span class="font-medium">{g.name}</span>{:else}<span class="text-base-content/50">{$t('lic.noGroups')}</span>{/each}
			</p>
			<div class="flex gap-3 text-sm">
				{#if !detail.id.startsWith('LicenseRef-')}
					<a class="link link-primary" href={`https://spdx.org/licenses/${detail.id}.html`} target="_blank" rel="noreferrer">{$t('lic.spdxPage')}</a>
				{/if}
				<a class="link link-primary" href={`/components?license=${encodeURIComponent(detail.id)}`}>{$t('lic.componentsUnderIt')}</a>
			</div>
		</div>
	</div>
{/if}

{#if tab === 'catalog'}
	<form onsubmit={search} class="card bg-base-100 shadow-sm mb-5">
		<div class="card-body flex-row flex-wrap items-end gap-3">
			<label class="form-control flex-1 min-w-48">
				<span class="label-text mb-1">{$t('lic.idOrName')}</span>
				<input bind:value={q.q} placeholder={$t('lic.idOrNamePlaceholder')} class="input input-bordered input-sm w-full" />
			</label>
			<select bind:value={q.category} class="select select-bordered select-sm">
				<option value="">{$t('lic.anyCategory')}</option>
				{#each categories as c (c)}<option value={c}>{c}</option>{/each}
			</select>
			<select bind:value={q.osi} class="select select-bordered select-sm">
				<option value="">{$t('lic.osiAny')}</option>
				<option value="true">{$t('lic.osiApproved')}</option>
				<option value="false">{$t('lic.notOsiApproved')}</option>
			</select>
			<button class="btn btn-primary btn-sm">{$t('lic.search')}</button>
		</div>
	</form>

	<State {loading} empty={!loading && licenses.length === 0} emptyText={$t('lic.empty')} />
	{#if !loading && licenses.length > 0}
		<p class="mb-2 text-sm text-base-content/60">{$t('lic.licenseCount', { count: total })}</p>
		<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
			<table class="table table-sm">
				<thead><tr><th>{$t('lic.colId')}</th><th>{$t('lic.colName')}</th><th>{$t('lic.colCategory')}</th><th>{$t('lic.colFlags')}</th></tr></thead>
				<tbody>
					{#each licenses as l (l.id)}
						<tr class="hover cursor-pointer" onclick={() => showLicense(l.id)}>
							<td class="font-mono text-xs">{l.id}</td>
							<td class="text-sm">{l.name}</td>
							<td>{#if l.category}<span class="badge badge-sm {badgeFor(l.category)} whitespace-nowrap">{$labelOf('licenseCategory', l.category)}</span>{:else}<span class="text-xs text-base-content/40">—</span>{/if}</td>
							<td class="space-x-1 whitespace-nowrap">
								{#if l.osi_approved}<span class="badge badge-xs badge-info">OSI</span>{/if}
								{#if l.fsf_libre}<span class="badge badge-xs badge-info badge-outline">FSF</span>{/if}
								{#if l.deprecated}<span class="badge badge-xs badge-warning badge-outline">{$t('lic.deprecatedShort')}</span>{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination limit={meta.limit} offset={meta.offset} count={meta.count} hasMore={meta.has_more} onchange={loadCatalog} />
	{/if}
{:else}
	<div class="grid gap-5 lg:grid-cols-2">
		<div>
			<h2 class="mb-2 font-semibold">{$t('lic.customGroups')}</h2>
			<State loading={groupsLoading} empty={!groupsLoading && groups.length === 0} emptyText={$t('lic.noCustomGroups')} />
			{#each groups as g (g.id)}
				<div class="card bg-base-100 shadow-sm mb-3">
					<div class="card-body py-4">
						<div class="flex items-start justify-between gap-2">
							<div>
								<h3 class="font-semibold">{g.name}</h3>
								{#if g.description}<p class="text-sm text-base-content/60">{g.description}</p>{/if}
							</div>
							{#if $me?.is_admin}
								<div class="flex gap-1">
									<button class="btn btn-ghost btn-xs" onclick={() => editGroup(g)}>{$t('common.edit')}</button>
									<button class="btn btn-ghost btn-xs text-error" onclick={() => deleteGroup(g)}>{$t('common.delete')}</button>
								</div>
							{/if}
						</div>
						<div class="flex flex-wrap gap-1">
							{#each g.license_ids as id (id)}
								<button class="badge badge-outline badge-sm font-mono" onclick={() => showLicense(id)}>{id}</button>
							{:else}<span class="text-xs text-base-content/50">{$t('lic.idsEmpty')}</span>{/each}
						</div>
						<p class="text-xs text-base-content/40">{$t('lic.updated', { date: fmtDate(g.updated_at) })}</p>
					</div>
				</div>
			{/each}

			{#if $me?.is_admin}
				<form onsubmit={saveGroup} class="card bg-base-100 shadow-sm">
					<div class="card-body gap-3">
						<h3 class="font-semibold">{form.id ? $t('lic.editGroup') : $t('lic.newGroup')}</h3>
						<Field label={$t('home.name')} required>
							<input bind:value={form.name} required class="input input-bordered input-sm" />
						</Field>
						<Field label={$t('lic.description')}>
							<input bind:value={form.description} class="input input-bordered input-sm" />
						</Field>
						<Field label={$t('lic.licenseIds')} hint={$t('lic.licenseIdsHint')}>
							<textarea bind:value={form.ids} rows="3" class="textarea textarea-bordered textarea-sm font-mono" placeholder="MIT, Apache-2.0, BSD-3-Clause"></textarea>
						</Field>
						<div class="flex gap-2">
							<button class="btn btn-primary btn-sm" disabled={saving}>{form.id ? $t('common.save') : $t('common.create')}</button>
							{#if form.id}<button type="button" class="btn btn-ghost btn-sm" onclick={() => (form = blank())}>{$t('common.cancel')}</button>{/if}
						</div>
					</div>
				</form>
			{/if}
		</div>

		<div>
			<h2 class="mb-2 font-semibold">{$t('lic.builtinGroups')} <span class="text-sm font-normal text-base-content/50">{$t('lic.builtinGroupsNote')}</span></h2>
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('lic.colCategory')}</th><th>{$t('lic.colReference')}</th><th class="text-right">{$t('lic.colLicenses')}</th></tr></thead>
					<tbody>
						{#each builtin as b (b.ref)}
							<tr class="hover cursor-pointer" onclick={() => showBuiltin(b.ref)}>
								<td><span class="badge badge-sm {badgeFor(b.category)}">{$labelOf('licenseCategory', b.category)}</span></td>
								<td class="font-mono text-xs">{b.ref}</td>
								<td class="text-right">{b.count}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if builtinMembers}
				<div class="card bg-base-100 shadow-sm mt-3">
					<div class="card-body py-4">
						<div class="flex items-center justify-between">
							<h3 class="font-semibold">{$labelOf('licenseCategory', builtinMembers.category)}</h3>
							<button class="btn btn-ghost btn-xs" onclick={() => (builtinMembers = null)}>✕</button>
						</div>
						<div class="flex flex-wrap gap-1 max-h-64 overflow-y-auto">
							{#each builtinMembers.license_ids as id (id)}
								<button class="badge badge-outline badge-sm font-mono" onclick={() => showLicense(id)}>{id}</button>
							{/each}
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}
