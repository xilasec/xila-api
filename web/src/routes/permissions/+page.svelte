<script>
	// Permission audit (admin): every principal, every project they can reach,
	// the effective role and each grant that gives it.
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api.js';
	import { t, labelOf } from '$lib/i18n.js';
	import State from '$lib/components/State.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import ExportMenu from '$lib/components/ExportMenu.svelte';
	import AccessTable from '$lib/components/AccessTable.svelte';

	const LIMIT = 50;
	let loading = $state(true);
	let error = $state('');
	let entries = $state(/** @type {any[]} */ ([]));
	let offset = $state(0);
	let hasMore = $state(false);
	let filters = $state({ user: '', role: '', source: '', principal_kind: '' });

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.listPermissions({ ...filters, limit: LIMIT, offset });
			entries = res.entries ?? [];
			hasMore = res.pagination?.has_more ?? false;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('perm.loadFailed');
		} finally {
			loading = false;
		}
	}

	/** @param {SubmitEvent} e */
	function search(e) {
		e.preventDefault();
		offset = 0;
		load();
	}

	function clear() {
		filters = { user: '', role: '', source: '', principal_kind: '' };
		offset = 0;
		load();
	}

	/** @param {number} o */
	function gotoPage(o) {
		offset = o;
		load();
	}

	onMount(load);
</script>

<div class="flex items-center justify-between mb-4">
	<div>
		<h1 class="text-2xl font-bold">{$t('perm.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('perm.subtitle')}</p>
	</div>
	<ExportMenu run={(/** @type {'csv' | 'xlsx'} */ format) => api.exportPermissions({ ...filters }, format)} />
</div>

<form onsubmit={search} class="flex flex-wrap items-end gap-2 mb-4">
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('perm.principalEmail')}</span>
		<input bind:value={filters.user} placeholder="dana@" class="input input-bordered input-sm w-44" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('perm.effectiveRole')}</span>
		<select bind:value={filters.role} class="select select-bordered select-sm">
			<option value="">{$t('perm.any')}</option>
			{#each ['admin', 'owner', 'editor', 'viewer'] as r}<option value={r}>{$labelOf('role', r)}</option>{/each}
		</select>
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('perm.grantedBy')}</span>
		<select bind:value={filters.source} class="select select-bordered select-sm">
			<option value="">{$t('perm.any')}</option>
			<option value="manual">{$t('perm.manualGrant')}</option>
			<option value="sso">{$t('perm.ssoGroupSync')}</option>
		</select>
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('perm.principal')}</span>
		<select bind:value={filters.principal_kind} class="select select-bordered select-sm">
			<option value="">{$t('perm.peopleAndServiceAccounts')}</option>
			<option value="user">{$t('perm.people')}</option>
			<option value="service">{$t('perm.serviceAccounts')}</option>
		</select>
	</label>
	<button class="btn btn-sm btn-primary">{$t('perm.search')}</button>
	<button type="button" class="btn btn-sm btn-ghost" onclick={clear}>{$t('perm.clear')}</button>
</form>

<State {loading} {error} empty={!loading && !error && entries.length === 0} emptyText={$t('perm.empty')} />
{#if !loading && !error && entries.length > 0}
	<AccessTable {entries} showPrincipal showProject />
{/if}
<Pagination limit={LIMIT} {offset} count={entries.length} {hasMore} onchange={gotoPage} />
