<script>
	// The instance audit log (admin): every mutating API request and every
	// sign-in event — who, what, before → after, from where, with what result.
	import { onMount } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate } from '#lib/format.js';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import ExportMenu from '#lib/components/ExportMenu.svelte';

	const LIMIT = 50;
	let loading = $state(true);
	let error = $state('');
	let entries = $state(/** @type {any[]} */ ([]));
	let offset = $state(0);
	let hasMore = $state(false);
	let expanded = $state(/** @type {number | null} */ (null));
	let filters = $state({
		actor: '',
		actor_kind: '',
		action: '',
		resource_type: '',
		resource_id: '',
		project_id: '',
		outcome: '',
		from: '',
		to: ''
	});

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const ACTOR_KIND_KEY = {
		user: 'audit.actorKind.user',
		service_account: 'audit.actorKind.service_account',
		api_token: 'audit.actorKind.api_token',
		system: 'audit.actorKind.system',
		anonymous: 'audit.actorKind.anonymous'
	};
	const actorKinds = ['user', 'service_account', 'api_token', 'system', 'anonymous'];

	function query() {
		return { ...filters };
	}

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.listAuditLog({ ...query(), limit: LIMIT, offset });
			entries = res.entries ?? [];
			hasMore = res.pagination?.has_more ?? false;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('audit.loadFailed');
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
		for (const k of /** @type {(keyof typeof filters)[]} */ (Object.keys(filters))) filters[k] = '';
		offset = 0;
		load();
	}

	/** @param {number} o */
	function gotoPage(o) {
		offset = o;
		load();
	}

	/** @param {any} e */
	function actorLabel(e) {
		if (e.actor_kind === 'system') return $t('audit.system');
		return e.actor_email || e.actor_user_id || $t('audit.unknown');
	}

	/** @param {any} changes */
	function hasChanges(changes) {
		return changes && Object.keys(changes).length > 0;
	}

	onMount(load);
</script>

<div class="flex items-center justify-between mb-4">
	<div>
		<h1 class="text-2xl font-bold">{$t('audit.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('audit.subtitle')}</p>
	</div>
	<ExportMenu run={(/** @type {'csv' | 'xlsx'} */ format) => api.exportAuditLog(query(), format)} />
</div>

<form onsubmit={search} class="flex flex-wrap items-end gap-2 mb-4">
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.actorEmail')}</span>
		<input bind:value={filters.actor} placeholder="dana@" class="input input-bordered input-sm w-40" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.actorKind')}</span>
		<select bind:value={filters.actor_kind} class="select select-bordered select-sm">
			<option value="">{$t('audit.any')}</option>
			{#each actorKinds as k}<option value={k}>{$t(ACTOR_KIND_KEY[k])}</option>{/each}
		</select>
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.actionPrefix')}</span>
		<input bind:value={filters.action} placeholder="auth.login" class="input input-bordered input-sm w-40" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.resourceType')}</span>
		<input bind:value={filters.resource_type} placeholder="projects" class="input input-bordered input-sm w-32" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.resourceId')}</span>
		<input bind:value={filters.resource_id} class="input input-bordered input-sm w-40" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.projectId')}</span>
		<input bind:value={filters.project_id} class="input input-bordered input-sm w-40" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.result')}</span>
		<select bind:value={filters.outcome} class="select select-bordered select-sm">
			<option value="">{$t('audit.any')}</option>
			<option value="success">{$t('audit.success')}</option>
			<option value="failure">{$t('audit.failure')}</option>
		</select>
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.from')}</span>
		<input type="date" bind:value={filters.from} class="input input-bordered input-sm" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('audit.to')}</span>
		<input type="date" bind:value={filters.to} class="input input-bordered input-sm" />
	</label>
	<button class="btn btn-sm btn-primary">{$t('audit.search')}</button>
	<button type="button" class="btn btn-sm btn-ghost" onclick={clear}>{$t('audit.clear')}</button>
</form>

<State {loading} {error} empty={!loading && !error && entries.length === 0} emptyText={$t('audit.empty')} />
{#if !loading && !error && entries.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('audit.colWhen')}</th><th>{$t('audit.colActor')}</th><th>{$t('audit.colAction')}</th><th>{$t('audit.colResource')}</th><th>{$t('audit.colRequest')}</th><th>{$t('audit.colResult')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each entries as e (e.id)}
					<tr class="hover">
						<td class="whitespace-nowrap text-xs">{fmtDate(e.created_at)}</td>
						<td>
							<div class="font-medium">{actorLabel(e)}</div>
							<span class="badge badge-ghost badge-xs">{ACTOR_KIND_KEY[e.actor_kind] ? $t(ACTOR_KIND_KEY[e.actor_kind]) : e.actor_kind}</span>
							{#if e.client_ip}<span class="text-xs text-base-content/50 ml-1">{e.client_ip}</span>{/if}
						</td>
						<td class="font-mono text-xs">{e.action}</td>
						<td class="text-xs">
							{#if e.resource_type}<span class="text-base-content/60">{e.resource_type}</span>{/if}
							{#if e.resource_id}<div class="font-mono">{e.resource_id}</div>{/if}
						</td>
						<td class="font-mono text-xs max-w-xs truncate" title={e.path}>{e.method} {e.path}</td>
						<td>
							<span class="badge badge-sm" class:badge-success={e.outcome === 'success'} class:badge-error={e.outcome === 'failure'}>
								{e.status || e.outcome}
							</span>
						</td>
						<td class="text-right">
							{#if hasChanges(e.changes)}
								<button class="btn btn-ghost btn-xs" onclick={() => (expanded = expanded === e.id ? null : e.id)}>
									{expanded === e.id ? $t('audit.hide') : $t('audit.details')}
								</button>
							{/if}
						</td>
					</tr>
					{#if expanded === e.id}
						<tr>
							<td colspan="7">
								<pre class="text-xs bg-base-200 rounded p-2 overflow-x-auto">{JSON.stringify(e.changes, null, 2)}</pre>
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
{/if}
<Pagination limit={LIMIT} {offset} count={entries.length} {hasMore} onchange={gotoPage} />
