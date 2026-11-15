<script>
	// Cross-project root causes: the same package upgrade, base-image rebuild
	// or rule fix needed in more than one project, merged into one row across
	// every project you can see. Expands to the affected projects and their
	// live remediation action, if any; "Create missing" accepts the proposal
	// in every project you can edit that doesn't already have one.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import Badge from '#lib/components/Badge.svelte';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';

	/** @typedef {import('#lib/i18n.js').MessageKey} MessageKey */
	const SEVS = ['critical', 'high', 'medium', 'low'];
	/** @type {Record<string, MessageKey>} */
	const KIND_KEY = {
		package_upgrade: 'remed.kindUpgrade',
		base_image: 'remed.kindBaseImage',
		iac_rule: 'remed.kindIacRule',
		code_location: 'remed.kindCode',
		config: 'remed.kindConfig'
	};
	/** @type {Record<string, MessageKey>} */
	const STATUS_KEY = {
		open: 'remed.status.open',
		in_progress: 'remed.status.in_progress',
		done: 'remed.status.done',
		wont_do: 'remed.status.wont_do'
	};

	let rootCauses = $state(/** @type {any[]} */ ([]));
	let meta = $state(/** @type {any} */ (null));
	let loading = $state(true);
	let kindFilter = $state('');
	let q = $state('');
	let kevOnly = $state(false);
	let offset = $state(0);
	let open = $state(/** @type {string | null} */ (null)); // "kind|key"
	let detail = $state(/** @type {any | null} */ (null));
	let busy = $state(/** @type {string | null} */ (null));

	/** @param {any} rc */
	const rowKey = (rc) => `${rc.kind}|${rc.key}`;

	async function load() {
		loading = true;
		try {
			const res = await api.rootCauses({
				kind: kindFilter || undefined,
				q: q || undefined,
				kev: kevOnly || undefined,
				limit: 50,
				offset
			});
			rootCauses = res.root_causes ?? [];
			meta = res.pagination;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		load();
	});

	/** @param {any} rc */
	async function toggle(rc) {
		const k = rowKey(rc);
		if (open === k) {
			open = null;
			return;
		}
		open = k;
		detail = null;
		try {
			detail = await api.rootCause(rc.kind, rc.key);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} rc */
	async function createMissing(rc) {
		busy = rowKey(rc);
		try {
			const res = await api.createRootCauseRemediation(rc.kind, rc.key);
			notify($t('rootcause.createdResult', { created: res.created ?? 0, skipped: res.skipped?.length ?? 0 }), 'success');
			await load();
			if (open === rowKey(rc)) detail = await api.rootCause(rc.kind, rc.key);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = null;
		}
	}

	/** @param {number} o */
	function go(o) {
		offset = o;
		load();
	}
</script>

<div class="flex flex-wrap items-center gap-2 mb-3">
	<p class="text-sm text-base-content/60">{$t('rootcause.intro')}</p>
	<input
		class="input input-bordered input-sm ml-auto w-56"
		placeholder={$t('rootcause.searchPlaceholder')}
		bind:value={q}
		oninput={() => {
			offset = 0;
			load();
		}}
	/>
	<select
		class="select select-bordered select-sm"
		bind:value={kindFilter}
		onchange={() => {
			offset = 0;
			load();
		}}
	>
		<option value="">{$t('remed.allKinds')}</option>
		{#each Object.keys(KIND_KEY) as k}<option value={k}>{$t(KIND_KEY[k])}</option>{/each}
	</select>
	<label class="label cursor-pointer gap-2">
		<input
			type="checkbox"
			class="checkbox checkbox-sm"
			bind:checked={kevOnly}
			onchange={() => {
				offset = 0;
				load();
			}}
		/>
		<span class="label-text text-sm">KEV</span>
	</label>
</div>

<State {loading} empty={!loading && rootCauses.length === 0} emptyText={$t('rootcause.empty')} />

{#if !loading && rootCauses.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					<th>{$t('remed.colAction')}</th>
					<th>{$t('rootcause.colProjects')}</th>
					<th>{$t('proj.colOpenFindings')}</th>
					<th class="text-right">{$t('fixplan.colPriorityRemoved')}</th>
					<th>{$t('fixplan.colExploit')}</th>
					<th>{$t('rootcause.colActioned')}</th>
				</tr>
			</thead>
			<tbody>
				{#each rootCauses as rc (rowKey(rc))}
					<tr class="hover cursor-pointer" onclick={() => toggle(rc)} aria-expanded={open === rowKey(rc)}>
						<td>
							<span class="badge badge-ghost badge-xs mr-1">{$t(KIND_KEY[rc.kind] ?? KIND_KEY.config)}</span>
							<span class="font-medium">{rc.title}</span>
							{#if rc.target}<span class="font-mono text-xs text-success ml-1">→ {rc.target}</span>{/if}
						</td>
						<td>{rc.projects}</td>
						<td class="text-xs whitespace-nowrap">
							{$t('triage.findingsCount', { count: rc.findings })}
							{#each SEVS as s}{#if rc.by_severity?.[s]}<span class="ml-1"><Badge kind="severity" value={s} /> {rc.by_severity[s]}</span>{/if}{/each}
						</td>
						<td class="text-right font-semibold">{Math.round(rc.priority_removed)}</td>
						<td class="text-xs">
							{#if rc.kev}<span class="badge badge-error badge-xs">KEV {rc.kev}</span>{/if}
							{#if rc.max_epss}<span class="text-base-content/50 ml-1">EPSS {Math.round(rc.max_epss * 100)}%</span>{/if}
						</td>
						<td>
							{#if rc.all_actioned}
								<span class="badge badge-success badge-xs">{$t('rootcause.allActioned')}</span>
							{:else}
								<button
									class="btn btn-xs"
									disabled={busy === rowKey(rc)}
									onclick={(e) => {
										e.stopPropagation();
										createMissing(rc);
									}}
								>
									{#if busy === rowKey(rc)}<span class="loading loading-spinner loading-xs"></span>{:else}{$t('rootcause.createMissing')}{/if}
								</button>
							{/if}
						</td>
					</tr>
					{#if open === rowKey(rc)}
						<tr>
							<td colspan="6" class="bg-base-200/50">
								{#if !detail}
									<span class="loading loading-spinner loading-xs"></span>
								{:else}
									<ul class="text-sm space-y-2">
										{#each detail.affected_projects as p (p.project_id)}
											<li class="flex flex-wrap items-center gap-2">
												<a class="link" href={`/projects/${p.project_id}?tab=remediation`}>{p.project_name}</a>
												<Badge kind="severity" value={p.max_severity} />
												<span class="text-xs">{$t('triage.findingsCount', { count: p.findings })}</span>
												<span class="text-xs text-base-content/50">{Math.round(p.priority_removed)}</span>
												{#if p.kev}<span class="badge badge-error badge-xs">KEV {p.kev}</span>{/if}
												{#if p.action}
													<span class="badge badge-ghost badge-xs">{$t(STATUS_KEY[p.action.status] ?? 'remed.status.open')}</span>
												{:else}
													<span class="text-xs text-base-content/40">{$t('rootcause.noAction')}</span>
												{/if}
											</li>
										{/each}
									</ul>
								{/if}
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
	{#if meta}
		<Pagination limit={meta.limit} offset={meta.offset} count={meta.count} hasMore={meta.has_more} onchange={go} />
	{/if}
{/if}
