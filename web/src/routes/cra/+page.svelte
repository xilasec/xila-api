<script>
	// Every EU CRA Article 14 reporting case the caller can see (all for an
	// admin), most urgent first, with live deadline timers.
	import { api, errorMessage } from '#lib/api.js';
	import { me, notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate } from '#lib/format.js';
	import { CRA_STATES, stateLabel, stateClass, deadlineClass, deadlineLabel, countdown, nextDeadline } from '#lib/cra.js';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import CraCaseDetail from '#lib/components/CraCaseDetail.svelte';

	const LIMIT = 50;
	let loading = $state(true);
	let error = $state('');
	let cases = $state(/** @type {any[]} */ ([]));
	let meta = $state(/** @type {any} */ (null));
	let stateFilter = $state('active');
	let offset = $state(0);
	let selected = $state(/** @type {string | null} */ (null));
	let sweeping = $state(false);
	let now = $state(Date.now());

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.listCRACases({ state: stateFilter === 'all' ? '' : stateFilter, limit: LIMIT, offset });
			cases = res.cases ?? [];
			meta = res.pagination;
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		stateFilter;
		offset;
		load();
	});
	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(t);
	});

	async function sweep() {
		sweeping = true;
		try {
			const res = await api.craSweep();
			notify($t('cra.sweepResult', { opened: res.opened, dueSoon: res.due_soon, missed: res.missed }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			sweeping = false;
		}
	}
</script>

<div class="flex items-center justify-between mb-5 gap-3">
	<div>
		<h1 class="text-2xl font-bold">{$t('cra.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('cra.subtitle')}</p>
	</div>
	<div class="flex items-center gap-2">
		<select class="select select-bordered select-sm" bind:value={stateFilter} onchange={() => (offset = 0)}>
			<option value="all">{$t('cra.allStates')}</option>
			{#each CRA_STATES as s}<option value={s}>{stateLabel(s)}</option>{/each}
		</select>
		{#if $me?.is_admin}
			<button class="btn btn-outline btn-sm" onclick={sweep} disabled={sweeping} title={$t('cra.sweepTitle')}>{$t('cra.sweepNow')}</button>
		{/if}
	</div>
</div>

<State {loading} {error} empty={!loading && !error && cases.length === 0} emptyText={$t('cra.empty')} />
{#if !loading && !error && cases.length > 0}
	<div class="card bg-base-100 shadow-sm">
		<div class="overflow-x-auto">
			<table class="table table-sm">
				<thead><tr><th>{$t('cra.colProject')}</th><th>{$t('cra.colVulnerability')}</th><th>{$t('cra.colState')}</th><th>{$t('cra.colAware')}</th><th>{$t('cra.colNextDeadline')}</th><th>{$t('cra.colClocks')}</th></tr></thead>
				<tbody>
					{#each cases as c (c.id)}
						{@const d = nextDeadline(c)}
						<tr class="cursor-pointer hover" class:bg-base-200={selected === c.id} onclick={() => (selected = selected === c.id ? null : c.id)}>
							<td><a class="link" href="/projects/{c.project_id}?tab=compliance" onclick={(e) => e.stopPropagation()}>{c.project_name}</a>
								{#if c.product_name}<div class="text-xs text-base-content/60">{c.product_name} {c.product_version}</div>{/if}</td>
							<td><span class="font-medium">{c.vuln_id}</span><div class="text-xs text-base-content/60 truncate max-w-xs">{c.title}</div></td>
							<td><span class="badge badge-sm {stateClass(c.state)}">{stateLabel(c.state)}</span></td>
							<td class="text-xs">{fmtDate(c.aware_at)}</td>
							<td class="text-xs">
								{#if d && d.due_at}{fmtDate(d.due_at)}<div class={d.status === 'missed' ? 'text-error' : 'text-base-content/60'}>{countdown(d.due_at, now)}</div>{:else}—{/if}
							</td>
							<td>
								{#each c.deadlines as dl (dl.stage)}
									<span class="badge badge-xs mr-1 {deadlineClass(dl.status)}" title={dl.stage}>{deadlineLabel(dl.status)}</span>
								{/each}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	</div>
	<Pagination limit={LIMIT} {offset} count={meta?.count ?? 0} hasMore={meta?.has_more ?? false} onchange={(/** @type {number} */ o) => (offset = o)} />
{/if}
{#if selected}
	<div class="card bg-base-100 shadow-sm mt-4">
		<div class="card-body p-5">
			<CraCaseDetail caseId={selected} onchange={load} />
		</div>
	</div>
{/if}
