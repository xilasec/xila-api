<script>
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { api, ApiError } from '$lib/api.js';
	import { t } from '$lib/i18n.js';
	import { fmtDate, prettyStatus } from '$lib/format.js';
	import Badge from '$lib/components/Badge.svelte';
	import State from '$lib/components/State.svelte';

	let loading = $state(true);
	let error = $state('');
	let findings = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let days = $state(Number($page.url.searchParams.get('days')) || 30);

	// Persist the window in the URL, then reload — so a refresh keeps it.
	function applyDays() {
		goto('?days=' + days, { shallow: true, replace: true });
		load();
	}

	/** @param {string} id */
	const projectName = (id) => projects.find((pr) => pr.id === id)?.name ?? '—';

	/** @param {string | null | undefined} iso */
	function daysLeft(iso) {
		if (!iso) return null;
		return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
	}

	async function load() {
		loading = true;
		error = '';
		try {
			findings = await api.expiringFindings(days);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('exc.loadFailed');
		} finally {
			loading = false;
		}
	}

	onMount(async () => {
		projects = await api.listProjects().catch(() => []);
		await load();
	});
</script>

<div class="flex items-center justify-between mb-5">
	<div>
		<h1 class="text-2xl font-bold">{$t('exc.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('exc.subtitle')}</p>
	</div>
	<select bind:value={days} onchange={applyDays} class="select select-bordered select-sm">
		{#each [7, 30, 60, 90] as d}<option value={d}>{$t('exc.nextDays', { count: d })}</option>{/each}
	</select>
</div>

<State
	loading={loading}
	error={error}
	empty={!loading && !error && findings.length === 0}
	emptyText={$t('exc.empty')}
/>

{#if !loading && findings.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('exc.colExpires')}</th><th>{$t('exc.colSeverity')}</th><th>{$t('exc.colFinding')}</th><th>{$t('exc.colProject')}</th><th>{$t('exc.colReason')}</th><th>{$t('exc.colAcceptedBy')}</th></tr>
			</thead>
			<tbody>
				{#each findings as f (f.id)}
					{@const ra = f.risk_acceptance}
					{@const expires = ra ? ra.expires_at : f.exception_expires_at}
					{@const left = daysLeft(expires)}
					<tr class="hover cursor-pointer" onclick={() => goto(`/findings/${f.id}`)}>
						<td class="whitespace-nowrap">
							<span class="badge badge-sm {(left ?? 0) <= 7 ? 'badge-warning' : 'badge-ghost'}">{$t('sla.days', { count: left ?? 0 })}</span>
							<span class="text-xs text-base-content/50 ml-1">{fmtDate(expires)}</span>
						</td>
						<td><Badge kind="severity" value={f.severity} /></td>
						<td class="max-w-sm truncate">{f.title}</td>
						<td class="text-xs">{projectName(f.project_id)}</td>
						<td class="text-sm max-w-xs truncate" title={ra ? ra.justification : f.exception_reason}>{(ra ? ra.title : f.exception_reason) || '—'}</td>
						<td class="text-xs">{(ra ? ra.approver : f.exception_by) || '—'}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
