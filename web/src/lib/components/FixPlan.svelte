<script>
	// Fix-first plan: upgrades ranked by the risk they remove ("upgrade
	// log4j-core 2.14.1 → 2.16.0 closes 2 findings"). With projectId it covers
	// one project; without, every project the caller can see.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import Badge from '#lib/components/Badge.svelte';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';

	/** @type {{ projectId?: string }} */
	let { projectId = '' } = $props();

	const SEVS = ['critical', 'high', 'medium', 'low'];
	let fixes = $state(/** @type {any[]} */ ([]));
	let noFix = $state(/** @type {any} */ (null));
	let meta = $state(/** @type {any} */ (null));
	let loading = $state(true);
	let direct = $state(false);
	let offset = $state(0);
	let open = $state(/** @type {string | null} */ (null)); // expanded row key
	let rowFindings = $state(/** @type {any[]} */ ([]));

	async function load() {
		loading = true;
		try {
			const res = await api.fixPlan(projectId, { direct: direct || undefined, limit: 50, offset });
			fixes = res.fixes ?? [];
			noFix = res.no_fix;
			meta = res.pagination;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		projectId;
		offset = 0;
		load();
	});

	/** @param {any} f */
	const key = (f) => `${f.project_id}|${f.purl || f.package}|${f.installed}`;

	/** @param {any} f */
	async function toggle(f) {
		if (open === key(f)) {
			open = null;
			return;
		}
		open = key(f);
		rowFindings = [];
		try {
			rowFindings = await Promise.all(f.finding_ids.map((/** @type {string} */ id) => api.getFinding(id)));
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {number} o */
	function go(o) {
		offset = o;
		load();
	}
</script>

<div class="flex items-center gap-3 mb-3">
	<p class="text-sm text-base-content/60">
		{$t('fixplan.intro')}
	</p>
	<label class="label cursor-pointer gap-2 ml-auto">
		<input type="checkbox" class="checkbox checkbox-sm" bind:checked={direct} onchange={() => { offset = 0; load(); }} />
		<span class="label-text text-sm">{$t('fixplan.directOnly')}</span>
	</label>
</div>

<State {loading} empty={!loading && fixes.length === 0} emptyText={$t('fixplan.empty')} />

{#if !loading && fixes.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					{#if !projectId}<th>{$t('findings.colProject')}</th>{/if}
					<th>{$t('finding.package')}</th><th>{$t('fixplan.colUpgrade')}</th><th>{$t('fixplan.colCloses')}</th><th class="text-right">{$t('fixplan.colPriorityRemoved')}</th><th>{$t('fixplan.colExploit')}</th>
				</tr>
			</thead>
			<tbody>
				{#each fixes as f (key(f))}
					<tr class="hover cursor-pointer" onclick={() => toggle(f)} aria-expanded={open === key(f)}>
						{#if !projectId}<td class="text-xs"><a class="link" href={`/projects/${f.project_id}?tab=fix-plan`} onclick={(e) => e.stopPropagation()}>{f.project_name}</a></td>{/if}
						<td>
							<span class="font-medium">{f.package}</span>
							{#if f.direct === true}<span class="badge badge-outline badge-xs ml-1">{$t('finding.direct')}</span>{:else if f.direct === false}<span class="badge badge-ghost badge-xs ml-1">{$t('finding.transitive')}</span>{/if}
							{#if f.ecosystem}<span class="text-xs text-base-content/40 ml-1">{f.ecosystem}</span>{/if}
						</td>
						<td class="font-mono text-xs whitespace-nowrap">{f.installed} → <span class="text-success font-semibold">{f.upgrade_to}</span></td>
						<td class="text-xs whitespace-nowrap">
							{$t('triage.findingsCount', { count: f.closes })}
							{#each SEVS as s}{#if f.by_severity?.[s]}<span class="ml-1"><Badge kind="severity" value={s} /> {f.by_severity[s]}</span>{/if}{/each}
						</td>
						<td class="text-right font-semibold">{Math.round(f.priority_removed)}</td>
						<td class="text-xs">
							{#if f.kev}<span class="badge badge-error badge-xs">KEV {f.kev}</span>{/if}
							{#if f.max_epss}<span class="text-base-content/50 ml-1">EPSS {Math.round(f.max_epss * 100)}%</span>{/if}
						</td>
					</tr>
					{#if open === key(f)}
						<tr>
							<td colspan={projectId ? 5 : 6} class="bg-base-200/50">
								{#if rowFindings.length === 0}<span class="loading loading-spinner loading-xs"></span>{/if}
								<ul class="text-sm space-y-1">
									{#each rowFindings as rf (rf.id)}
										<li>
											<Badge kind="severity" value={rf.severity} />
											<a class="link ml-1" href={`/findings/${rf.id}`}>{rf.title}</a>
											<span class="text-xs text-base-content/50 ml-1">{rf.cve?.join(', ')} · {$t('fixplan.fixedInInline')} {rf.fixed_version}</span>
										</li>
									{/each}
								</ul>
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

{#if !loading && noFix?.findings}
	<p class="text-sm text-base-content/60 mt-3">
		{$t('fixplan.noFixIntro', { findings: noFix.findings, packages: noFix.packages })}
		{#each SEVS as s}{#if noFix.by_severity?.[s]}<span class="ml-1"><Badge kind="severity" value={s} /> {noFix.by_severity[s]}</span>{/if}{/each}
		{$t('fixplan.noFixOutro')}
	</p>
{/if}
