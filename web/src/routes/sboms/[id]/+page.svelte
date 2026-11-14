<script>
	import { untrack } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { fmtDate, fmtNumber, severityClass } from '$lib/format.js';
	import { t } from '$lib/i18n.js';
	import Badge from '$lib/components/Badge.svelte';
	import State from '$lib/components/State.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import VulnBadge from '$lib/components/VulnBadge.svelte';
	import ExportMenu from '$lib/components/ExportMenu.svelte';
	import LicenseBadge from '$lib/components/LicenseBadge.svelte';
	import OutdatedBadge from '$lib/components/OutdatedBadge.svelte';
	import IntegrityBadge from '$lib/components/IntegrityBadge.svelte';
	import AIBadge from '$lib/components/AIBadge.svelte';

	const id = $derived($page.params.id ?? '');
	const TABS = ['vulnerabilities', 'components', 'services', 'changes', 'graph'];

	let sbom = $state(/** @type {any} */ (null));
	let history = $state(/** @type {any[]} */ ([])); // snapshots of the same artifact, newest first
	let error = $state('');
	let tab = $state(/** @type {string} */ (TABS.includes($page.url.searchParams.get('tab') ?? '') ? $page.url.searchParams.get('tab') : 'vulnerabilities'));
	let loading = $state(false);
	let downloading = $state(false);
	let bomSpec = $state('1.6');

	async function downloadBom() {
		downloading = true;
		try {
			const name = `${sbom.artifact || 'sbom'}-${sbom.version || sbom.id}`.replace(/[\/\\"]/g, '_');
			await api.exportSbom(sbom.id, `${name}.cdx.json`, bomSpec);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			downloading = false;
		}
	}

	// per-tab data
	let vulns = $state(/** @type {any[] | null} */ (null));
	let comps = $state(/** @type {any[]} */ ([]));
	let cMeta = $state(/** @type {any} */ (null));
	let cOffset = $state(0);
	let cFilter = $state({ search: '', vulnerable: '', outdated: '', integrity: '', kind: '' });
	let freshness = $state(/** @type {any} */ (null)); // { total, outdated, up_to_date, unknown }
	let diff = $state(/** @type {any} */ (null));
	let baseId = $state('');
	let graph = $state(/** @type {any} */ (null));
	let services = $state(/** @type {any} */ (null)); // { services, summary }
	// Data flow direction is relative to the service.
	/** @type {Record<string, string[]>} */
	const FLOW = {
		inbound: ['→', 'sbomp.flowIn'],
		outbound: ['←', 'sbomp.flowOut'],
		'bi-directional': ['⇄', 'sbomp.flowBoth'],
		unknown: ['?', 'sbomp.flowUnknown']
	};
	/** @param {string} f */
	const flowArrow = (f) => (FLOW[f] ?? FLOW.unknown)[0];
	/** @param {string} f */
	const flowTitle = (f) => $t(/** @type {import('$lib/i18n.js').MessageKey} */ ((FLOW[f] ?? FLOW.unknown)[1]));
	/** @param {boolean | null | undefined} b */
	const yesNo = (b) => b === true
		? $t('sbomp.yes')
		: b === false ? $t('sbomp.no') : $t('sbomp.unstated');

	const serviceNames = $derived(new Map((services?.services ?? []).filter((/** @type {any} */ s) => s.bom_ref).map((/** @type {any} */ s) => [s.bom_ref, s.name])));
	const idx = $derived(history.findIndex((s) => s.id === id));
	const newer = $derived(idx > 0 ? history[idx - 1] : null);
	const older = $derived(idx >= 0 && idx < history.length - 1 ? history[idx + 1] : null);
	/** @param {any} s */
	const label = (s) => s.version || fmtDate(s.created_at);
	/** @param {string} c */
	const changeLabel = (c) =>
		['added', 'removed', 'upgraded', 'downgraded', 'changed'].includes(c) ? $t(/** @type {import('$lib/i18n.js').MessageKey} */ ('sbomp.change.' + c)) : c;

	async function load() {
		error = '';
		sbom = null;
		vulns = diff = graph = services = freshness = null;
		try {
			sbom = await api.getSbom(id);
			// The outdated count is a header extra: a failure mustn't block the page.
			api.sbomFreshness(id).then((f) => freshness = f, () => {});
			// Prev/next and the diff base stay on this snapshot's branch: another
			// branch's SBOM of the same artifact is a different line of history.
			history = (await api.listSboms(sbom.project_id)).filter(
				(/** @type {any} */ s) => s.artifact === sbom.artifact && s.version_id === sbom.version_id
			);
			baseId = '';
			await openTab(tab, false); // the URL already says which tab
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('sbomp.loadFailed');
		}
	}

	/** @param {string} name @param {boolean} [syncURL] */
	async function openTab(name, syncURL = true) {
		tab = name;
		if (syncURL) goto(`?tab=${name}`, { shallow: true, replace: true });
		loading = true;
		try {
			if (name === 'vulnerabilities' && !vulns) vulns = (await api.sbomVulnerabilities(id)).vulnerabilities ?? [];
			else if (name === 'components') await loadComponents();
			else if (name === 'services' && !services) services = await api.sbomServices(id);
			else if (name === 'changes' && !diff) diff = await api.sbomDiff(id, baseId || undefined);
			else if (name === 'graph' && !graph) graph = await api.sbomGraph(id);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	async function loadComponents() {
		const q = { limit: 100, offset: cOffset, search: cFilter.search, vulnerable: cFilter.vulnerable, outdated: cFilter.outdated, integrity: cFilter.integrity, kind: cFilter.kind };
		const res = await api.sbomComponents(id, q);
		comps = res.components ?? [];
		cMeta = res.pagination;
	}
	async function reloadComponents() {
		loading = true;
		try {
			await loadComponents();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	/** @param {Event} [e] */
	function filterComponents(e) {
		e?.preventDefault();
		cOffset = 0;
		reloadComponents();
	}
	function showOutdated() {
		cFilter = { search: '', vulnerable: '', outdated: 'true', integrity: '', kind: '' };
		cOffset = 0;
		openTab('components');
	}
	/** @param {number} o */
	function compPage(o) {
		cOffset = o;
		reloadComponents();
	}
	async function rebase() {
		diff = null;
		await openTab('changes');
	}

	$effect(() => {
		id; // reload when navigating between snapshots
		untrack(load);
	});

	// ---------- graph: a collapsible dependency tree ----------
	const CHILD_CAP = 300;
	const DEPTH_CAP = 40;
	let onlyVuln = $state(false);
	let find = $state('');
	let toggled = $state(/** @type {Record<string, boolean>} */ ({})); // path key -> explicit open/closed
	let selected = $state(/** @type {any} */ (null)); // node whose details / paths are shown
	let paths = $state(/** @type {any[] | null} */ (null));

	const g = $derived.by(() => {
		if (!graph) return null;
		/** @type {Map<string, any>} */
		const byRef = new Map(graph.nodes.map((/** @type {any} */ n) => [n.ref, n]));
		/** @type {Map<string, string[]>} */
		const children = new Map();
		/** @type {Map<string, string[]>} */
		const parents = new Map();
		for (const e of graph.edges) {
			if (!children.has(e.from)) children.set(e.from, []);
			children.get(e.from)?.push(e.to);
			if (!parents.has(e.to)) parents.set(e.to, []);
			parents.get(e.to)?.push(e.from);
		}
		/** @param {string} r */
		const name = (r) => byRef.get(r)?.name ?? r;
		for (const list of children.values()) list.sort((a, b) => name(a).localeCompare(name(b)));
		/** @type {string[]} */
		let entries = graph.root ? [graph.root] : graph.nodes.filter((/** @type {any} */ n) => !parents.has(n.ref) && children.has(n.ref)).map((/** @type {any} */ n) => n.ref);
		/** @type {string[]} */
		const vulnerable = graph.nodes.filter((/** @type {any} */ n) => n.vuln_count > 0).map((/** @type {any} */ n) => n.ref);
		return { byRef, children, parents, entries, vulnerable, name };
	});

	// Every ancestor of a focus node "leads to" it: computed upward, O(edges).
	/** @param {string[]} seeds */
	function ancestors(seeds) {
		const out = new Set(seeds);
		if (!g) return out;
		const queue = [...seeds];
		while (queue.length) {
			for (const p of g.parents.get(/** @type {string} */ (queue.pop())) ?? []) {
				if (!out.has(p)) {
					out.add(p);
					queue.push(p);
				}
			}
		}
		return out;
	}
	const matches = $derived.by(() => {
		if (!g || !find.trim()) return null;
		const q = find.trim().toLowerCase();
		/** @type {string[]} */
		const found = graph.nodes.filter((/** @type {any} */ n) => n.name.toLowerCase().includes(q) || n.purl.toLowerCase().includes(q)).map((/** @type {any} */ n) => n.ref);
		return found;
	});
	const focus = $derived(matches ?? (onlyVuln ? g?.vulnerable : null));
	const leads = $derived(g && focus ? ancestors(focus) : null);
	const leadsToVuln = $derived(g ? ancestors(g.vulnerable) : new Set());

	/** @param {string} ref */
	function visibleChildren(ref) {
		if (!g) return [];
		const kids = g.children.get(ref) ?? [];
		return leads ? kids.filter((k) => leads.has(k)) : kids;
	}
	/** @param {string} key @param {string} ref @param {number} depth */
	function isOpen(key, ref, depth) {
		if (key in toggled) return toggled[key];
		if (leads) return leads.has(ref) && !(focus?.includes(ref) && !visibleChildren(ref).length);
		return depth === 0;
	}
	/** @param {string} key @param {boolean} open */
	function toggle(key, open) {
		toggled = { ...toggled, [key]: !open };
	}
	function resetTree() {
		toggled = {};
	}
	/** @param {any} node */
	async function select(node) {
		selected = node;
		paths = null;
		try {
			paths = (await api.sbomPaths(id, { ref: node.ref })).paths;
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

{#if error}
	<State error={error} />
{:else if !sbom}
	<State loading={true} />
{:else}
	<a href={`/projects/${sbom.project_id}?tab=sboms`} class="text-sm text-base-content/60 hover:text-base-content">{$t('sbomp.backToProject')}</a>
	<div class="flex flex-wrap items-center justify-between gap-3 mt-2 mb-5">
		<div>
			<h1 class="text-2xl font-bold">{sbom.artifact || 'SBOM'} <span class="text-base-content/50 font-normal">{sbom.version}</span></h1>
			<p class="text-sm text-base-content/60">
				{sbom.format} {sbom.spec_version} · {$t('sbomp.components', { count: sbom.component_count })}
				{#if freshness && freshness.total > freshness.unknown}
					· <button class="link {freshness.outdated ? 'link-warning' : 'link-hover'}" onclick={showOutdated}
						title={$t('sbomp.outdatedTitle', { upToDate: freshness.up_to_date, unknown: freshness.unknown })}
						>{$t('sbomp.outdated', { count: freshness.outdated })}</button>
				{/if}
				· {$t('sbomp.uploaded', { date: fmtDate(sbom.created_at) })}
			</p>
		</div>
		<div class="flex items-center gap-2">
			<div class="join">
				<select class="select select-bordered select-sm join-item" bind:value={bomSpec} aria-label={$t('sbomp.cdxVersion')}>
					<option value="1.6">1.6</option>
					<option value="1.7">1.7</option>
				</select>
				<button class="btn btn-sm join-item" onclick={downloadBom} disabled={downloading}
					title={$t('sbomp.downloadTitle')}>
					{#if downloading}<span class="loading loading-spinner loading-xs"></span>{/if}
					{$t('sbomp.download')}
				</button>
			</div>
			<div class="join">
				<a class="btn btn-sm join-item {older ? '' : 'btn-disabled'}" href={older ? `/sboms/${older.id}?tab=${tab}` : undefined}>← {older ? label(older) : $t('sbomp.oldest')}</a>
				<span class="btn btn-sm join-item no-animation pointer-events-none" title={$t('sbomp.snapshotTitle')}>{history.length - idx} / {history.length}</span>
				<a class="btn btn-sm join-item {newer ? '' : 'btn-disabled'}" href={newer ? `/sboms/${newer.id}?tab=${tab}` : undefined}>{newer ? label(newer) : $t('sbomp.newest')} →</a>
			</div>
		</div>
	</div>

	<div role="tablist" class="tabs tabs-bordered mb-4">
		{#each TABS as tb (tb)}
			<button role="tab" class="tab" class:tab-active={tab === tb} onclick={() => openTab(tb)}>{$t(/** @type {import('$lib/i18n.js').MessageKey} */ ('sbomp.tab.' + tb))}</button>
		{/each}
	</div>

	{#if tab === 'vulnerabilities'}
		<State
			loading={loading}
			empty={!loading && vulns?.length === 0}
			emptyText={$t('sbomp.noVulns')}
		/>

		{#if !loading && vulns?.length}
			<p class="text-sm text-base-content/60 mb-2">
				{$t('sbomp.vulnsIntro')}
			</p>
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('sbomp.colVuln')}</th><th>{$t('sbomp.colSeverity')}</th><th>{$t('sbomp.colSummary')}</th><th>{$t('sbomp.colAffects')}</th><th>{$t('sbomp.colFixedIn')}</th><th>{$t('sbomp.colSource')}</th></tr></thead>
					<tbody>
						{#each vulns as v (v.key)}
							<tr class="hover">
								<td class="whitespace-nowrap">
									<a class="link link-primary" href={`/vulnerabilities/${encodeURIComponent(v.key)}`}>{v.key}</a>
									{#each v.ids.filter((/** @type {string} */ x) => x !== v.key) as other (other)}<div class="text-xs text-base-content/50">{other}</div>{/each}
								</td>
								<td><Badge kind="severity" value={v.severity} /></td>
								<td class="max-w-sm truncate" title={v.summary}>{v.summary || '—'}</td>
								<td class="text-xs">{#each v.components as c (c.id)}<div>{c.name}@{c.version}</div>{/each}</td>
								<td class="text-xs text-success">{v.fixed_version || '—'}</td>
								<td class="text-xs">
									{v.sources.join(', ')}
									{#if v.statuses.length}<div class="text-base-content/50">{v.statuses.join(', ').replaceAll('_', ' ')}</div>{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'components'}
		<form onsubmit={filterComponents} class="flex flex-wrap items-center gap-2 mb-3">
			<input bind:value={cFilter.search} placeholder={$t('sbomp.searchPlaceholder')} class="input input-bordered input-sm max-w-xs" />
			<select bind:value={cFilter.vulnerable} onchange={filterComponents} class="select select-bordered select-sm">
				<option value="">{$t('sbomp.vulnAny')}</option>
				<option value="true">{$t('sbomp.vulnOnly')}</option>
				<option value="false">{$t('sbomp.cleanOnly')}</option>
			</select>
			<select bind:value={cFilter.outdated} onchange={filterComponents} class="select select-bordered select-sm">
				<option value="">{$t('sbomp.outdatedAny')}</option>
				<option value="true">{$t('sbomp.outdatedOnly')}</option>
				<option value="false">{$t('sbomp.latestOnly')}</option>
			</select>
			<select bind:value={cFilter.integrity} onchange={filterComponents} class="select select-bordered select-sm" title={$t('sbomp.integrityTitle')}>
				<option value="">{$t('sbomp.integrityAny')}</option>
				<option value="mismatch">{$t('sbomp.integrityMismatch')}</option>
				<option value="verified">{$t('sbomp.integrityVerified')}</option>
				<option value="unknown">{$t('sbomp.integrityUnknown')}</option>
			</select>
<select bind:value={cFilter.kind} onchange={filterComponents} class="select select-bordered select-sm" title={$t('comp.kindTitle')}>
				<option value="">{$t('comp.kindAny')}</option>
				<option value="ai">{$t('comp.kindAi')}</option>
				<option value="model">{$t('comp.kindModels')}</option>
				<option value="dataset">{$t('comp.kindDatasets')}</option>
				<option value="ai-service">{$t('comp.kindAiServices')}</option>
				<option value="software">{$t('comp.kindSoftware')}</option>
			</select>
			<button class="btn btn-sm">{$t('common.filter')}</button>
			<div class="ml-auto">
				<ExportMenu run={(format) => api.exportSbomComponents(id, { search: cFilter.search, vulnerable: cFilter.vulnerable, outdated: cFilter.outdated, integrity: cFilter.integrity, kind: cFilter.kind }, format)} />
			</div>
		</form>

		<State
			loading={loading}
			empty={!loading && comps.length === 0}
			emptyText={$t('sbomp.noComponents')}
		/>

		{#if !loading && comps.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('sbomp.colComponent')}</th><th>{$t('sbomp.colVersion')}</th><th>{$t('sbomp.colLatest')}</th><th>{$t('sbomp.colVulns')}</th><th>{$t('sbomp.colDependency')}</th><th>{$t('sbomp.colLicense')}</th><th>PURL</th></tr></thead>
					<tbody>
						{#each comps as c (c.id)}
							<tr class="hover">
								<td>{c.name} <AIBadge c={c} /></td>
								<td class="text-xs">{c.version || '—'}</td>

								<td>
									<OutdatedBadge c={c} />
									<IntegrityBadge integrity={c.integrity} />
								</td>

								<td>
									<VulnBadge
										count={c.vuln_count}
										severity={c.max_severity}
										kev={c.kev}
										vulns={c.vulns}
									/>
								</td>

								<td class="text-xs">
									{#if c.direct === true}{$t('sbomp.direct')}{:else if c.direct === false}{$t('sbomp.transitive')}{#if c.depth} · {$t('sbomp.depth', { depth: c.depth })}{/if}{:else}—{/if}
									{#if c.scope === 'dev'}<span class="badge badge-ghost badge-xs ml-1">dev</span>{/if}
								</td>

								<td><LicenseBadge c={c} /></td>

								<td
									class="text-xs font-mono text-base-content/60 max-w-xs truncate"
									title={c.purl}
								>{c.purl || '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if cMeta}<Pagination limit={cMeta.limit} offset={cMeta.offset} count={cMeta.count} hasMore={cMeta.has_more} onchange={compPage} />{/if}
		{/if}
	{:else if tab === 'services'}
		<State
			loading={loading}
			empty={!loading && services?.services.length === 0}
			emptyText={$t('sbomp.noServices')}
		/>

		{#if !loading && services?.services.length}
			{@const sum = services.summary}
			<div class="flex flex-wrap items-center gap-2 mb-3 text-sm">
				<span class="text-base-content/60">{$t('sbomp.serviceCount', { count: sum.total })}</span>
				{#if sum.unauthenticated_external}<span class="badge badge-error badge-sm">{$t('sbomp.unauthExternalCount', { count: sum.unauthenticated_external })}</span>{/if}
				{#if sum.crosses_trust_boundary}<span class="badge badge-warning badge-sm">{$t('sbomp.crossingCount', { count: sum.crosses_trust_boundary })}</span>{/if}
				<span class="ml-auto text-xs text-base-content/50">{$t('sbomp.flowLegend')}</span>
			</div>
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('sbomp.colService')}</th><th>{$t('sbomp.colVersion')}</th><th>{$t('sbomp.colEndpoints')}</th><th>{$t('sbomp.colAuth')}</th><th>{$t('sbomp.colTrust')}</th><th>{$t('sbomp.colData')}</th><th>{$t('sbomp.colWarnings')}</th></tr></thead>
					<tbody>
						{#each services.services as s (s.id)}
							<tr class="hover align-top">
								<td>
									<div class="font-medium">{s.name}</div>
									{#if s.group || s.provider}<div class="text-xs text-base-content/50">{[s.group, s.provider].filter(Boolean).join(' · ')}</div>{/if}
									{#if s.parent_ref}<div class="text-xs text-base-content/50">{$t('sbomp.inParent', { name: serviceNames.get(s.parent_ref) ?? s.parent_ref })}</div>{/if}
								</td>
								<td class="text-xs">{s.version || '—'}</td>
								<td class="text-xs font-mono max-w-xs">
									{#each s.endpoints as e (e)}<div class="truncate" title={e}>{e}</div>{:else}—{/each}
								</td>
								<td>
									{#if s.authenticated === true}<span class="badge badge-success badge-outline badge-xs">{$t('sbomp.authenticated')}</span>
									{:else if s.authenticated === false}<span class="badge badge-error badge-outline badge-xs">{$t('sbomp.unauthenticated')}</span>
									{:else}<span class="text-xs text-base-content/40">{$t('sbomp.unstated')}</span>{/if}
								</td>
								<td class="text-xs">
									{#if s.trust_boundary === true}<span class="badge badge-warning badge-outline badge-xs mr-1">{$t('sbomp.trustBoundary')}</span>{/if}
									{#if s.trust_zone}<span class="badge badge-ghost badge-xs" title={$t('sbomp.trustZone')}>{s.trust_zone}</span>{/if}
									{#if s.trust_boundary !== true && !s.trust_zone}—{/if}
								</td>
								<td class="text-xs">
									{#each s.data as d, i (i)}
										<span
											class="badge badge-xs mr-1 mb-1 {d.crosses_trust_zone ? 'badge-warning' : 'badge-ghost'}"
											title={[flowTitle(d.flow), d.name, d.description, d.crosses_trust_zone ? $t('sbomp.crossesZone') : ''].filter(Boolean).join(' — ')}
										>{flowArrow(d.flow)} {d.classification || '?'}</span>
									{:else}—{/each}
								</td>
								<td>
									{#if s.unauthenticated_external}<span class="badge badge-error badge-xs mr-1" title={$t('sbomp.unauthExternalTitle')}>{$t('sbomp.unauthExternal')}</span>{/if}
									{#if s.crosses_trust_boundary}<span class="badge badge-warning badge-xs" title={$t('sbomp.crossesTitle')}>{$t('sbomp.crossesBoundary')}</span>{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'changes'}
		<div class="flex flex-wrap items-center gap-2 mb-3 text-sm">
			<span class="text-base-content/60">{$t('sbomp.comparedWith')}</span>
			<select bind:value={baseId} onchange={rebase} class="select select-bordered select-sm">
				<option value="">{$t('sbomp.previousSnapshot')}</option>
				{#each history.filter((s) => s.id !== id) as s (s.id)}
					<option value={s.id}>{label(s)} · {fmtDate(s.created_at)}</option>
				{/each}
			</select>
		</div>
		<State loading={loading} />
		{#if !loading && diff}
			{@const s = diff.summary}
			{#if !diff.base}
				<p class="text-sm text-base-content/60 mb-3">{$t('sbomp.firstSnapshot', { artifact: sbom.artifact })}</p>
			{/if}
			<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100 w-full mb-4">
				<div class="stat">
					<div class="stat-title">{$t('sbomp.packages')}</div>
					<div class="stat-desc pt-1 flex flex-wrap gap-2 text-sm">
						<span class="text-success">{$t('sbomp.added', { count: s.added })}</span><span class="text-error">{$t('sbomp.removed', { count: s.removed })}</span>
						<span>{$t('sbomp.upgraded', { count: s.upgraded })}</span><span class="text-warning">{$t('sbomp.downgraded', { count: s.downgraded })}</span>
						{#if s.changed}<span>{$t('sbomp.changed', { count: s.changed })}</span>{/if}<span class="text-base-content/50">{$t('sbomp.unchanged', { count: diff.unchanged })}</span>
					</div>
				</div>
				<div class="stat">
					<div class="stat-title">{$t('sbomp.vulnsFixed')}</div>
					<div class="stat-value text-success text-2xl">{s.vulns_fixed.length}</div>
					<div class="stat-desc truncate max-w-xs" title={s.vulns_fixed.join(', ')}>{s.vulns_fixed.join(', ') || '—'}</div>
				</div>
				<div class="stat">
					<div class="stat-title">{$t('sbomp.vulnsIntroduced')}</div>
					<div class="stat-value text-2xl {s.vulns_introduced.length ? 'text-error' : ''}">{s.vulns_introduced.length}</div>
					<div class="stat-desc truncate max-w-xs" title={s.vulns_introduced.join(', ')}>{s.vulns_introduced.join(', ') || '—'}</div>
				</div>
				{#if s.services_added + s.services_removed + s.services_changed > 0}
					<div class="stat">
						<div class="stat-title">{$t('sbomp.services')}</div>
						<div class="stat-desc pt-1 flex flex-wrap gap-2 text-sm">
							<span class="text-success">{$t('sbomp.added', { count: s.services_added })}</span><span class="text-error">{$t('sbomp.removed', { count: s.services_removed })}</span>
							<span>{$t('sbomp.changed', { count: s.services_changed })}</span>
						</div>
					</div>
				{/if}
			</div>
			{#if diff.changes.length}
				<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
					<table class="table table-sm">
						<thead><tr><th>{$t('sbomp.colChange')}</th><th>{$t('sbomp.colPackage')}</th><th>{$t('sbomp.colFrom')}</th><th>{$t('sbomp.colTo')}</th><th>{$t('sbomp.colVulns')}</th></tr></thead>
						<tbody>
							{#each diff.changes as c (c.key)}
								<tr class="hover">
									<td>
										<span class="badge badge-sm {c.change === 'added' ? 'badge-success' : c.change === 'removed' ? 'badge-error' : c.change === 'downgraded' ? 'badge-warning' : 'badge-ghost'}">{changeLabel(c.change)}</span>
									</td>
									<td>{c.group ? `${c.group}/` : ''}{c.name}{#if c.scope === 'dev'}<span class="badge badge-ghost badge-xs ml-1">dev</span>{/if}</td>
									<td class="text-xs">{c.from.join(', ') || '—'}</td>
									<td class="text-xs">{c.to.join(', ') || '—'}</td>
									<td class="text-xs">
										{#each c.fixed_vulns.slice(0, 6) as v (v)}<span class="badge badge-success badge-outline badge-xs mr-1" title={$t('sbomp.fixedTitle')}>✓ {v}</span>{/each}
										{#if c.fixed_vulns.length > 6}<span class="text-success mr-2" title={c.fixed_vulns.slice(6).join(', ')}>{$t('sbomp.moreFixed', { count: c.fixed_vulns.length - 6 })}</span>{/if}
										{#each c.introduced_vulns.slice(0, 6) as v (v)}<span class="badge badge-error badge-xs mr-1" title={$t('sbomp.introducedTitle')}>+ {v}</span>{/each}
										{#if c.introduced_vulns.length > 6}<span class="text-error" title={c.introduced_vulns.slice(6).join(', ')}>{$t('sbomp.moreIntroduced', { count: c.introduced_vulns.length - 6 })}</span>{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<p class="text-sm text-base-content/60">{$t('sbomp.noPackageChanges')}</p>
			{/if}
			{#if diff.services?.length}
				<h3 class="font-semibold mt-6 mb-2">{$t('sbomp.services')}</h3>
				<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
					<table class="table table-sm">
						<thead><tr><th>{$t('sbomp.colChange')}</th><th>{$t('sbomp.colService')}</th><th>{$t('sbomp.colWhatChanged')}</th></tr></thead>
						<tbody>
							{#each diff.services as c (c.key)}
								<tr class="hover align-top">
									<td><span class="badge badge-sm {c.change === 'added' ? 'badge-success' : c.change === 'removed' ? 'badge-error' : 'badge-ghost'}">{changeLabel(c.change)}</span></td>
									<td>{c.group ? `${c.group}/` : ''}{c.name}</td>
									<td class="text-xs space-y-0.5">
										{#if c.change === 'changed' && c.fields.includes('version')}<div>{$t('sbomp.versionChange', { from: c.version_from || '—', to: c.version_to || '—' })}</div>{/if}
										{#if c.change !== 'changed' && (c.version_to || c.version_from)}<div>{$t('sbomp.version', { v: c.version_to || c.version_from })}</div>{/if}
										{#each c.endpoints_added as e (e)}<div class="text-success font-mono">+ {e}</div>{/each}
										{#each c.endpoints_removed as e (e)}<div class="text-error font-mono">− {e}</div>{/each}
										{#if c.fields.includes('authenticated')}
											<div class={c.authenticated_to === false ? 'text-error' : ''}>{$t('sbomp.authChange', { from: yesNo(c.authenticated_from), to: yesNo(c.authenticated_to) })}</div>
										{/if}
										{#if c.fields.includes('trust_boundary')}<div>{$t('sbomp.boundaryChange', { from: yesNo(c.trust_boundary_from), to: yesNo(c.trust_boundary_to) })}</div>{/if}
										{#if c.fields.includes('trust_zone')}<div>{$t('sbomp.zoneChange', { from: c.trust_zone_from || '—', to: c.trust_zone_to || '—' })}</div>{/if}
										{#if c.data_added.length || c.data_removed.length}
											<div>
												{#each c.data_added as d, i (i)}<span class="badge badge-success badge-outline badge-xs mr-1" title={flowTitle(d.flow)}>+ {flowArrow(d.flow)} {d.classification}</span>{/each}
												{#each c.data_removed as d, i (i)}<span class="badge badge-error badge-outline badge-xs mr-1" title={flowTitle(d.flow)}>− {flowArrow(d.flow)} {d.classification}</span>{/each}
											</div>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		{/if}
	{:else if tab === 'graph'}
		<State loading={loading} />
		{#if !loading && g}
			{#if graph.edges.length === 0}
				<p class="text-sm text-base-content/60">{$t('sbomp.noGraph')}</p>
			{:else}
				<div class="flex flex-wrap items-center gap-3 mb-3 text-sm">
					<input bind:value={find} placeholder={$t('sbomp.findPackage')} class="input input-bordered input-sm w-56" oninput={resetTree} />
					<label class="label cursor-pointer gap-2">
						<input type="checkbox" bind:checked={onlyVuln} onchange={resetTree} class="checkbox checkbox-sm" />
						<span class="label-text">{$t('sbomp.onlyVulnPaths')}</span>
					</label>
					<span class="text-base-content/50">
						{$t('sbomp.graphStats', { nodes: graph.nodes.length, edges: graph.edges.length, vulnerable: g.vulnerable.length })}
						{#if matches} · {$t('sbomp.matchCount', { count: matches.length })}{/if}
					</span>
				</div>
				<div class="grid gap-4 lg:grid-cols-3">
					<div class="lg:col-span-2 bg-base-100 rounded-box shadow-sm p-3 font-mono text-sm overflow-x-auto">
						{#each g.entries as ref (ref)}
							{@render tree(ref, ref, 0)}
						{/each}
					</div>
					<div class="bg-base-100 rounded-box shadow-sm p-4 text-sm self-start">
						{#if selected}
							<div class="font-semibold">{selected.name} <span class="text-base-content/50 font-normal">{selected.version}</span></div>
							{#if selected.purl}<div class="text-xs font-mono text-base-content/50 break-all">{selected.purl}</div>{/if}
							<div class="mt-2"><VulnBadge count={selected.vuln_count} severity={selected.max_severity} kev={selected.kev} vulns={selected.vulns} /></div>
							{#each selected.vulns as v (v)}
								<a class="link link-primary text-xs mr-2" href={`/vulnerabilities/${encodeURIComponent(v)}`}>{v}</a>
							{/each}
							<div class="mt-3 text-xs text-base-content/50">{$t('sbomp.whyHere')}</div>
							{#if paths === null}
								<span class="loading loading-spinner loading-xs"></span>
							{:else if paths.length === 0}
								<div class="text-xs text-base-content/50">{$t('sbomp.notReachable')}</div>
							{:else}
								{#each paths as p, i (i)}
									<div class="text-xs mt-1">{p.map((/** @type {any} */ n) => n.name).join(' → ')}</div>
								{/each}
							{/if}
						{:else}
							<p class="text-base-content/50">{$t('sbomp.selectPrompt')}</p>
						{/if}
					</div>
				</div>
			{/if}
		{/if}
	{/if}
{/if}

{#snippet tree(/** @type {string} */ (ref), /** @type {string} */ (key), /** @type {number} */ (depth))}
	{@const node = g?.byRef.get(ref)}
	{@const kids = visibleChildren(ref)}
	{@const open = isOpen(key, ref, depth)}
	{@const cycle = key.split('\u0000').slice(0, -1).includes(ref)}
	<div style="padding-left: {depth * 1.1}rem" class="flex items-center gap-1 py-0.5 whitespace-nowrap {matches?.includes(ref) ? 'bg-warning/20 rounded' : ''}">
		{#if kids.length && !cycle && depth < DEPTH_CAP}
			<button class="w-4 text-base-content/50" onclick={() => toggle(key, open)} aria-label={open ? $t('sbomp.collapse') : $t('sbomp.expand')}>{open ? '▾' : '▸'}</button>
		{:else}
			<span class="w-4"></span>
		{/if}
		<button class="hover:underline {node?.root ? 'font-semibold' : ''} {node?.missing ? 'text-base-content/40' : ''}" onclick={() => node && select(node)}>
			{node?.name ?? ref}{#if node?.version}<span class="text-base-content/50">@{node.version}</span>{/if}
		</button>
		{#if node?.vuln_count}<span class="badge badge-xs {severityClass(node.max_severity)}">{node.vuln_count}</span>{/if}
		{#if !node?.vuln_count && leadsToVuln.has(ref) && !node?.root}<span class="text-error text-xs" title={$t('sbomp.leadsToVuln')}>●</span>{/if}
		{#if node?.scope === 'dev'}<span class="badge badge-ghost badge-xs">dev</span>{/if}
		{#if node?.kind === 'service'}<span class="badge badge-info badge-outline badge-xs">{$t('sbomp.service')}</span>{/if}
		{#if cycle}<span class="text-xs text-base-content/40">{$t('sbomp.cycle')}</span>{/if}
		{#if kids.length && !open && !cycle}<span class="text-xs text-base-content/40">{kids.length}</span>{/if}
	</div>
	{#if open && !cycle && depth < DEPTH_CAP}
		{#each kids.slice(0, CHILD_CAP) as child (child)}
			{@render tree(child, key + '\u0000' + child, depth + 1)}
		{/each}
		{#if kids.length > CHILD_CAP}
			<div style="padding-left: {(depth + 1) * 1.1}rem" class="text-xs text-base-content/40">{$t('sbomp.moreChildren', { count: kids.length - CHILD_CAP })}</div>
		{/if}
	{/if}
{/snippet}
