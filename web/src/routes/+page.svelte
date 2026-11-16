<script>
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify, me } from '#lib/stores.js';
	import { criticalityClass, riskTone, slugify, fmtNumber, fmtDateOnly } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import SeverityDots from '#lib/components/SeverityDots.svelte';
	import TrendChart from '#lib/components/TrendChart.svelte';
	import ReportMenu from '#lib/components/ReportMenu.svelte';
	import IngestQueueCard from '#lib/components/IngestQueueCard.svelte';
	import { OPEN_BY_SEVERITY, RISK, fmtCount, fmtRisk, windowStats } from '#lib/trends.js';
	import { flattenTree, parentChoices } from '#lib/projectTree.js';

	let loading = $state(true);
	let error = $state('');
	let orgs = $state(/** @type {any[]} */ ([]));
	let teams = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let risk = $state(/** @type {Record<string, any>} */ ({})); // projectId -> summary
	let overview = $state(/** @type {any} */ (null)); // portfolio rollup
	let anomalies = $state(/** @type {any[]} */ ([])); // ingestion problems
	// { development, ... } from the public /auth/config — used only to show the
	// `xila-api demo-seed` hint to admins outside production.
	let authCfg = $state(/** @type {{ development?: boolean } | null} */ (null));
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const ANOMALY_LABEL = {
		stale: 'home.anomaly.stale',
		volume_drop: 'home.anomaly.volume_drop',
		failed_scan: 'home.anomaly.failed_scan',
		connector_failing: 'home.anomaly.connector_failing',
		failed_jobs: 'home.anomaly.failed_jobs'
	};
	let trend = $state(/** @type {any[]} */ ([])); // 90-day daily metric points
	const trendStats = $derived(windowStats(trend));
	let saving = $state(false);

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const CATEGORY_LABELS = {
		sast: 'home.cat.sast',
		dast: 'home.cat.dast',
		sca: 'home.cat.sca',
		secret: 'home.cat.secret',
		container: 'home.cat.container',
		iac: 'home.cat.iac',
		license: 'home.cat.license',
		cloud: 'home.cat.cloud',
		kubernetes: 'home.cat.kubernetes'
	};

	// Category counts sorted desc, with a shared max for bar scaling.
	const categoryRows = $derived.by(() => {
		const cats = overview?.open_by_category ?? {};
		const rows = Object.entries(cats)
			.filter(([, n]) => n > 0)
			.sort((a, b) => b[1] - a[1]);
		const max = rows.reduce((m, [, n]) => Math.max(m, n), 0) || 1;
		return { rows, max };
	});

	/** @param {number} s */
	const complianceTone = (s) => (s >= 90 ? 'text-success' : s >= 60 ? 'text-warning' : 'text-error');
	/** @param {number} s */
	const complianceBar = (s) =>
		s >= 90 ? 'progress-success' : s >= 60 ? 'progress-warning' : 'progress-error';

	/** @type {HTMLDialogElement} */
	let teamDialog;
	/** @type {HTMLDialogElement} */
	let projectDialog;

	let newTeam = $state({ org_id: '', slug: '', name: '' });
	const emptyProject = () => ({ team_id: '', slug: '', name: '', business_criticality: 'medium', parent_id: '', is_collection: false });
	let newProject = $state(emptyProject());
	// Projects in tree order; the tree view is the default once any project has
	// a visible parent.
	const tree = $derived(flattenTree(projects));
	const hasHierarchy = $derived(tree.some((n) => n.depth > 0));
	let view = $state(/** @type {'' | 'grid' | 'tree'} */ (''));
	const showTree = $derived(view === 'tree' || (view === '' && hasHierarchy));
	const newParentChoices = $derived(parentChoices(projects, teams, newProject.team_id, null));

	/** @type {HTMLDialogElement} */
	let orgDialog;
	let newOrg = $state({ slug: '', name: '' });

	/** @param {SubmitEvent} e */
	async function createOrg(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.createOrg({ ...newOrg, slug: newOrg.slug || slugify(newOrg.name) });
			orgDialog.close();
			newOrg = { slug: '', name: '' };
			notify($t('home.orgCreated'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @type {HTMLDialogElement} */
	let membersDialog;
	let membersTeamId = $state('');
	let members = $state(/** @type {any[]} */ ([]));
	let membersLoading = $state(false);
	let newMember = $state({ email: '', role: 'viewer' });

	async function openMembers() {
		if (teams.length === 0) {
			notify($t('home.teamFirst'), 'warning');
			return;
		}
		membersTeamId = teams[0].id;
		membersDialog.showModal();
		await loadMembers();
	}
	async function loadMembers() {
		membersLoading = true;
		members = [];
		try {
			members = await api.listMembers(membersTeamId);
		} catch (err) {
			notify(errorMessage(err)); // e.g. 403 if you don't own this team
		} finally {
			membersLoading = false;
		}
	}
	/** @param {SubmitEvent} e */
	async function addMember(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.addMember(membersTeamId, newMember.email.trim(), newMember.role);
			newMember = { email: '', role: 'viewer' };
			await loadMembers();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}
	/** @param {any} m */
	async function removeMember(m) {
		try {
			await api.removeMember(membersTeamId, m.user_id);
			await loadMembers();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// Archived projects (the ones you own) and restoring them.
	let showArchived = $state(false);
	let archived = $state(/** @type {any[]} */ ([]));
	async function toggleArchived() {
		showArchived = !showArchived;
		if (showArchived) archived = await api.listProjects(undefined, true).catch(() => []);
	}
	/** @param {any} p */
	async function restoreProject(p) {
		try {
			await api.restore('projects', p.id);
			archived = archived.filter((x) => x.id !== p.id);
			await load();
		} catch (err) {
			error = errorMessage(err);
		}
	}

	async function load() {
		loading = true;
		error = '';
		try {
			[orgs, teams, projects, overview, trend] = await Promise.all([
				api.listOrgs(),
				api.listTeams(),
				api.listProjects(),
				api.portfolio().catch(() => null),
				api.metricsTrends(90).catch(() => [])
			]);
			api.ingestionHealth().then((a) => (anomalies = a)).catch(() => {});
			api.authConfig().then((c) => (authCfg = c)).catch(() => {});
			const summaries = await Promise.all(
				projects.map((p) => api.projectSummary(p.id).catch(() => null))
			);
			/** @type {Record<string, any>} */
			const map = {};
			projects.forEach((p, i) => (map[p.id] = summaries[i]));
			risk = map;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('notif.loadFailed');
		} finally {
			loading = false;
		}
	}

	onMount(load);

	/** @param {string} id */
	const teamName = (id) => teams.find((tm) => tm.id === id)?.name ?? '—';

	function openTeam() {
		if (orgs.length === 0) {
			notify($t('home.orgFirst'), 'warning');
			return;
		}
		newTeam.org_id = orgs[0].id;
		teamDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function createTeam(e) {
		e.preventDefault();
		saving = true;
		try {
			const { org_id, ...data } = newTeam;
			await api.createTeam(org_id, { ...data, slug: data.slug || slugify(data.name) });
			teamDialog.close();
			newTeam = { org_id: '', slug: '', name: '' };
			notify($t('home.teamCreated'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	function openProject() {
		if (teams.length === 0) {
			notify($t('home.teamFirst'), 'warning');
			return;
		}
		newProject.team_id = teams[0].id;
		projectDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function createProject(e) {
		e.preventDefault();
		saving = true;
		try {
			const { team_id, parent_id, ...data } = newProject;
			await api.createProject(team_id, { ...data, parent_id: parent_id || null, slug: data.slug || slugify(data.name) });
			projectDialog.close();
			newProject = emptyProject();
			notify($t('home.projectCreated'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	// Getting-started card (shown when the instance has no projects yet): a
	// ready-to-paste upload command. Project id and token are placeholders —
	// swapped in by hand once the user has both (step 1 creates the project,
	// the Tokens page mints the token).
	const uploadSnippet = [
		'trivy fs --format json . > trivy.json',
		'curl -X POST "$XILA_URL/api/v1/projects/<project-id>/scans?scanner=trivy" \\',
		'  -H "Authorization: Bearer <api-token>" --data-binary @trivy.json'
	].join('\n');

	async function copyUploadSnippet() {
		try {
			await navigator.clipboard.writeText(uploadSnippet);
			notify($t('common.copied'), 'success');
		} catch {
			notify($t('common.copyFailed'), 'warning');
		}
	}
</script>

<div class="flex items-center justify-between mb-6">
	<div>
		<h1 class="text-2xl font-bold">{$t('home.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('home.subtitle')}</p>
	</div>
	<div class="flex gap-2">
		<ReportMenu open={(opts) => api.openPortfolioReport(opts)} />
		<button class="btn btn-ghost btn-sm" onclick={openMembers}>{$t('home.members')}</button>
		<button class="btn btn-ghost btn-sm" onclick={() => orgDialog.showModal()}>{$t('home.addOrg')}</button>
		<button class="btn btn-ghost btn-sm" onclick={openTeam}>{$t('home.addTeam')}</button>
		<button class="btn btn-primary btn-sm" onclick={openProject}>{$t('home.addProject')}</button>
	</div>
</div>

{#if !loading && !error && overview && overview.projects > 0}
	<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100 w-full mb-4">
		<div class="stat">
			<div class="stat-title">{$t('home.statProjects')}</div>
			<div class="stat-value">{fmtNumber(overview.projects)}</div>
		</div>
		<a href="/findings?status=open" class="stat hover:bg-base-200 transition-colors">
			<div class="stat-title">{$t('home.statOpen')}</div>
			<div class="stat-value">{fmtNumber(overview.total_open)}</div>
			<div class="stat-desc">{$t('home.statOpenDesc')}</div>
		</a>
		<a href="/findings?sort=priority" class="stat hover:bg-base-200 transition-colors">
			<div class="stat-title">{$t('home.statRisk')}</div>
			<div class="stat-value {riskTone(overview.risk_score)}">{fmtNumber(Math.round(overview.risk_score))}</div>
			<div class="stat-desc">{$t('home.statRiskDesc')}</div>
		</a>
		<a href="/findings?kev=true" class="stat hover:bg-base-200 transition-colors">
			<div class="stat-title">{$t('home.statExploitable')}</div>
			<div class="stat-value text-error">{fmtNumber(overview.exploitable_open)}</div>
			<div class="stat-desc">{$t('home.statKev', { count: overview.kev_open })}</div>
		</a>
		<a href="/exceptions" class="stat hover:bg-base-200 transition-colors">
			<div class="stat-title">{$t('home.statExpiring')}</div>
			<div class="stat-value {overview.expiring_soon > 0 ? 'text-warning' : ''}">{fmtNumber(overview.expiring_soon)}</div>
			<div class="stat-desc">{$t('home.statExpiringDesc')}</div>
		</a>
		{#if overview.sla}
			<a href="/findings?sla=breached&sort=sla_due" class="stat hover:bg-base-200 transition-colors">
				<div class="stat-title">{$t('home.statSla')}</div>
				<div class="stat-value {overview.sla.breached > 0 ? 'text-error' : 'text-success'}">{fmtNumber(overview.sla.breached)}</div>
				<div class="stat-desc">
					{$t('home.statDueSoon', { count: overview.sla.due_soon })}{#if overview.sla.compliance !== null} · {$t('home.statOnTime', { percent: Math.round(overview.sla.compliance * 100) })}{/if} →
				</div>
			</a>
		{/if}
	</div>

	{#if $me?.is_admin}<IngestQueueCard />{/if}

	{#if anomalies.length > 0}
		<div class="alert alert-warning mb-4 items-start" role="status">
			<div class="w-full">
				<h3 class="font-semibold">{$t('home.ingestion', { count: anomalies.length })}</h3>
				<p class="text-xs opacity-70 mb-1">{$t('home.ingestionIntro')}</p>
				<ul class="text-sm space-y-0.5">
					{#each anomalies.slice(0, 8) as a (a.kind + a.project_id + a.scanner + (a.asset_id ?? ''))}
						<li>
							<a class="link-hover font-medium" href="/projects/{a.project_id}">{a.project_name}</a>
							<span class="badge badge-sm badge-outline ml-1">{ANOMALY_LABEL[a.kind] ? $t(ANOMALY_LABEL[a.kind]) : a.kind}</span>
							<span class="opacity-80">— {a.detail}</span>
						</li>
					{/each}
				</ul>
				{#if anomalies.length > 8}<p class="text-xs opacity-70 mt-1">{$t('home.andMore', { count: anomalies.length - 8 })}</p>{/if}
			</div>
		</div>
	{/if}

	<div class="grid gap-4 lg:grid-cols-2 mb-4">
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body p-5">
				<h3 class="font-semibold mb-2">{$t('home.openBySeverity')} <span class="text-xs text-base-content/50 font-normal">{$t('home.bySeverity90')}</span></h3>
				<TrendChart points={trend} series={OPEN_BY_SEVERITY} stacked format={fmtCount} />
			</div>
		</div>
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body p-5">
				<h3 class="font-semibold mb-2">{$t('home.statRisk')} <span class="text-xs text-base-content/50 font-normal">{$t('home.days90')}</span></h3>
				<TrendChart points={trend} series={RISK} format={fmtRisk} />
				{#if trend.length}
					<p class="text-xs text-base-content/60 mt-1">
						{$t('home.windowNew', { count: trendStats.opened })} · {$t('home.windowFixed', { count: trendStats.closed })}{#if trendStats.mttr !== null} · {$t('home.windowMttr', { days: trendStats.mttr })}{/if}{#if trendStats.compliance !== null} · {$t('home.windowSla', { percent: trendStats.compliance })}{/if}
					</p>
				{/if}
			</div>
		</div>
	</div>

	<div class="grid gap-4 lg:grid-cols-2 mb-8">
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body p-5">
				<h3 class="font-semibold mb-2">{$t('home.byCategory')}</h3>
				{#if categoryRows.rows.length === 0}
					<p class="text-sm text-success">{$t('home.allClear')}</p>
				{:else}
					<div class="flex flex-col gap-2">
						{#each categoryRows.rows as [cat, n] (cat)}
							<a href={`/findings?category=${cat}&status=open`} class="flex items-center gap-3 text-sm hover:opacity-80">
								<span class="w-28 shrink-0 text-base-content/70">{CATEGORY_LABELS[cat] ? $t(CATEGORY_LABELS[cat]) : cat}</span>
								<div class="flex-1 bg-base-200 rounded h-2.5">
									<div class="bg-primary h-2.5 rounded" style="width:{Math.max(4, (n / categoryRows.max) * 100)}%"></div>
								</div>
								<span class="w-8 text-right font-semibold">{fmtNumber(n)}</span>
							</a>
						{/each}
					</div>
				{/if}
			</div>
		</div>

		<div class="card bg-base-100 shadow-sm">
			<div class="card-body p-5">
				<h3 class="font-semibold mb-2">{$t('home.compliance')} <span class="text-xs text-base-content/50 font-normal">{$t('home.complianceAvg')}</span></h3>
				{#if !overview.compliance || overview.compliance.length === 0}
					<p class="text-sm text-base-content/50">{$t('home.noFrameworks')}</p>
				{:else}
					<div class="flex flex-col gap-3">
						{#each overview.compliance as fw (fw.framework)}
							<div>
								<div class="flex justify-between text-sm mb-1">
									<span>{fw.name}</span>
									<span class="font-semibold {complianceTone(fw.avg_score)}">{fw.avg_score}%</span>
								</div>
								<progress class="progress {complianceBar(fw.avg_score)} w-full" value={fw.avg_score} max="100"></progress>
							</div>
						{/each}
					</div>
				{/if}
			</div>
		</div>
	</div>

	<h2 class="text-lg font-semibold mb-3">{$t('home.title')}</h2>
{/if}

<State {loading} {error} />

{#if !loading && !error && projects.length === 0}
	<div class="card bg-base-100 shadow-sm">
		<div class="card-body">
			<h2 class="card-title">{$t('home.onboarding.title')}</h2>
			<p class="text-sm text-base-content/60 mb-4">{$t('home.onboarding.subtitle')}</p>
			<div class="grid gap-6 md:grid-cols-3">
				<div>
					<div class="flex items-center gap-2 mb-1">
						<span class="badge badge-primary badge-sm">1</span>
						<h3 class="font-semibold">{$t('home.onboarding.step1')}</h3>
					</div>
					<p class="text-sm text-base-content/60 mb-2">{$t('home.onboarding.step1Desc')}</p>
					<button class="btn btn-primary btn-sm" onclick={openProject}>{$t('home.addProject')}</button>
				</div>
				<div>
					<div class="flex items-center gap-2 mb-1">
						<span class="badge badge-primary badge-sm">2</span>
						<h3 class="font-semibold">{$t('home.onboarding.step2')}</h3>
					</div>
					<p class="text-sm text-base-content/60 mb-2">
						{$t('home.onboarding.step2Desc')} <a class="link" href="/tokens">{$t('home.onboarding.createToken')}</a>
					</p>
					<div class="mockup-code text-xs">
						<pre data-prefix="$"><code>{uploadSnippet}</code></pre>
					</div>
					<button class="btn btn-ghost btn-xs mt-1" onclick={copyUploadSnippet}>{$t('home.onboarding.copy')}</button>
				</div>
				<div>
					<div class="flex items-center gap-2 mb-1">
						<span class="badge badge-primary badge-sm">3</span>
						<h3 class="font-semibold">{$t('home.onboarding.step3')}</h3>
					</div>
					<p class="text-sm text-base-content/60">{$t('home.onboarding.step3Desc')}</p>
				</div>
			</div>
			{#if $me?.is_admin && authCfg?.development}
				<div class="alert alert-info mt-4 text-sm">
					<span>{$t('home.onboarding.demoHint')}</span>
				</div>
			{/if}
		</div>
	</div>
{/if}

{#if !loading && !error && projects.length > 0 && hasHierarchy}
	<div class="flex justify-end mb-2">
		<div class="join">
			<button class="btn btn-xs join-item" class:btn-active={showTree} onclick={() => (view = 'tree')}>{$t('home.viewTree')}</button>
			<button class="btn btn-xs join-item" class:btn-active={!showTree} onclick={() => (view = 'grid')}>{$t('home.viewGrid')}</button>
		</div>
	</div>
{/if}

{#if !loading && !error && projects.length > 0 && showTree}
	<div class="card bg-base-100 shadow-sm overflow-x-auto">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('home.colProject')}</th><th>{$t('home.colTeam')}</th><th>{$t('home.colCriticality')}</th><th class="text-right">{$t('home.colRisk')}</th><th class="text-right">{$t('home.colOpen')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each tree as { project: p, depth } (p.id)}
					{@const s = risk[p.id]}
					<tr class="hover">
						<td>
							<a href={`/projects/${p.id}`} class="link-hover font-medium flex items-center gap-1" style:padding-left={`${depth * 1.25}rem`}>
								{#if depth > 0}<span class="text-base-content/40">└</span>{/if}
								{p.name}
								{#if p.is_collection}<span class="badge badge-ghost badge-xs" title={$t('home.collectionTitle')}>{$t('home.collection')}</span>{/if}
							</a>
						</td>
						<td class="text-xs text-base-content/60">{teamName(p.team_id)}</td>
						<td><span class="badge {criticalityClass(p.business_criticality)} badge-sm">{$labelOf('criticality', p.business_criticality)}</span></td>
						<td class="text-right font-semibold {s ? riskTone(s.risk_score) : ''}">{s ? fmtNumber(Math.round(s.risk_score)) : '—'}</td>
						<td class="text-right">{s ? fmtNumber(s.total_open) : '—'}</td>
						<td>{#if s}<SeverityDots counts={s.open_by_severity} emptyLabel="none" />{/if}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<p class="text-xs text-base-content/50 mt-2">{$t('home.collectionNote')}</p>
{:else if !loading && !error && projects.length > 0}
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
		{#each projects as p (p.id)}
			{@const s = risk[p.id]}
			<a href={`/projects/${p.id}`} class="card bg-base-100 shadow-sm hover:shadow-md transition-shadow">
				<div class="card-body p-5">
					<div class="flex items-start justify-between gap-2">
						<div class="min-w-0">
							<h2 class="card-title text-base truncate">{p.name}{#if p.is_collection}<span class="badge badge-ghost badge-xs">{$t('home.collection')}</span>{/if}</h2>
							<p class="text-xs text-base-content/50 truncate">{teamName(p.team_id)} · {p.slug}</p>
						</div>
						<span class="badge {criticalityClass(p.business_criticality)} badge-sm capitalize"
							>{$labelOf('criticality', p.business_criticality)}</span
						>
					</div>

					{#if s}
						<div class="mt-3 flex items-end justify-between gap-2">
							<div>
								<div class="text-xs text-base-content/50">{$t('home.statRisk')}</div>
								<div class="text-2xl font-bold {riskTone(s.risk_score)}">{fmtNumber(Math.round(s.risk_score))}</div>
							</div>
							<div class="text-right">
								<div class="mb-1 text-xs text-base-content/60"><span class="font-semibold text-base-content">{fmtNumber(s.total_open)}</span> {$t('home.openCount')}</div>
								<SeverityDots counts={s.open_by_severity} emptyLabel={$t('home.noOpen')} />
							</div>
						</div>
					{/if}
				</div>
			</a>
		{/each}
	</div>
{/if}

{#if !loading && !error}
	<div class="mt-6">
		<button class="btn btn-ghost btn-sm" onclick={toggleArchived}>
			{showArchived ? $t('home.archivedHide') : $t('home.archivedShow')}
		</button>
		{#if showArchived}
			{#if archived.length === 0}
				<p class="text-sm text-base-content/60 mt-2">{$t('home.archivedNone')}</p>
			{:else}
				<ul class="mt-2 space-y-1">
					{#each archived as p (p.id)}
						<li class="flex items-center gap-2 text-sm">
							<a class="link" href={`/projects/${p.id}`}>{p.name}</a>
							<span class="badge badge-sm badge-warning">{$t('home.archivedOn', { date: fmtDateOnly(p.archived_at) })}</span>
							<button class="btn btn-ghost btn-xs" onclick={() => restoreProject(p)}>{$t('common.restore')}</button>
						</li>
					{/each}
				</ul>
			{/if}
		{/if}
	</div>
{/if}

<!-- New organization modal -->
<dialog bind:this={orgDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('home.newOrg')}</h3>
		<p class="text-sm text-base-content/60 mb-3">{$t('home.newOrgIntro')}</p>
		<form onsubmit={createOrg} class="flex flex-col gap-3">
			<Field label={$t('home.name')} required>
				<input bind:value={newOrg.name} required placeholder="Acme Inc" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('home.slug')} hint={$t('home.slugHint')}>
				<input bind:value={newOrg.slug} placeholder="acme" class="input input-bordered w-full" />
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => orgDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('home.createOrg')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- New team modal -->
<dialog bind:this={teamDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('home.newTeam')}</h3>
		<form onsubmit={createTeam} class="flex flex-col gap-3">
			<Field label={$t('home.organization')} required>
				<select bind:value={newTeam.org_id} class="select select-bordered w-full">
					{#each orgs as o (o.id)}<option value={o.id}>{o.name}</option>{/each}
				</select>
			</Field>
			<Field label={$t('home.name')} required>
				<input bind:value={newTeam.name} required placeholder="Platform Team" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('home.slug')} hint={$t('home.slugHint')}>
				<input bind:value={newTeam.slug} placeholder="platform" class="input input-bordered w-full" />
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => teamDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('home.createTeam')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- Team members modal -->
<dialog bind:this={membersDialog} class="modal">
	<div class="modal-box max-w-xl">
		<h3 class="font-bold text-lg mb-3">{$t('home.teamMembers')}</h3>
		<label class="form-control mb-3">
			<span class="label-text text-xs mb-1">{$t('home.team')}</span>
			<select class="select select-bordered select-sm" bind:value={membersTeamId} onchange={loadMembers}>
				{#each teams as tm (tm.id)}<option value={tm.id}>{tm.name}</option>{/each}
			</select>
		</label>

		<form onsubmit={addMember} class="flex flex-wrap items-end gap-2 mb-3">
			<input bind:value={newMember.email} required type="email" placeholder="user@email"
				class="input input-bordered input-sm flex-1 min-w-40" />
			<select bind:value={newMember.role} class="select select-bordered select-sm">
				<option value="viewer">{$t('role.viewer')}</option>
				<option value="editor">{$t('role.editor')}</option>
				<option value="owner">{$t('role.owner')}</option>
				<option value="uploader" title={$t('proj.roleUploader')}>{$t('role.uploader')}</option>
			</select>
			<button class="btn btn-primary btn-sm" disabled={saving}>{$t('common.add')}</button>
		</form>

		{#if membersLoading}
			<p class="text-sm text-base-content/50">{$t('common.loading')}</p>
		{:else if members.length === 0}
			<p class="text-sm text-base-content/50">{$t('home.noMembers')}</p>
		{:else}
			<table class="table table-sm">
				<tbody>
					{#each members as m (m.user_id)}
						<tr>
							<td class="font-medium">{m.email}</td>
							<td>
								<span class="badge badge-ghost badge-sm">{$labelOf('role', m.role)}</span>
								{#if m.source === 'sso'}<span class="badge badge-outline badge-xs" title={$t('home.ssoGrantTitle')}>SSO</span>{/if}
							</td>
							<td class="text-right">
								<button class="btn btn-ghost btn-xs text-error" onclick={() => removeMember(m)}>{$t('common.remove')}</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
		<div class="modal-action">
			<form method="dialog"><button class="btn btn-sm">{$t('home.closeButton')}</button></form>
		</div>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- New project modal -->
<dialog bind:this={projectDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('home.newProject')}</h3>
		<form onsubmit={createProject} class="flex flex-col gap-3">
			<Field label={$t('home.team')} required>
				<select bind:value={newProject.team_id} class="select select-bordered w-full">
					{#each teams as tm}<option value={tm.id}>{tm.name}</option>{/each}
				</select>
			</Field>
			<Field label={$t('home.name')} required>
				<input bind:value={newProject.name} required placeholder="Web App" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('home.slug')} hint={$t('home.slugAutoHint')}>
				<input bind:value={newProject.slug} placeholder="web-app" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('home.criticality')} hint={$t('home.criticalityHint')}>
				<select bind:value={newProject.business_criticality} class="select select-bordered w-full capitalize">
					{#each ['low', 'medium', 'high', 'critical'] as c}<option value={c}>{$labelOf('criticality', c)}</option>{/each}
				</select>
			</Field>
			<Field label={$t('home.parent')} hint={$t('home.parentHint')}>
				<select bind:value={newProject.parent_id} class="select select-bordered w-full">
					<option value="">{$t('home.parentNone')}</option>
					{#each newParentChoices as { project: pp, depth } (pp.id)}<option value={pp.id}>{'\u00a0\u00a0'.repeat(depth)}{pp.name}</option>{/each}
				</select>
			</Field>
			<label class="label cursor-pointer justify-start gap-2">
				<input type="checkbox" bind:checked={newProject.is_collection} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('home.collectionCheckbox')}</span>
			</label>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => projectDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('home.createProject')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
