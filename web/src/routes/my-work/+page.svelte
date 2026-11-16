<script>
	// "My work": everything waiting on the signed-in user in one queue —
	// findings assigned to them, requests they may decide, acceptances they
	// own that are about to expire and AI proposals on their findings. Each
	// list is the server's own filtered queue (never trimmed client-side), so
	// what shows here is exactly what the linked pages would show.
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate, prettyStatus } from '#lib/format.js';
	import Badge from '#lib/components/Badge.svelte';
	import State from '#lib/components/State.svelte';

	const LIMIT = 25;
	const EXPIRY_DAYS = 30;

	let loading = $state(true);
	let error = $state('');
	let assigned = $state(/** @type {any[]} */ ([]));
	let assignedMore = $state(false);
	let assessments = $state(/** @type {any[]} */ ([]));
	let assessmentsMore = $state(false);
	let requests = $state(/** @type {any[]} */ ([]));
	let requestsMore = $state(false);
	let expiring = $state(/** @type {any[]} */ ([]));
	let expiringMore = $state(false);
	let proposals = $state(/** @type {any[]} */ ([]));
	let proposalsMore = $state(false);
	// AI triage answers 404 while it is off: then the section is hidden.
	let aiOn = $state(true);
	let projects = $state(/** @type {any[]} */ ([]));
	/** @param {string} id */
	const projectName = (id) => projects.find((pr) => pr.id === id)?.name ?? '';

	const total = $derived(assigned.length + assessments.length + requests.length + expiring.length + proposals.length);

	onMount(async () => {
		try {
			const page = { limit: LIMIT };
			const [f, a, r, e, ps] = await Promise.all([
				api.searchFindings({ ...page, assignee: 'me', active: true, sort: 'priority' }),
				api.listAssessments({ ...page, actionable: true }),
				api.listRiskAcceptances({ ...page, actionable: true }),
				api.listRiskAcceptances({ ...page, state: 'approved', owner: 'me', expires_within_days: EXPIRY_DAYS }),
				api.listProjects().catch(() => [])
			]);
			projects = ps;
			assigned = f.findings ?? [];
			assignedMore = !!f.pagination?.has_more;
			assessments = a.assessments ?? [];
			assessmentsMore = !!a.pagination?.has_more;
			requests = r.risk_acceptances ?? [];
			requestsMore = !!r.pagination?.has_more;
			expiring = e.risk_acceptances ?? [];
			expiringMore = !!e.pagination?.has_more;
			try {
				const p = await api.listAIProposals({ ...page, mine: true });
				proposals = p.proposals ?? [];
				proposalsMore = !!p.pagination?.has_more;
			} catch (err) {
				if (err instanceof ApiError && err.status === 404) aiOn = false;
				else throw err;
			}
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	});

	/** @param {string | null | undefined} iso */
	function daysLeft(iso) {
		if (!iso) return null;
		return Math.max(0, Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000));
	}
</script>

<div class="mb-5">
	<h1 class="text-2xl font-bold">{$t('mywork.title')}</h1>
	<p class="text-sm text-base-content/60">{$t('mywork.subtitle')}</p>
</div>

<State {loading} {error} empty={!loading && !error && total === 0} emptyText={$t('mywork.empty')} />

{#if !loading && !error && total > 0}
	<div class="grid gap-6">
		{#if assigned.length}
			<section>
				<div class="flex items-baseline justify-between mb-2">
					<h2 class="font-semibold">{$t('mywork.assigned')} <span class="badge badge-ghost badge-sm">{assigned.length}{assignedMore ? '+' : ''}</span></h2>
					<a class="link text-sm" href="/findings?assignee=me">{$t('mywork.seeAll')}</a>
				</div>
				<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
					<table class="table table-sm">
						<thead><tr><th>{$t('mywork.colFinding')}</th><th>{$t('mywork.colProject')}</th><th>{$t('mywork.colStatus')}</th><th>{$t('mywork.colSLA')}</th></tr></thead>
						<tbody>
							{#each assigned as f (f.id)}
								<tr class="hover">
									<td>
										<Badge kind="severity" value={f.severity} />
										<a class="link link-hover ml-1" href={`/findings/${f.id}`}>{f.title}</a>
										{#if f.kev}<span class="badge badge-error badge-xs ml-1">KEV</span>{/if}
									</td>
									<td class="text-sm">{projectName(f.project_id)}</td>
									<td class="text-sm">{prettyStatus(f.status)}</td>
									<td class="text-sm whitespace-nowrap">{f.sla_due_at ? fmtDate(f.sla_due_at) : '—'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		{#if assessments.length || requests.length}
			<section>
				<div class="flex items-baseline justify-between mb-2">
					<h2 class="font-semibold">{$t('mywork.decide')} <span class="badge badge-ghost badge-sm">{assessments.length + requests.length}{assessmentsMore || requestsMore ? '+' : ''}</span></h2>
					<a class="link text-sm" href="/approvals">{$t('mywork.openApprovals')}</a>
				</div>
				<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
					{#each assessments as a (a.id)}
						<li class="p-3 text-sm flex flex-wrap gap-2 items-center">
							<span class="badge badge-outline badge-sm">{$t('mywork.kindAssessment')}</span>
							<a class="link link-hover" href={`/findings/${a.finding_id}`}>{a.finding_title ?? a.finding_id}</a>
							{#if a.status}<span class="text-base-content/60">→ {prettyStatus(a.status)}</span>{/if}
							{#if a.severity}<span class="text-base-content/60">→ <Badge kind="severity" value={a.severity} /></span>{/if}
							<span class="text-base-content/50 ml-auto">{a.requester || '—'} · {fmtDate(a.created_at)}</span>
						</li>
					{/each}
					{#each requests as r (r.id)}
						<li class="p-3 text-sm flex flex-wrap gap-2 items-center">
							<span class="badge badge-outline badge-sm">{$t('mywork.kindAcceptance')}</span>
							<span class="font-medium">{r.title}</span>
							<span class="text-base-content/60">{r.project_name}</span>
							<span class="text-base-content/50 ml-auto">{r.requester || '—'} · {fmtDate(r.requested_at)}</span>
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if expiring.length}
			<section>
				<div class="flex items-baseline justify-between mb-2">
					<h2 class="font-semibold">{$t('mywork.expiring', { days: EXPIRY_DAYS })} <span class="badge badge-ghost badge-sm">{expiring.length}{expiringMore ? '+' : ''}</span></h2>
					<a class="link text-sm" href="/approvals">{$t('mywork.openApprovals')}</a>
				</div>
				<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
					{#each expiring as r (r.id)}
						<li class="p-3 text-sm flex flex-wrap gap-2 items-center">
							<span class="font-medium">{r.title}</span>
							<span class="text-base-content/60">{r.project_name}</span>
							<span class="ml-auto {(daysLeft(r.expires_at) ?? 99) <= 7 ? 'text-error' : 'text-warning'}">
								{$t('mywork.expiresIn', { days: daysLeft(r.expires_at) ?? 0 })} · {fmtDate(r.expires_at)}
							</span>
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if aiOn && proposals.length}
			<section>
				<h2 class="font-semibold mb-2">{$t('mywork.proposals')} <span class="badge badge-ghost badge-sm">{proposals.length}{proposalsMore ? '+' : ''}</span></h2>
				<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
					{#each proposals as p (p.id)}
						<li class="p-3 text-sm flex flex-wrap gap-2 items-center">
							<span class="badge badge-outline badge-sm">{p.kind}</span>
							<Badge kind="severity" value={p.finding_severity} />
							<a class="link link-hover" href={`/findings/${p.finding_id}`}>{p.finding_title}</a>
							<span class="text-base-content/60">{p.project_name}</span>
							{#if p.verdict}<span class="text-base-content/60">· {p.verdict}</span>{/if}
							<span class="text-base-content/50 ml-auto">{fmtDate(p.created_at)}</span>
						</li>
					{/each}
				</ul>
			</section>
		{/if}
	</div>
{/if}
