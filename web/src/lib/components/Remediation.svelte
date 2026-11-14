<script>
	// Remediation actions: open findings grouped by the one change that fixes
	// them (upgrade, base-image rebuild, IaC rule, file, config), each with an
	// owner, a due date and a status. With projectId it covers one project and
	// lists the proposals waiting to be accepted; without, every visible project.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { fmtDateOnly } from '#lib/format.js';
	import Badge from '#lib/components/Badge.svelte';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';

	/** @type {{ projectId?: string }} */
	let { projectId = '' } = $props();

	/** @typedef {import('#lib/i18n.js').MessageKey} MessageKey */
	const SEVS = ['critical', 'high', 'medium', 'low'];
	const STATUSES = ['open', 'in_progress', 'done', 'wont_do'];
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
	/** @type {Record<string, MessageKey>} */
	const REASON_KEY = {
		findings_resolved: 'remed.reason.findings_resolved',
		manual: 'remed.reason.manual',
		issue_closed: 'remed.reason.issue_closed'
	};

	let actions = $state(/** @type {any[]} */ ([]));
	let proposals = $state(/** @type {any[]} */ ([]));
	let meta = $state(/** @type {any} */ (null));
	let loading = $state(true);
	let statusFilter = $state('');
	let kindFilter = $state('');
	let offset = $state(0);
	let open = $state(/** @type {string | null} */ (null));
	let rowFindings = $state(/** @type {any[] | null} */ (null));
	let busy = $state(/** @type {string | null} */ (null));

	async function load() {
		loading = true;
		try {
			const res = await api.remediationActions(projectId, {
				status: statusFilter || undefined,
				kind: kindFilter || undefined,
				limit: 50,
				offset
			});
			actions = res.actions ?? [];
			meta = res.pagination;
			proposals = projectId ? await api.remediationProposals(projectId) : [];
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

	/** @param {any} a */
	async function toggle(a) {
		if (open === a.id) {
			open = null;
			return;
		}
		open = a.id;
		rowFindings = null;
		try {
			rowFindings = await api.remediationFindings(a.id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} p */
	async function accept(p) {
		busy = p.kind + p.key;
		try {
			await api.acceptRemediation(projectId, p.kind, p.key);
			notify($t('remed.actionCreated'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = null;
		}
	}

	/** @param {any} a @param {string} status */
	async function setStatus(a, status) {
		try {
			const updated = await api.updateRemediation(a.id, { status });
			actions = actions.map((x) => (x.id === a.id ? { ...updated } : x));
		} catch (err) {
			notify(errorMessage(err));
			await load();
		}
	}

	/** @param {any} a */
	async function fileIssue(a) {
		busy = a.id;
		try {
			const link = await api.fileRemediationIssue(a.id);
			actions = actions.map((x) => (x.id === a.id ? { ...x, issue: link } : x));
			notify($t('remed.ticketFiled'), 'success');
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

	/** @param {string | null} d */
	const day = (d) => (d ? fmtDateOnly(d) : '—');
</script>

<div class="flex flex-wrap items-center gap-2 mb-3">
	<p class="text-sm text-base-content/60">
		{$t('remed.intro')}
	</p>
	<select class="select select-bordered select-sm ml-auto" bind:value={statusFilter} onchange={() => { offset = 0; load(); }}>
		<option value="">{$t('remed.filterOpen')}</option>
		<option value="done,wont_do">{$t('remed.closed')}</option>
		<option value="all">{$t('common.all')}</option>
	</select>
	<select class="select select-bordered select-sm" bind:value={kindFilter} onchange={() => { offset = 0; load(); }}>
		<option value="">{$t('remed.allKinds')}</option>
		{#each Object.keys(KIND_KEY) as k}<option value={k}>{$t(KIND_KEY[k])}</option>{/each}
	</select>
</div>

<State {loading} empty={!loading && actions.length === 0 && proposals.length === 0} emptyText={$t('remed.empty')} />

{#if !loading && actions.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					{#if !projectId}<th>{$t('findings.colProject')}</th>{/if}
					<th>{$t('remed.colAction')}</th><th>{$t('proj.colOpenFindings')}</th><th>{$t('wf.assignee')}</th><th>{$t('remed.colDue')}</th><th>{$t('finding.status')}</th><th>{$t('remed.colTicket')}</th>
				</tr>
			</thead>
			<tbody>
				{#each actions as a (a.id)}
					<tr class="hover cursor-pointer" onclick={() => toggle(a)} aria-expanded={open === a.id}>
						{#if !projectId}<td class="text-xs"><a class="link" href={`/projects/${a.project_id}?tab=remediation`} onclick={(e) => e.stopPropagation()}>{a.project_name}</a></td>{/if}
						<td>
							<span class="badge badge-ghost badge-xs mr-1">{$t(KIND_KEY[a.kind] ?? KIND_KEY.config)}</span>
							<span class="font-medium">{a.title}</span>
							{#if a.target}<span class="font-mono text-xs"> → <span class="text-success font-semibold">{a.target}</span></span>{/if}
						</td>
						<td class="text-xs whitespace-nowrap">
							{a.open_findings} / {a.findings}
							{#if a.max_severity}<span class="ml-1"><Badge kind="severity" value={a.max_severity} /></span>{/if}
							{#if a.kev}<span class="badge badge-error badge-xs ml-1">KEV {a.kev}</span>{/if}
						</td>
						<td class="text-xs">{a.owner_email ?? '—'}</td>
						<td class="text-xs whitespace-nowrap" class:text-error={a.overdue}>{day(a.due_at)}</td>
						<td onclick={(e) => e.stopPropagation()}>
							<select class="select select-bordered select-xs" value={a.status} onchange={(e) => setStatus(a, e.currentTarget.value)}>
								{#each STATUSES as s}<option value={s}>{$t(STATUS_KEY[s])}</option>{/each}
							</select>
							{#if a.close_reason}<div class="text-xs text-base-content/50">{REASON_KEY[a.close_reason] ? $t(REASON_KEY[a.close_reason]) : a.close_reason.replace('_', ' ')}</div>{/if}
						</td>
						<td class="text-xs" onclick={(e) => e.stopPropagation()}>
							{#if a.issue}
								<a class="link" href={a.issue.url} target="_blank" rel="noopener noreferrer">#{a.issue.external_id}</a>
								<span class="text-base-content/50">{a.issue.state === 'open' ? $t('issue.state.open') : a.issue.state === 'closed' ? $t('issue.state.closed') : a.issue.state}</span>
							{:else}
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={() => fileIssue(a)}>{$t('remed.fileTicket')}</button>
							{/if}
						</td>
					</tr>
					{#if open === a.id}
						<tr>
							<td colspan={projectId ? 6 : 7} class="bg-base-200/50">
								{#if rowFindings === null}<span class="loading loading-spinner loading-xs"></span>{/if}
								<ul class="text-sm space-y-1">
									{#each rowFindings ?? [] as f (f.id)}
										<li>
											<Badge kind="severity" value={f.severity} />
											<Badge kind="status" value={f.status} />
											<a class="link ml-1" href={`/findings/${f.id}`}>{f.title}</a>
											<span class="text-xs text-base-content/50 ml-1">
												{f.package_name ? `${f.package_name}@${f.package_version}` : f.file_path}{f.line ? `:${f.line}` : ''}
												{f.cve?.length ? `· ${f.cve.join(', ')}` : ''}
											</span>
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

{#if !loading && projectId && proposals.length > 0}
	<h3 class="font-semibold mt-6 mb-2">{$t('remed.proposedHeading', { count: proposals.length })}</h3>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('remed.colAction')}</th><th>{$t('fixplan.colCloses')}</th><th class="text-right">{$t('fixplan.colPriorityRemoved')}</th><th></th></tr></thead>
			<tbody>
				{#each proposals as p (p.kind + p.key)}
					<tr>
						<td>
							<span class="badge badge-ghost badge-xs mr-1">{$t(KIND_KEY[p.kind] ?? KIND_KEY.config)}</span>
							{p.title}
							{#if p.target}<span class="font-mono text-xs"> → <span class="text-success">{p.target}</span></span>{/if}
						</td>
						<td class="text-xs whitespace-nowrap">
							{$t('triage.findingsCount', { count: p.closes })}
							{#each SEVS as s}{#if p.by_severity?.[s]}<span class="ml-1"><Badge kind="severity" value={s} /> {p.by_severity[s]}</span>{/if}{/each}
						</td>
						<td class="text-right">{Math.round(p.priority_removed)}</td>
						<td class="text-right">
							<button class="btn btn-primary btn-xs" disabled={busy === p.kind + p.key} onclick={() => accept(p)}>{$t('ai.accept')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
