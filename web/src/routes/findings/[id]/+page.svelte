<script>
	import { page } from '$app/state';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify, features, isOn } from '#lib/stores.js';
	import { fmtDate, fmtDateOnly, fmtDay, fmtNumber, STATUSES, severityAccent, kevCatalogs } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import Badge from '#lib/components/Badge.svelte';
	import SlaBadge from '#lib/components/SlaBadge.svelte';
	import State from '#lib/components/State.svelte';
	import FindingIssue from '#lib/components/FindingIssue.svelte';
	import FindingWorkflow from '#lib/components/FindingWorkflow.svelte';
	import FindingWriteup from '#lib/components/FindingWriteup.svelte';
	import ExploitBadge from '#lib/components/ExploitBadge.svelte';
	import FindingExploits from '#lib/components/FindingExploits.svelte';
	import FindingFieldsEditor from '#lib/components/FindingFieldsEditor.svelte';
	import FindingAI from '#lib/components/FindingAI.svelte';
	import CustomFieldsEditor from '#lib/components/CustomFieldsEditor.svelte';
	import { advisoryLinks, depsDevURL } from '#lib/links.js';

	const id = $derived(page.params.id ?? '');

	let finding = $state(/** @type {any} */ (null));
	/** Archive instead of delete: the finding leaves every view until restored. */
	let markingDuplicate = $state(false);
	let duplicatePrimaryId = $state('');
	let duplicateBusy = $state(false);

	function markDuplicateOpen() {
		duplicatePrimaryId = '';
		markingDuplicate = true;
	}

	/** @param {SubmitEvent} e */
	async function markDuplicateSubmit(e) {
		e.preventDefault();
		if (!duplicatePrimaryId.trim()) return;
		duplicateBusy = true;
		try {
			finding = await api.markDuplicate(id, duplicatePrimaryId.trim());
			markingDuplicate = false;
			notify($t('finding.markedDuplicate'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			duplicateBusy = false;
		}
	}

	async function unmarkDuplicate() {
		duplicateBusy = true;
		try {
			finding = await api.unmarkDuplicate(id);
			notify($t('finding.unmarkedDuplicate'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			duplicateBusy = false;
		}
	}

	async function setArchived(/** @type {boolean} */ archived) {
		if (archived && !confirm($t('finding.archiveConfirm'))) return;
		try {
			if (archived) await api.archive('findings', id);
			else await api.restore('findings', id);
			finding = await api.getFinding(id);
			notify(archived ? $t('finding.archived') : $t('finding.restored'), 'success');
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('finding.archiveForbidden') : errorMessage(err));
		}
	}
	let components = $state(/** @type {any[]} */ ([]));
	let via = $state(/** @type {{ component: any, paths: any[] } | null} */ (null)); // { component, paths } — why the newest matching component is in the tree
	let branch = $state(/** @type {any} */ (null)); // the project version (branch / release) this finding lives on
	let exceptions = $state(/** @type {any[]} */ ([]));
	let duplicates = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);
	// The finding's pending manual assessment (ASSESSMENT_REQUIRES_APPROVAL), if any.
	let pendingAssessment = $state(/** @type {any} */ (null));
	let deciding = $state(false);
	let revision = $state(0); // bumps the activity feed for events that don't touch the finding

	// Statuses that are "exceptions" — accepting them prompts for a justification
	// and optional expiry (after which the sweep reopens the finding).
	const EXCEPTION_STATES = ['risk_accepted', 'false_positive', 'wont_fix'];

	let statusSelect = $state('');
	let pendingStatus = $state('');
	let exForm = $state({ reason: '', expires: '' });
	/** @type {HTMLDialogElement} */
	let exDialog;

	$effect(() => {
		if (finding) statusSelect = finding.status;
	});

	// The id we last kicked off a load for. Clicking through to another finding
	// while one is in flight would otherwise let the slower response land last and
	// overwrite the page with the finding you navigated away from.
	let loadingID = '';

	/** @param {string} findingID */
	async function load(findingID) {
		loadingID = findingID;
		loading = true;
		error = '';
		try {
			const [res, ex, dups, as] = await Promise.all([
				api.findingComponents(findingID),
				api.findingExceptions(findingID),
				api.findingDuplicates(findingID).catch(() => []),
				api.findingAssessments(findingID).catch(() => [])
			]);
			if (loadingID !== findingID) return; // superseded by a newer navigation
			finding = res.finding;
			branch = null;
			api.listVersions(finding.project_id)
				.then((vs) => {
					if (loadingID === findingID) branch = vs.find((/** @type {any} */ v) => v.id === finding.version_id) ?? null;
				})
				.catch(() => {});
			components = res.components ?? [];
			via = null;
			loadPaths(findingID, components[0]);
			exceptions = ex;
			duplicates = dups;
			pendingAssessment = as.find((/** @type {any} */ a) => a.state === 'pending') ?? null;
		} catch (err) {
			if (loadingID !== findingID) return;
			error = err instanceof ApiError ? err.message : $t('finding.loadFailed');
		} finally {
			if (loadingID === findingID) loading = false;
		}
	}

	// The matches come newest snapshot first; explain how that one pulls the
	// package in. Best-effort: SBOMs without a dependency graph just show nothing.
	/** @param {string} findingID @param {any} c */
	async function loadPaths(findingID, c) {
		if (!c?.bom_ref) return;
		try {
			const res = await api.sbomPaths(c.sbom_id, { component_id: c.id });
			if (loadingID === findingID && res.paths?.length) via = { component: c, paths: res.paths };
		} catch {
			// no graph for this snapshot
		}
	}

	function onStatusChange() {
		const s = statusSelect;
		if (EXCEPTION_STATES.includes(s)) {
			pendingStatus = s;
			exForm = { reason: '', expires: '' };
			exDialog.showModal();
		} else {
			applyStatus(s, {});
		}
	}

	/** @param {string} status @param {{ reason?: string, expires_at?: string }} opts */
	async function applyStatus(status, opts) {
		saving = true;
		try {
			const res = await api.setFindingStatus(id, status, opts);
			if (res?.state === 'requested') {
				// "Accept risk" requests a risk acceptance; the finding is unchanged.
				statusSelect = finding.status;
				finding = await api.getFinding(id);
				revision++;
				notify($t('findings.raRequested'), 'success');
			} else if (res?.state === 'pending') {
				// Held for four-eyes approval: the finding is unchanged.
				pendingAssessment = res;
				statusSelect = finding.status;
				revision++;
				notify($t('findings.forApproval'), 'success');
			} else {
				finding = res;
				exceptions = await api.findingExceptions(id);
				notify($t('finding.statusUpdated'), 'success');
			}
		} catch (err) {
			notify(errorMessage(err));
			statusSelect = finding.status; // revert the dropdown
		} finally {
			saving = false;
		}
	}

	/** @param {boolean} approve */
	async function decide(approve) {
		const a = pendingAssessment;
		const note = prompt(approve ? $t('finding.approvalNote') : $t('finding.rejectWhy'));
		if (note === null) return;
		deciding = true;
		try {
			if (approve) {
				const out = await api.approveAssessment(a.id, note);
				finding = out.finding;
				exceptions = await api.findingExceptions(id);
				notify($t('finding.approved'), 'success');
			} else {
				await api.rejectAssessment(a.id, note);
				notify($t('finding.rejected'), 'success');
			}
			pendingAssessment = null;
			revision++;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			deciding = false;
		}
	}

	/** @param {any} a */
	function describeRequest(a) {
		const parts = [];
		if (a.status) parts.push($t('finding.reqStatus', { status: $labelOf('status', a.status) }));
		if (a.severity) parts.push($t('finding.reqSeverity', { severity: $labelOf('severity', a.severity) }));
		return parts.join(', ');
	}

	/** @param {SubmitEvent} e */
	async function submitException(e) {
		e.preventDefault();
		/** @type {{ reason: string, expires_at?: string }} */
		const opts = { reason: exForm.reason };
		if (exForm.expires) opts.expires_at = new Date(exForm.expires).toISOString();
		exDialog.close();
		await applyStatus(pendingStatus, opts);
	}

	function cancelException() {
		exDialog.close();
		statusSelect = finding.status;
	}

	// Re-load whenever the route id changes — not just on mount. SvelteKit reuses
	// this component when you navigate from one finding to another (the "open the
	// primary finding" link, or "also reported by"), so an onMount-only fetch would
	// leave the previous finding on screen until you reloaded the page by hand.
	$effect(() => {
		load(id);
	});
</script>

<button onclick={() => history.back()} class="text-sm text-base-content/60 hover:text-base-content">{$t('finding.back')}</button>

<State {loading} {error} />

{#if !loading && finding}
	<div class="mt-2 mb-4 flex flex-wrap items-start justify-between gap-3 rounded-box border-l-4 {severityAccent(finding.severity)} bg-base-100 p-5 shadow-sm">
		<div class="min-w-0">
			<div class="mb-2 flex flex-wrap items-center gap-2">
				<Badge kind="severity" value={finding.severity} size="badge-md" />
				<span class="badge badge-ghost badge-md uppercase">{$labelOf('category', finding.category)}</span>
				<span class="badge badge-neutral badge-md">{$t('finding.priority', { value: Math.round(finding.priority) })}</span>
				{#if finding.kev}<span class="badge badge-error badge-md" title={finding.kev_sources?.length ? $t('finding.kevTitle', { catalogs: kevCatalogs(finding.kev_sources) }) : $t('finding.kevTitleAny')}>KEV{#if finding.kev_sources?.length} · {finding.kev_sources.join(', ')}{/if}</span>{/if}
				{#if finding.kev_ransomware}<span class="badge badge-error badge-outline badge-md" title={$t('finding.ransomwareTitle')}>{$t('finding.ransomware')}</span>{/if}
				<ExploitBadge maturity={finding.exploit_maturity} size="md" />
				{#if finding.epss}<span class="badge badge-outline badge-md">EPSS {fmtNumber(finding.epss, { style: 'percent' })}</span>{/if}
				{#if finding.cvss}
					<span class="badge badge-outline badge-md" title={finding.cvss_source === 'nvd' ? $t('finding.cvssNvd') : $t('finding.cvssScanner')}>
						CVSS {fmtNumber(Math.round(finding.cvss * 10) / 10)}{#if finding.cvss_source === 'nvd'} · NVD{/if}
					</span>
				{/if}
			</div>
			{#if finding.cvss_vector}
				<p class="mb-2 text-xs text-base-content/60">
					<span class="uppercase">NVD CVSS {finding.cvss_version}</span>
					<code class="ml-1 break-all">{finding.cvss_vector}</code>
				</p>
			{/if}
			{#if finding.archived_at}
				<div class="alert alert-warning mb-2">
					<span>{$t('finding.archivedOn', { date: fmtDateOnly(finding.archived_at) })}</span>
					<button class="btn btn-sm" onclick={() => setArchived(false)}>{$t('common.restore')}</button>
				</div>
			{/if}
			<h1 class="text-xl font-bold flex items-center gap-2">
				{finding.title}
				{#if !finding.archived_at}
					<button class="btn btn-ghost btn-xs text-error" onclick={() => setArchived(true)}>{$t('common.archive')}</button>
				{/if}
				{#if !finding.duplicate_of}
					<button class="btn btn-ghost btn-xs" onclick={markDuplicateOpen}>{$t('finding.markDuplicate')}</button>
				{/if}
			</h1>
			{#if markingDuplicate}
				<form class="mb-2 flex items-center gap-2" onsubmit={markDuplicateSubmit}>
					<input class="input input-bordered input-sm max-w-xs" bind:value={duplicatePrimaryId}
						placeholder={$t('finding.markDuplicatePlaceholder')} />
					<button class="btn btn-sm btn-primary" disabled={duplicateBusy}>{$t('common.save')}</button>
					<button type="button" class="btn btn-sm btn-ghost" onclick={() => (markingDuplicate = false)}>{$t('common.cancel')}</button>
				</form>
			{/if}
			<p class="text-sm text-base-content/60">
				{finding.scanner}{#if finding.rule_id} · {finding.rule_id}{#if !finding.cve?.some((/** @type {string} */ c) => c.toUpperCase() === finding.rule_id.toUpperCase())}{#each advisoryLinks(finding.rule_id) as l (l.label)}<a class="link text-xs ml-1" href={l.href} target="_blank" rel="noopener noreferrer">{l.label} ↗</a>{/each}{/if}{/if}
				{#if duplicates.length}· <span title={$t('finding.alsoReportedTitle')}>{$t('finding.reportedBy', { count: duplicates.length + 1 })}</span>{/if}
				{#if finding.planned_remediation_at}· {$t('finding.plannedFix', { date: fmtDay(finding.planned_remediation_at) })}{/if}
			</p>
			<FindingFieldsEditor {finding}
				onsaved={(/** @type {any} */ f) => { finding = { ...finding, ...f }; revision++; }}
				onconflict={() => load(id)} />
		</div>
		<label class="form-control">
			<span class="label-text mb-1">{$t('finding.status')}</span>
			<select class="select select-bordered select-sm" bind:value={statusSelect} onchange={onStatusChange} disabled={saving || !!pendingAssessment}
				title={pendingAssessment ? $t('finding.awaitingTitle') : ''}>
				{#each STATUSES as s}<option value={s}>{$labelOf('status', s)}</option>{/each}
			</select>
		</label>
	</div>

	{#if pendingAssessment}
		<div class="alert alert-warning mb-4 text-sm">
			<div class="min-w-0 flex-1">
				<span class="font-semibold">{$t('finding.awaiting')}</span> {describeRequest(pendingAssessment)}
				<div class="text-xs opacity-70 mt-0.5">
					{$t('finding.requestedBy', { who: pendingAssessment.requester || $t('finding.deletedUser') })} · {fmtDate(pendingAssessment.created_at)}
					{#if pendingAssessment.expires_at}· {$t('finding.acceptanceExpires', { date: fmtDate(pendingAssessment.expires_at) })}{/if}
				</div>
				{#if pendingAssessment.reason}<div class="mt-1">“{pendingAssessment.reason}”</div>{/if}
			</div>
			{#if pendingAssessment.can_decide}
				<div class="flex gap-2">
					<button class="btn btn-success btn-sm" disabled={deciding} onclick={() => decide(true)}>{$t('finding.approve')}</button>
					<button class="btn btn-ghost btn-sm" disabled={deciding} onclick={() => decide(false)}>{$t('finding.reject')}</button>
				</div>
			{/if}
		</div>
	{/if}

	{#if finding.duplicate_of}
		<div class="alert alert-warning mb-4 py-2 text-sm">
			<span>{$t('finding.duplicate')} <a class="link font-semibold" href={`/findings/${finding.duplicate_of}`}>{$t('finding.openPrimary')}</a></span>
			{#if finding.duplicate_manual}
				<button class="btn btn-ghost btn-xs" disabled={duplicateBusy} onclick={unmarkDuplicate}>{$t('finding.unmarkDuplicate')}</button>
			{/if}
		</div>
	{/if}

	{#if finding.risk_acceptance}
		<div class="alert {finding.risk_acceptance.state === 'approved' ? 'alert-info' : 'alert-warning'} mb-4 text-sm">
			<div>
				<span class="font-semibold">{finding.risk_acceptance.state === 'approved' ? $t('finding.ra.approved') : finding.risk_acceptance.state === 'requested' ? $t('finding.ra.requested') : $t('finding.raOther', { state: finding.risk_acceptance.state })}</span>
				<a class="link" href={`/projects/${finding.project_id}?tab=acceptances`}>{finding.risk_acceptance.title}</a>
				— {finding.risk_acceptance.justification}
				<div class="text-xs opacity-70 mt-0.5">
					{#if finding.risk_acceptance.approver}{$t('finding.approvedBy', { who: finding.risk_acceptance.approver })}{:else}{$t('finding.awaitingLower')}{/if}
					{#if finding.risk_acceptance.expires_at}· {$t('finding.expires', { date: fmtDate(finding.risk_acceptance.expires_at) })}{:else}· {$t('finding.noExpiry')}{/if}
				</div>
			</div>
		</div>
	{/if}

	{#if finding.exception_reason}
		<div class="alert alert-info mb-4 text-sm">
			<div>
				<span class="font-semibold capitalize">{$labelOf('status', finding.status)}</span> — {finding.exception_reason}
				<div class="text-xs opacity-70 mt-0.5">
					{#if finding.exception_by}{$t('finding.acceptedBy', { who: finding.exception_by })}{/if}
					{#if finding.exception_expires_at}· {$t('finding.expires', { date: fmtDate(finding.exception_expires_at) })}{:else}· {$t('finding.noExpiry')}{/if}
				</div>
			</div>
		</div>
	{/if}

	<FindingIssue findingId={finding.id} projectId={finding.project_id} />

	<div class="grid gap-4 md:grid-cols-3">
		<!-- Details -->
		<div class="md:col-span-2 card bg-base-100 shadow-sm">
			<div class="card-body">
				<FindingWriteup {finding} onsaved={(f) => (finding = f)} />
				<dl class="grid grid-cols-3 gap-y-2 text-sm">
					{#if finding.package_name}
						<dt class="text-base-content/50">{$t('finding.package')}</dt>
						<dd class="col-span-2">{finding.package_name}{#if finding.package_version} @ {finding.package_version}{/if}</dd>
					{/if}
					{#if finding.dep_direct !== null || finding.dep_scope}
						<dt class="text-base-content/50">{$t('finding.reachability')}</dt>
						<dd class="col-span-2">
							{#if finding.dep_direct === true}<span class="badge badge-outline badge-sm">{$t('finding.direct')}</span>
							{:else if finding.dep_direct === false}<span class="badge badge-ghost badge-sm">{$t('finding.transitive')}{#if finding.dep_depth} · {$t('finding.depth', { depth: finding.dep_depth })}{/if}</span>{/if}
							{#if finding.dep_scope}<span class="badge badge-ghost badge-sm ml-1">{$labelOf('scope', finding.dep_scope)}</span>{/if}
							<span class="ml-2 text-xs text-base-content/50">
								{#if finding.dep_scope === 'dev'}{$t('finding.devNote')}
								{:else if finding.dep_direct === false}{$t('finding.transitiveNote')}
								{:else}{$t('finding.directNote')}{/if}
							</span>
						</dd>
					{/if}
					{#if finding.fixed_version}
						<dt class="text-base-content/50">{$t('finding.fixedIn')}</dt>
						<dd class="col-span-2 text-success">{finding.fixed_version}</dd>
					{/if}
					{#if finding.purl}
						<dt class="text-base-content/50">PURL</dt>
						<dd class="col-span-2 font-mono text-xs break-all">
							{finding.purl}
							{#if depsDevURL(finding.purl)}<a class="link ml-1 font-sans" href={depsDevURL(finding.purl)} target="_blank" rel="noopener noreferrer">deps.dev ↗</a>{/if}
						</dd>
					{/if}
					{#if finding.file_path}
						<dt class="text-base-content/50">{$t('finding.location')}</dt>
						<dd class="col-span-2 font-mono text-xs">
							{#if finding.source_url}
								<a class="link" href={finding.source_url} target="_blank" rel="noopener noreferrer"
									title={$t('finding.repoTitle')}>{finding.file_path}{#if finding.line}:{finding.line}{/if} ↗</a>
							{:else}
								{finding.file_path}{#if finding.line}:{finding.line}{/if}
							{/if}
						</dd>
					{/if}
					{#if finding.cve?.length}
						<dt class="text-base-content/50">CVE</dt>
						<dd class="col-span-2">
							{#each finding.cve as cve, i (cve)}
								{#if i > 0}<span class="text-base-content/40">, </span>{/if}{cve}
								{#each advisoryLinks(cve) as l (l.label)}<a class="link text-xs ml-1" href={l.href} target="_blank" rel="noopener noreferrer">{l.label} ↗</a>{/each}
							{/each}
						</dd>
					{/if}
					{#if finding.cwe}
						<dt class="text-base-content/50">CWE</dt>
						<dd class="col-span-2">CWE-{finding.cwe}</dd>
					{/if}
					{#if finding.url}
						<dt class="text-base-content/50">{$t('finding.reference')}</dt>
						<dd class="col-span-2"><a class="link link-primary text-xs break-all" href={finding.url}>{finding.url}</a></dd>
					{/if}
				</dl>
				<FindingExploits findingId={finding.id} />
			</div>
		</div>

		<!-- Timeline -->
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<h3 class="font-semibold text-sm text-base-content/60">{$t('finding.lifecycle')}</h3>
				<div class="text-sm space-y-2 mt-1">
					{#if branch}
						<div>
							<div class="text-xs text-base-content/50">{branch.kind === 'release' ? $t('finding.release') : $t('finding.branch')}</div>
							<span class="font-mono">{branch.name}</span>
							{#if branch.is_default}<span class="badge badge-primary badge-xs ml-1">{$t('finding.default')}</span>{/if}
						</div>
					{/if}
					<div><div class="text-xs text-base-content/50">{$t('finding.firstSeen')}</div>{fmtDate(finding.first_seen_at)}</div>
					<div><div class="text-xs text-base-content/50">{$t('finding.lastSeen')}</div>{fmtDate(finding.last_seen_at)}</div>
					{#if finding.resolved_at}
						<div><div class="text-xs text-base-content/50">{$t('finding.resolved')}</div>{fmtDate(finding.resolved_at)}</div>
					{/if}
					{#if finding.sla_due_at}
						<div>
							<div class="text-xs text-base-content/50">{$t('finding.slaWindow', { days: finding.sla_days })}</div>
							<div class="flex items-center gap-2">
								{fmtDate(finding.sla_due_at)}
								<SlaBadge status={finding.sla_status} due={finding.sla_due_at} compact />
							</div>
							{#if finding.sla_status === 'paused'}
								<div class="text-xs text-base-content/50">{$t('finding.slaPausedNote')}</div>
							{/if}
						</div>
					{:else}
						<div><div class="text-xs text-base-content/50">SLA</div><span class="text-base-content/40">{$t('finding.slaNone', { severity: $labelOf('severity', finding.severity) })}</span></div>
					{/if}
				</div>
			</div>
		</div>
	</div>

	{#if isOn($features, 'custom_fields')}
		<div class="mb-4">
			<CustomFieldsEditor kind="findings" id={finding.id} projectId={finding.project_id} values={finding.custom} canEdit
				onsaved={(v) => (finding = { ...finding, custom: v })} />
		</div>
	{/if}
	<FindingWorkflow {finding} {revision} onchange={(f) => (finding = f)} onconflict={() => load(id)} />

	<FindingAI {finding} onchange={(f) => (finding = f)} onrevision={() => revision++} />

	<!-- Exception / risk-acceptance history -->
	{#if exceptions.length > 0}
		<div class="mt-6">
			<h2 class="text-lg font-semibold mb-2">{$t('finding.exceptionHistory')}</h2>
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('finding.colWhen')}</th><th>{$t('finding.colAction')}</th><th>{$t('finding.colReason')}</th><th>{$t('finding.colBy')}</th><th>{$t('finding.colExpires')}</th></tr></thead>
					<tbody>
						{#each exceptions as ex (ex.id)}
							<tr>
								<td class="text-xs text-base-content/60">{fmtDate(ex.created_at)}</td>
								<td><span class="badge badge-ghost badge-sm">{$labelOf('status', ex.status)}</span></td>
								<td class="text-sm">{ex.reason || '—'}</td>
								<td class="text-xs">{ex.actor || '—'}</td>
								<td class="text-xs">{ex.expires_at ? fmtDate(ex.expires_at) : '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}

	<!-- Cross-tool duplicates collapsed under this finding -->
	{#if duplicates.length > 0}
		<div class="mt-6">
			<h2 class="mb-2 text-lg font-semibold">{$t('finding.alsoReported')} <span class="text-sm font-normal text-base-content/50">{$t('finding.sameIssue')}</span></h2>
			<div class="overflow-x-auto rounded-box bg-base-100 shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('finding.colScanner')}</th><th>{$t('finding.colSeverity')}</th><th>{$t('finding.colRule')}</th><th>{$t('finding.colPackage')}</th></tr></thead>
					<tbody>
						{#each duplicates as d (d.id)}
							<tr class="hover">
								<td class="font-medium">{d.scanner}</td>
								<td><Badge kind="severity" value={d.severity} /></td>
								<td class="text-xs">{d.rule_id || '—'}</td>
								<td class="text-xs">{d.package_name || '—'}{#if d.package_version}<span class="text-base-content/50"> @{d.package_version}</span>{/if}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}

	<!-- Correlated SBOM components -->
	<div class="mt-6">
		<h2 class="text-lg font-semibold mb-2">{$t('finding.introducedBy')}</h2>
		{#if components.length === 0}
			<div class="text-sm text-base-content/50">
				{$t('finding.noComponent')}
			</div>
		{:else}
			{#if via}
				<div class="bg-base-100 rounded-box shadow-sm p-4 mb-3 text-sm">
					<div class="text-xs text-base-content/50 mb-1">
						{$t('finding.pulledVia')} <a class="link" href={`/sboms/${via.component.sbom_id}?tab=graph`}>{$t('finding.graph', { name: via.component.artifact || $t('finding.snapshot') })}</a>
					</div>
					{#each via.paths.slice(0, 5) as p, i (i)}
						<div class="font-mono text-xs">
							{#each p as n, j (j)}{#if j > 0}<span class="text-base-content/40"> → </span>{/if}<span class={j === p.length - 1 ? 'font-semibold text-error' : j === 1 ? 'font-semibold' : ''}>{n.name}{#if n.version}<span class="text-base-content/50">@{n.version}</span>{/if}</span>{/each}
						</div>
					{/each}
					{#if via.paths.length > 5}<div class="text-xs text-base-content/50">{$t('finding.moreRoutes', { count: via.paths.length - 5 })}</div>{/if}
					<div class="text-xs text-base-content/50 mt-1">{$t('finding.firstHop')}</div>
				</div>
			{/if}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('finding.colComponent')}</th><th>{$t('finding.colVersion')}</th><th>{$t('finding.colArtifact')}</th><th>{$t('finding.colPurl')}</th></tr></thead>
					<tbody>
						{#each components as c (c.id)}
							<tr class="hover">
								<td>{c.name}</td>
								<td class="text-xs">{c.version || '—'}</td>
								<td class="text-xs"><a class="link link-hover" href={`/sboms/${c.sbom_id}`}>{c.artifact || '—'}</a></td>
								<td class="text-xs text-base-content/50 max-w-xs truncate">{c.purl || '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}

<!-- Accept-risk / exception modal -->
<dialog bind:this={exDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-1">{$labelOf('status', pendingStatus)}</h3>
		<p class="text-sm text-base-content/60 mb-4">{$t('finding.exIntro')}</p>
		<form onsubmit={submitException} class="flex flex-col gap-3">
			<label class="form-control">
				<span class="label-text mb-1">{$t('triage.reason')}</span>
				<textarea bind:value={exForm.reason} required placeholder={$t('triage.reasonPlaceholder')}
					class="textarea textarea-bordered h-24"></textarea>
			</label>
			<label class="form-control">
				<span class="label-text mb-1">{$t('triage.expires')} <span class="text-base-content/40">{$t('triage.expiresHint')}</span></span>
				<input type="date" bind:value={exForm.expires} class="input input-bordered" />
			</label>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={cancelException}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('common.confirm')}
				</button>
			</div>
		</form>
	</div>
	<button type="button" class="modal-backdrop" onclick={cancelException} aria-label={$t('common.close')}></button>
</dialog>
