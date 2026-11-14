<script>
	// The manual-assessment review queue (ASSESSMENT_REQUIRES_APPROVAL): status /
	// severity changes analysts asked for, waiting for a second person.
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate, prettyStatus } from '#lib/format.js';
	import Badge from '#lib/components/Badge.svelte';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import RiskAcceptances from '#lib/components/RiskAcceptances.svelte';

	const LIMIT = 50;
	let loading = $state(true);
	let error = $state('');
	let stateFilter = $state('pending');
	let assessments = $state(/** @type {any[]} */ ([]));
	let offset = $state(0);
	let hasMore = $state(false);
	let busy = $state('');

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const STATE_KEY = { pending: 'appr.statePending', approved: 'appr.stateApproved', rejected: 'appr.stateRejected' };

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.listAssessments({ state: stateFilter, limit: LIMIT, offset });
			assessments = res.assessments ?? [];
			hasMore = res.pagination?.has_more ?? false;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('appr.loadFailed');
		} finally {
			loading = false;
		}
	}

	function changeState() {
		offset = 0;
		load();
	}

	/** @param {any} a @param {boolean} approve */
	async function decide(a, approve) {
		const note = prompt(approve ? $t('finding.approvalNote') : $t('finding.rejectWhy'));
		if (note === null) return;
		busy = a.id;
		try {
			if (approve) await api.approveAssessment(a.id, note);
			else await api.rejectAssessment(a.id, note);
			notify(approve ? $t('finding.approved') : $t('finding.rejected'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	onMount(load);
</script>

<div class="flex items-center justify-between mb-5">
	<div>
		<h1 class="text-2xl font-bold">{$t('appr.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('appr.subtitle')}</p>
	</div>
	<select bind:value={stateFilter} onchange={changeState} class="select select-bordered select-sm capitalize">
		<option value="pending" class="capitalize">{$t('appr.statePending')}</option>
		<option value="approved" class="capitalize">{$t('appr.stateApproved')}</option>
		<option value="rejected" class="capitalize">{$t('appr.stateRejected')}</option>
		<option value="" class="capitalize">{$t('appr.stateAll')}</option>
	</select>
</div>

<h2 class="text-lg font-semibold mb-2">{$t('appr.riskHeading')}</h2>
<div class="mb-6"><RiskAcceptances only="requested" /></div>

<h2 class="text-lg font-semibold mb-2">{$t('appr.manualHeading')}</h2>
<State {loading} {error} empty={!loading && !error && assessments.length === 0}
	emptyText={stateFilter === 'pending' ? $t('appr.emptyPending') : $t('appr.emptyOther')} />

{#if !loading && assessments.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('appr.colFinding')}</th><th>{$t('appr.colProject')}</th><th>{$t('appr.colChange')}</th><th>{$t('appr.colReason')}</th><th>{$t('appr.colRequested')}</th><th>{$t('appr.colState')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each assessments as a (a.id)}
					<tr>
						<td class="max-w-sm">
							<div class="flex items-center gap-2">
								<Badge kind="severity" value={a.current_severity} />
								<a class="link link-hover truncate" href={`/findings/${a.finding_id}`}>{a.finding_title}</a>
							</div>
							<div class="text-xs text-base-content/50">{$t('appr.now', { status: prettyStatus(a.current_status) })}</div>
						</td>
						<td class="text-xs">{a.project_name}</td>
						<td class="text-sm whitespace-nowrap">
							{#if a.status}<div>{$t('finding.reqStatus', { status: prettyStatus(a.status) })}</div>{/if}
							{#if a.severity}<div>{$t('finding.reqSeverity', { severity: a.severity })}</div>{/if}
							{#if a.expires_at}<div class="text-xs text-base-content/50">{$t('finding.expires', { date: fmtDate(a.expires_at) })}</div>{/if}
						</td>
						<td class="text-sm max-w-xs truncate" title={a.reason}>{a.reason || '—'}</td>
						<td class="text-xs whitespace-nowrap">{a.requester || '—'}<div class="text-base-content/50">{fmtDate(a.created_at)}</div></td>
						<td class="text-xs">
							<span class="badge badge-sm capitalize {a.state === 'pending' ? 'badge-warning' : a.state === 'approved' ? 'badge-success' : 'badge-ghost'}">{STATE_KEY[a.state] ? $t(STATE_KEY[a.state]) : a.state}</span>
							{#if a.state !== 'pending'}
								<div class="text-base-content/50 mt-0.5">{$t('appr.by', { who: a.decider || '—' })}</div>
								{#if a.decision_note}<div class="text-base-content/50" title={a.decision_note}>“{a.decision_note}”</div>{/if}
							{/if}
						</td>
						<td class="whitespace-nowrap text-right">
							{#if a.can_decide}
								<button class="btn btn-success btn-xs" disabled={busy === a.id} onclick={() => decide(a, true)}>{$t('finding.approve')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={() => decide(a, false)}>{$t('finding.reject')}</button>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<Pagination limit={LIMIT} {offset} count={assessments.length} {hasMore}
		onchange={(/** @type {number} */ o) => { offset = o; load(); }} />
{/if}
