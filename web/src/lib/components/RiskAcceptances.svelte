<script>
	// Risk acceptances: the approval queue (no projectId: requested ones across
	// visible projects, plus approved ones whose extension waits for you) or
	// one project's list. Expand a row for its ledger, its extensions and, for
	// an approved one, the extend form.
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import { fmtDate } from '#lib/format.js';
	import State from '#lib/components/State.svelte';

	/** @type {{ projectId?: string, only?: string }} */
	let { projectId = '', only = '' } = $props();

	let loading = $state(true);
	let error = $state('');
	let items = $state(/** @type {any[]} */ ([]));
	let open = $state('');
	let members = $state(/** @type {any[]} */ ([]));
	let extensions = $state(/** @type {any[]} */ ([]));
	let busy = $state('');
	let extendTo = $state('');
	let extendWhy = $state('');

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const STATE_KEY = { requested: 'ra.state.requested', approved: 'ra.state.approved', rejected: 'ra.state.rejected', revoked: 'ra.state.revoked' };

	async function load() {
		loading = true;
		error = '';
		try {
			const filters = only ? { state: only } : {};
			const res = projectId ? await api.projectRiskAcceptances(projectId, filters) : await api.listRiskAcceptances(filters);
			items = res.risk_acceptances ?? [];
			if (!projectId && only === 'requested') {
				// The queue also holds approved acceptances whose extension waits.
				const actionable = (await api.listRiskAcceptances({ actionable: true })).risk_acceptances ?? [];
				const seen = new Set(items.map((a) => a.id));
				items = [...items, ...actionable.filter((/** @type {any} */ a) => a.pending_extension && !seen.has(a.id))];
			}
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('appr.loadFailed');
		} finally {
			loading = false;
		}
	}

	/** @param {any} a */
	async function toggle(a) {
		if (open === a.id) {
			open = '';
			return;
		}
		open = a.id;
		extendTo = '';
		extendWhy = '';
		try {
			const res = await api.getRiskAcceptance(a.project_id, a.id);
			members = res.findings ?? [];
			extensions = res.extensions ?? [];
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} a @param {SubmitEvent} e */
	async function extend(a, e) {
		e.preventDefault();
		busy = a.id;
		try {
			// The date input is a local day; the acceptance lasts to its end.
			const to = new Date(extendTo + 'T23:59:59').toISOString();
			const res = await api.extendRiskAcceptance(a.project_id, a.id, to, extendWhy);
			notify(res.extension?.state === 'pending' ? $t('ra.extensionRequested') : $t('ra.extendedToast'), 'success');
			open = '';
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	/** @param {any} a @param {'approve' | 'reject'} action */
	async function decideExtension(a, action) {
		const note = prompt($t('finding.approvalNote'));
		if (note === null) return;
		busy = a.id;
		try {
			await api.decideRiskAcceptanceExtension(a.project_id, a.id, a.pending_extension.id, action, note);
			notify(action === 'approve' ? $t('ra.extendedToast') : $t('finding.rejected'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const EXT_STATE_KEY = { pending: 'ra.ext.pending', approved: 'ra.ext.approved', rejected: 'ra.ext.rejected', withdrawn: 'ra.ext.withdrawn' };

	/** @param {any} a @param {'approve' | 'reject' | 'revoke'} action */
	async function decide(a, action) {
		const note = prompt(action === 'approve' ? $t('finding.approvalNote') : $t('ra.revokeWhyPrompt'));
		if (note === null) return;
		busy = a.id;
		try {
			await api.decideRiskAcceptance(a.project_id, a.id, action, note);
			notify(action === 'approve' ? $t('ra.approvedToast') : action === 'reject' ? $t('finding.rejected') : $t('ra.revokedToast'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	onMount(load);
</script>

<State {loading} {error} empty={!loading && !error && items.length === 0}
	emptyText={only === 'requested' ? $t('ra.emptyRequested') : $t('ra.emptyAll')} />

{#if !loading && items.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('ra.colAcceptance')}</th>{#if !projectId}<th>{$t('ra.colProject')}</th>{/if}<th>{$t('ra.colFindings')}</th><th>{$t('ra.colExpires')}</th><th>{$t('ra.colRequested')}</th><th>{$t('ra.colState')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each items as a (a.id)}
					<tr class="hover cursor-pointer" onclick={() => toggle(a)}>
						<td class="max-w-sm">
							<div class="font-medium truncate">{a.title}</div>
							<div class="text-xs text-base-content/50 truncate" title={a.justification}>{a.justification}</div>
						</td>
						{#if !projectId}<td class="text-xs">{a.project_name}</td>{/if}
						<td>{a.finding_count}</td>
						<td class="text-xs whitespace-nowrap">{a.expires_at ? fmtDate(a.expires_at) : $t('tok.never')}</td>
						<td class="text-xs whitespace-nowrap">{a.requester || '—'}<div class="text-base-content/50">{fmtDate(a.requested_at)}</div></td>
						<td class="text-xs">
							<span class="badge badge-sm {a.state === 'requested' ? 'badge-warning' : a.state === 'approved' ? 'badge-success' : 'badge-ghost'}">{STATE_KEY[a.state] ? $t(STATE_KEY[a.state]) : a.state}</span>
							{#if a.approver}<div class="text-base-content/50 mt-0.5">{$t('appr.by', { who: a.approver })}</div>{/if}
							{#if a.pending_extension}
								<div class="mt-0.5 font-medium text-base-content/80" title={a.pending_extension.reason}>{$t('ra.extensionPending', { date: fmtDate(a.pending_extension.to_expires_at) })}</div>
							{/if}
						</td>
						<td class="whitespace-nowrap text-right">
							{#if a.can_approve}
								<button class="btn btn-success btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decide(a, 'approve'); }}>{$t('finding.approve')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decide(a, 'reject'); }}>{$t('finding.reject')}</button>
							{/if}
							{#if a.can_decide_extension}
								<button class="btn btn-success btn-xs" disabled={busy === a.id} title={a.pending_extension.reason} onclick={(e) => { e.stopPropagation(); decideExtension(a, 'approve'); }}>{$t('ra.approveExtension')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decideExtension(a, 'reject'); }}>{$t('ra.rejectExtension')}</button>
							{/if}
							{#if a.can_revoke && a.state === 'approved'}
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decide(a, 'revoke'); }}>{$t('ra.revoke')}</button>
							{/if}
						</td>
					</tr>
					{#if open === a.id}
						<tr>
							<td colspan={projectId ? 6 : 7} class="bg-base-200">
								<table class="table table-xs">
									<thead><tr><th>{$t('ra.colFinding')}</th><th>{$t('ra.colStatus')}</th><th>{$t('ra.colAdded')}</th><th>{$t('ra.colLeft')}</th></tr></thead>
									<tbody>
										{#each members as m (m.id)}
											<tr>
												<td><a class="link link-hover" href={`/findings/${m.finding_id}`}>{m.finding_title}</a></td>
												<td>{$labelOf('status', m.finding_status)}</td>
												<td class="text-xs">{fmtDate(m.added_at)} · {m.added_by || '—'}</td>
												<td class="text-xs">{#if m.removed_at}{fmtDate(m.removed_at)} · {m.reason}{:else}—{/if}</td>
											</tr>
										{/each}
									</tbody>
								</table>
								{#if extensions.length > 0}
									<h4 class="mt-3 mb-1 text-xs font-semibold">{$t('ra.extensions')}</h4>
									<ul class="text-xs space-y-1">
										{#each extensions as x (x.id)}
											<li>
												<span class="badge badge-ghost badge-xs">{EXT_STATE_KEY[x.state] ? $t(EXT_STATE_KEY[x.state]) : x.state}</span>
												{fmtDate(x.from_expires_at)} → {fmtDate(x.to_expires_at)} · {x.requester || '—'}: {x.reason}
												{#if x.decider}<span class="text-base-content/50"> · {$t('appr.by', { who: x.decider })}{#if x.decision_note}: {x.decision_note}{/if}</span>{/if}
											</li>
										{/each}
									</ul>
								{/if}
								{#if a.can_extend}
									<form class="mt-3 flex flex-wrap items-end gap-2" onsubmit={(e) => extend(a, e)}>
										<label class="text-xs">
											<span class="block mb-0.5">{$t('ra.extendTo')}</span>
											<input type="date" required bind:value={extendTo} min={a.expires_at?.slice(0, 10)} class="input input-bordered input-xs" />
										</label>
										<label class="text-xs flex-1 min-w-48">
											<span class="block mb-0.5">{$t('ra.extendReason')}</span>
											<input required maxlength="2000" bind:value={extendWhy} class="input input-bordered input-xs w-full" />
										</label>
										<button class="btn btn-primary btn-xs" disabled={busy === a.id}>{$t('ra.extend')}</button>
									</form>
								{/if}
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
{/if}
