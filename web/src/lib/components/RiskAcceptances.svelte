<script>
	// Risk acceptances: the approval queue (no projectId: requested ones across
	// visible projects) or one project's list. Expand a row for its ledger.
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
	let busy = $state('');

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const STATE_KEY = { requested: 'ra.state.requested', approved: 'ra.state.approved', rejected: 'ra.state.rejected', revoked: 'ra.state.revoked' };

	async function load() {
		loading = true;
		error = '';
		try {
			const filters = only ? { state: only } : {};
			const res = projectId ? await api.projectRiskAcceptances(projectId, filters) : await api.listRiskAcceptances(filters);
			items = res.risk_acceptances ?? [];
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
		try {
			members = (await api.getRiskAcceptance(a.project_id, a.id)).findings ?? [];
		} catch (err) {
			notify(errorMessage(err));
		}
	}

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
						</td>
						<td class="whitespace-nowrap text-right">
							{#if a.can_approve}
								<button class="btn btn-success btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decide(a, 'approve'); }}>{$t('finding.approve')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy === a.id} onclick={(e) => { e.stopPropagation(); decide(a, 'reject'); }}>{$t('finding.reject')}</button>
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
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
{/if}
