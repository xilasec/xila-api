<script>
	// The finding's linked tracker issue (Jira / GitHub / GitLab): a link + its
	// last synced state, or a "Create issue" button when the project has a tracker.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	/** @type {{ findingId: string, projectId?: string | null }} */
	let { findingId, projectId } = $props();

	/** @type {Record<string, string>} */
	const KIND_LABEL = { jira: 'Jira', github: 'GitHub', gitlab: 'GitLab' };

	let link = $state(/** @type {any} */ (null));
	let tracker = $state(/** @type {any} */ (null));
	let ready = $state(false);
	let busy = $state(false);

	$effect(() => {
		const fid = findingId;
		const pid = projectId;
		ready = false;
		link = null;
		tracker = null;
		(async () => {
			try {
				link = await api.findingIssue(fid);
			} catch (err) {
				if (!(err instanceof ApiError && err.status === 404)) notify(errorMessage(err));
				link = null;
			}
			if (!link && pid) {
				try {
					tracker = await api.issueTracker(pid);
				} catch (err) {
					if (!(err instanceof ApiError && err.status === 404)) notify(errorMessage(err));
					tracker = null;
				}
			}
			ready = true;
		})();
	});

	/** @param {any} l */
	function label(l) {
		const kind = KIND_LABEL[l.kind] ?? l.kind;
		return l.kind === 'jira' ? `${kind} ${l.external_id}` : `${kind} #${l.external_id}`;
	}

	async function create() {
		busy = true;
		try {
			link = await api.createFindingIssue(findingId);
			notify($t('issue.created'), 'success');
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('issue.needsEditor') : errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

{#if ready}
	<div class="mb-4 flex flex-wrap items-center gap-2 rounded-box bg-base-100 px-4 py-2 text-sm shadow-sm">
		<span class="text-base-content/50">{$t('issue.label')}</span>
		{#if link}
			{#if link.url}
				<a class="link link-primary font-medium" href={link.url} target="_blank" rel="noopener noreferrer">{label(link)} ↗</a>
			{:else}
				<span class="font-medium">{label(link)}</span>
			{/if}
			<span class="badge badge-sm {link.state === 'open' ? 'badge-warning' : 'badge-success'}">{link.state === 'open' ? $t('issue.state.open') : link.state === 'closed' ? $t('issue.state.closed') : link.state}</span>
			<span class="text-xs text-base-content/40">{$t('issue.synced')}</span>
		{:else if tracker?.enabled}
			<button class="btn btn-outline btn-xs" disabled={busy} onclick={create}>
				{$t('issue.create', { kind: KIND_LABEL[tracker.kind] ?? '' })}
			</button>
		{:else}
			<span class="text-base-content/50">
				{$t('issue.none')} <a class="link" href={`/projects/${projectId}?tab=issues`}>{$t('issue.configure')}</a>
			</span>
		{/if}
	</div>
{/if}
