<script>
	// README badges for a project: an owner issues (or rotates / revokes) a
	// badge token; the token is shown once, with Markdown to paste. Anyone with
	// the token sees the badges' numbers — that's the point of a README badge.
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { fmtDate } from '$lib/format.js';
	import { t } from '$lib/i18n.js';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	/** @type {[string, import('$lib/i18n.js').MessageKey][]} */
	const KINDS = [
		['findings', 'readme.findings'],
		['gate', 'readme.gate'],
		['sla', 'readme.sla']
	];

	let status = $state(/** @type {{ enabled: boolean, issued_at: string | null } | null} */ (null));
	// Set only right after issuing: the token is never readable again.
	let issued = $state(/** @type {{ token: string, urls: Record<string, string>, markdown: Record<string, string> } | null} */ (null));
	let busy = $state(false);

	$effect(() => {
		projectId;
		issued = null;
		api.badgeStatus(projectId).then((s) => (status = s)).catch(() => (status = null));
	});

	/** @param {unknown} err */
	function fail(err) {
		notify(err instanceof ApiError && err.status === 403 ? $t('readme.ownerOnly') : errorMessage(err));
	}

	async function issue() {
		if (status?.enabled && !confirm($t('readme.rotateConfirm'))) return;
		busy = true;
		try {
			issued = await api.issueBadgeToken(projectId);
			status = await api.badgeStatus(projectId);
		} catch (err) {
			fail(err);
		} finally {
			busy = false;
		}
	}

	async function revoke() {
		if (!confirm($t('readme.revokeConfirm'))) return;
		try {
			await api.revokeBadgeToken(projectId);
			issued = null;
			status = await api.badgeStatus(projectId);
			notify($t('readme.revoked'), 'success');
		} catch (err) {
			fail(err);
		}
	}

	/** @param {string} text */
	async function copy(text) {
		await navigator.clipboard.writeText(text);
		notify($t('readme.copied'), 'success');
	}
</script>

<div class="bg-base-100 rounded-box shadow-sm p-4 mt-4 max-w-3xl">
	<div class="flex items-center gap-2 mb-2">
		<h3 class="font-semibold">{$t('readme.title')}</h3>
		{#if status?.enabled}<span class="text-xs text-base-content/50">{$t('readme.issuedAt', { date: fmtDate(status.issued_at) })}</span>{/if}
		<span class="ml-auto"></span>
		{#if status?.enabled}<button class="btn btn-ghost btn-xs text-error" onclick={revoke}>{$t('readme.revoke')}</button>{/if}
		<button class="btn btn-sm btn-outline" onclick={issue} disabled={busy}>{status?.enabled ? $t('readme.rotate') : $t('readme.enable')}</button>
	</div>
	<p class="text-sm text-base-content/60 mb-2">
		{$t('readme.intro')}
	</p>
	{#if issued}
		<div class="space-y-2">
			{#each KINDS as [kind, labelKey]}
				<div class="flex items-center gap-2">
					<img src={issued.urls[kind]} alt={$t(labelKey)} class="h-5" />
					<code class="text-xs bg-base-200 rounded px-2 py-1 flex-1 truncate">{issued.markdown[kind]}</code>
					<button class="btn btn-ghost btn-xs" onclick={() => copy(issued?.markdown[kind] ?? '')}>{$t('readme.copy')}</button>
				</div>
			{/each}
			<p class="text-xs text-warning">{$t('readme.copyNowWarning')}</p>
		</div>
	{:else if status?.enabled}
		<p class="text-xs text-base-content/50">{$t('readme.live')}</p>
	{/if}
</div>
