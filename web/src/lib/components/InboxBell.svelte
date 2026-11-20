<script>
	// Self-contained header bell for the in-app notification inbox (13.8):
	// polls the unread count and links to /inbox. Not wired into
	// +layout.svelte — the integrator mounts it in the header once it decides
	// where it goes, so this component stays a drop-in.
	import { onMount, onDestroy } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { token } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	const POLL_MS = 30_000;
	let unread = $state(0);
	let error = $state('');
	/** @type {ReturnType<typeof setInterval> | undefined} */
	let timer;

	async function refresh() {
		try {
			unread = await api.inboxCount();
			error = '';
		} catch (err) {
			// Signed out, or the request failed — keep the last known count
			// rather than flashing to zero.
			error = errorMessage(err);
		}
	}

	onMount(() => {
		refresh();
		timer = setInterval(refresh, POLL_MS);
	});
	onDestroy(() => clearInterval(timer));
</script>

{#if $token}
	<a
		href="/inbox"
		class="btn btn-ghost btn-circle btn-sm relative"
		aria-label={unread > 0 ? $t('inbox.bellUnread', { count: unread }) : $t('inbox.title')}
		title={$t('inbox.title')}
	>
		<span aria-hidden="true">🔔</span>
		{#if unread > 0}
			<span class="badge badge-primary badge-xs absolute -top-1 -right-1 px-1">{unread > 99 ? '99+' : unread}</span>
		{/if}
	</a>
{/if}
{#if error}
	<span class="sr-only">{error}</span>
{/if}
