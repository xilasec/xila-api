<script>
	// Warns before an idle sign-out (M13 13.16) and signs out when the session
	// would have expired anyway, rather than leaving a page whose next
	// request fails. Counts from the last tracked request of any tab, minus
	// the minute the server may lag in recording activity.
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import { token } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { idleTimeout, idleSignedOut, lastActivity } from '#lib/session.js';

	let remaining = $state(Number.POSITIVE_INFINITY);
	// Warn in the last two minutes (a quarter of a short timeout).
	const warnAt = $derived(Math.min(120, Math.floor($idleTimeout / 4)));

	function signOut() {
		idleSignedOut.set(true);
		token.set(null);
		goto('/login');
	}

	$effect(() => {
		const idle = $idleTimeout;
		if (idle <= 0) return;
		const lag = Math.min(60, idle / 2) * 1000;
		const tick = () => {
			remaining = Math.floor((lastActivity() - lag + idle * 1000 - Date.now()) / 1000);
			if (remaining <= 0) signOut();
		};
		tick();
		const timer = setInterval(tick, 1000);
		return () => clearInterval(timer);
	});

	$effect(() => {
		if ($idleSignedOut) signOut();
	});

	async function stay() {
		try {
			await api.me(); // a tracked request: restarts the idle clock
		} catch {
			// a 401 here means it already expired: signOut follows
		}
	}

	const clock = $derived(`${Math.floor(Math.max(remaining, 0) / 60)}:${String(Math.max(remaining, 0) % 60).padStart(2, '0')}`);
</script>

{#if $idleTimeout > 0 && remaining > 0 && remaining <= warnAt}
	<div class="modal modal-open" role="alertdialog" aria-modal="true" aria-labelledby="idle-title">
		<div class="modal-box">
			<h3 id="idle-title" class="font-bold text-lg">{$t('session.warnTitle')}</h3>
			<p class="py-2">{$t('session.warnText', { time: clock })}</p>
			<div class="modal-action">
				<button class="btn btn-primary" onclick={stay}>{$t('session.stay')}</button>
			</div>
		</div>
	</div>
{/if}
