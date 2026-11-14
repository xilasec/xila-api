<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import { token, notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	// The link carries the token in the fragment (#token=…), which browsers never
	// send to a server or leak in a Referer.
	let resetToken = $state('');
	let password = $state('');
	let repeat = $state('');
	let saving = $state(false);
	let error = $state('');

	let mismatch = $derived(repeat !== '' && password !== repeat);

	onMount(() => {
		const m = window.location.hash.match(/(?:^|#|&)token=([^&]+)/);
		resetToken = m ? decodeURIComponent(m[1]) : '';
	});

	/** @param {SubmitEvent} e */
	async function submit(e) {
		e.preventDefault();
		if (password !== repeat) return;
		error = '';
		saving = true;
		try {
			const out = await api.confirmPasswordReset(resetToken, password);
			if (out.mfa_required) {
				// Two-factor still applies: sign in with the new password and a code.
				notify($t('reset.mfaNext'), 'success');
				goto('/login', { replace: true });
				return;
			}
			token.set(out.token);
			notify($t('reset.signedIn'), 'success');
			goto('/', { replace: true });
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			saving = false;
		}
	}
</script>

<div class="min-h-[70vh] flex items-center justify-center">
	<div class="card w-full max-w-sm bg-base-100 shadow-xl">
		<form class="card-body gap-3" onsubmit={submit}>
			<div class="text-center mb-2">
				<div class="text-3xl text-primary">◈</div>
				<h1 class="text-2xl font-bold">{$t('reset.title')}</h1>
			</div>
			{#if !resetToken}
				<div class="alert alert-warning py-2 text-sm">
					<span>{$t('reset.needsLink')}</span>
				</div>
				<a href="/login" class="btn btn-ghost btn-sm">{$t('login.backToSignIn')}</a>
			{:else}
				<label class="form-control">
					<span class="label-text mb-1">{$t('reset.newPassword')}</span>
					<input type="password" bind:value={password} required minlength="8" autocomplete="new-password" placeholder={$t('login.passwordPlaceholder')} class="input input-bordered w-full" />
				</label>
				<label class="form-control">
					<span class="label-text mb-1">{$t('reset.repeat')}</span>
					<input type="password" bind:value={repeat} required minlength="8" autocomplete="new-password" class="input input-bordered w-full" class:input-error={mismatch} />
				</label>
				{#if mismatch}<span class="text-xs text-error">{$t('reset.mismatch')}</span>{/if}
				{#if error}
					<div class="alert alert-error py-2 text-sm"><span>{error}</span></div>
				{/if}
				<p class="text-xs text-base-content/50">{$t('reset.signsOut')}</p>
				<button class="btn btn-primary" disabled={saving || mismatch}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}
					{$t('reset.submit')}
				</button>
			{/if}
		</form>
	</div>
</div>
