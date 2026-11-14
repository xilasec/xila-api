<script>
	import { api } from '$lib/api.js';
	import { me, token, notify, features, isOn } from '$lib/stores.js';
	import Field from '$lib/components/Field.svelte';
	import { onMount } from 'svelte';
	import QRCode from 'qrcode';
	import MyNotifications from '$lib/components/MyNotifications.svelte';
	import { t, locale, LOCALES } from '$lib/i18n.js';
	import { fmtDate } from '$lib/format.js';

	/** @param {unknown} err */
	const errorText = (err) => (err instanceof Error ? err.message : String(err));

	let current = $state('');
	let next = $state('');
	let repeat = $state('');
	let saving = $state(false);
	let revoking = $state(false);

	let hasPassword = $derived($me?.has_password ?? true);
	let mismatch = $derived(repeat !== '' && next !== repeat);

	// Both actions revoke every other session; the server returns a fresh token
	// for this one, so swap it in before anything else calls the API.
	/** @param {{ token: string, user: import('$lib/stores.js').User }} out */
	function adopt(out) {
		token.set(out.token);
		me.set(out.user);
	}

	/** @param {SubmitEvent} e */
	async function changePassword(e) {
		e.preventDefault();
		if (next !== repeat) return;
		saving = true;
		try {
			adopt(await api.changePassword(current, next));
			current = next = repeat = '';
			notify($t('account.passwordChanged'), 'success');
		} catch (err) {
			notify(errorText(err));
		} finally {
			saving = false;
		}
	}

	// Two-factor: status, enrollment (secret → code → recovery codes), disable.
	let mfa = $state(/** @type {{ enabled: boolean, recovery_codes_left: number, available: boolean } | null} */ (null));
	let setup = $state(/** @type {{ secret: string, otpauth_url: string, qr: string } | null} */ (null));
	let mfaCode = $state('');
	let recoveryCodes = $state(/** @type {string[]} */ ([]));
	let mfaBusy = $state(false);

	async function loadMfa() {
		mfa = await api.mfaStatus().catch(() => null);
	}
	onMount(loadMfa);

	async function startSetup() {
		mfaBusy = true;
		try {
			const s = await api.mfaSetup();
			setup = { ...s, qr: await QRCode.toDataURL(s.otpauth_url, { margin: 1, width: 192 }) };
			mfaCode = '';
		} catch (err) {
			notify(errorText(err));
		} finally {
			mfaBusy = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function enable(e) {
		e.preventDefault();
		mfaBusy = true;
		try {
			recoveryCodes = (await api.mfaEnable(mfaCode)).recovery_codes;
			setup = null;
			mfaCode = '';
			await loadMfa();
			notify($t('account.mfaOnToast'), 'success');
		} catch (err) {
			notify(errorText(err));
		} finally {
			mfaBusy = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function disable(e) {
		e.preventDefault();
		mfaBusy = true;
		try {
			await api.mfaDisable(mfaCode);
			mfaCode = '';
			recoveryCodes = [];
			await loadMfa();
			notify($t('account.mfaOffToast'), 'success');
		} catch (err) {
			notify(errorText(err));
		} finally {
			mfaBusy = false;
		}
	}

	async function signOutEverywhere() {
		if (!confirm($t('account.confirmSignOut'))) return;
		revoking = true;
		try {
			adopt(await api.revokeSessions());
			notify($t('account.signedOutElsewhere'), 'success');
		} catch (err) {
			notify(errorText(err));
		} finally {
			revoking = false;
		}
	}
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('account.title')}</h1>
	<p class="text-sm text-base-content/60">{$me?.email ?? ''}</p>
</div>

<div class="grid gap-4 md:grid-cols-2">
	<div class="card bg-base-100 shadow-sm">
		<form class="card-body gap-3" onsubmit={changePassword}>
			<h2 class="card-title text-base">{hasPassword ? $t('account.changePassword') : $t('account.setPassword')}</h2>
			{#if !hasPassword}
				<p class="text-xs text-base-content/60">
					{$t('account.ssoOnly')}
				</p>
			{:else if $me?.password_changed_at}
				<p class="text-xs text-base-content/60">
					{$t('account.lastChanged', { date: fmtDate($me.password_changed_at) })}
				</p>
			{/if}
			{#if hasPassword}
				<Field label={$t('account.currentPassword')} required>
					<input type="password" bind:value={current} required autocomplete="current-password" class="input input-bordered input-sm w-full" />
				</Field>
			{/if}
			<Field label={$t('account.newPassword')} required hint={$t('account.newPasswordHint')}>
				<input type="password" bind:value={next} required minlength="8" autocomplete="new-password" class="input input-bordered input-sm w-full" />
			</Field>
			<Field label={$t('account.repeatPassword')} required>
				<input type="password" bind:value={repeat} required minlength="8" autocomplete="new-password" class="input input-bordered input-sm w-full" class:input-error={mismatch} />
			</Field>
			{#if mismatch}<span class="text-xs text-error">{$t('reset.mismatch')}</span>{/if}
			<p class="text-xs text-base-content/50">{$t('account.changeSignsOut')}</p>
			<div class="card-actions justify-end">
				<button class="btn btn-primary btn-sm" disabled={saving || mismatch}>
					{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}
					{$t('common.save')}
				</button>
			</div>
		</form>
	</div>

	<div class="card bg-base-100 shadow-sm">
		<div class="card-body gap-3">
			<h2 class="card-title text-base">{$t('account.sessions')}</h2>
			<p class="text-sm text-base-content/70">
				{$t('account.sessionsIntro')} <a href="/tokens" class="link">{$t('nav.apiKeys')}</a>.
			</p>
			<div class="card-actions justify-end">
				<button class="btn btn-warning btn-sm" disabled={revoking} onclick={signOutEverywhere}>
					{#if revoking}<span class="loading loading-spinner loading-xs"></span>{/if}
					{$t('account.signOutElsewhere')}
				</button>
			</div>
		</div>
	</div>

	{#if isOn($features, 'mfa')}
	<div class="card bg-base-100 shadow-sm md:col-span-2">
		<div class="card-body gap-3">
			<h2 class="card-title text-base">
				{$t('account.mfaTitle')}
				{#if mfa?.enabled}<span class="badge badge-success badge-sm">{$t('account.on')}</span>{:else if mfa}<span class="badge badge-ghost badge-sm">{$t('account.off')}</span>{/if}
			</h2>
			<p class="text-sm text-base-content/70">
				{$t('account.mfaIntro')}
			</p>

			{#if recoveryCodes.length > 0}
				<div class="alert alert-warning items-start">
					<div>
						<p class="font-semibold">{$t('account.saveCodes')}</p>
						<p class="text-xs mb-2">{$t('account.codesUse')}</p>
						<div class="grid grid-cols-2 gap-x-6 font-mono text-sm sm:grid-cols-5">
							{#each recoveryCodes as c (c)}<span>{c}</span>{/each}
						</div>
					</div>
				</div>
			{/if}

			{#if mfa?.enabled}
				<p class="text-xs text-base-content/60">{$t('account.codesLeft', { count: mfa.recovery_codes_left })}</p>
				<form class="flex flex-wrap items-end gap-2" onsubmit={disable}>
					<Field label={$t('account.codeOrRecovery')}>
						<input bind:value={mfaCode} required autocomplete="one-time-code" class="input input-bordered input-sm w-48 font-mono" />
					</Field>
					<button class="btn btn-sm btn-outline btn-error" disabled={mfaBusy}>{$t('account.turnOff')}</button>
				</form>
			{:else if setup}
				<div class="flex flex-wrap items-start gap-6">
					<img src={setup.qr} alt={$t('account.qrAlt')} class="rounded-box border border-base-300" width="192" height="192" />
					<form class="flex flex-col gap-2 max-w-sm" onsubmit={enable}>
						<p class="text-sm">{$t('account.scan')}</p>
						<code class="text-xs break-all bg-base-200 rounded p-2">{setup.secret}</code>
						<Field label={$t('account.codeFromApp')} required>
							<input bind:value={mfaCode} required autocomplete="one-time-code" inputmode="numeric" placeholder="123456" class="input input-bordered input-sm w-40 font-mono" />
						</Field>
						<div class="flex gap-2">
							<button class="btn btn-primary btn-sm" disabled={mfaBusy}>{$t('account.turnOn')}</button>
							<button type="button" class="btn btn-ghost btn-sm" onclick={() => (setup = null)}>{$t('common.cancel')}</button>
						</div>
					</form>
				</div>
			{:else if mfa && !mfa.available}
				<div class="alert alert-warning text-sm py-2">{$t('account.mfaUnavailable')}</div>
			{:else if mfa}
				<div><button class="btn btn-sm" disabled={mfaBusy} onclick={startSetup}>{$t('account.setupMfa')}</button></div>
			{/if}
		</div>
	</div>
	{/if}
	<div class="card bg-base-100 shadow-sm md:col-span-2">
		<div class="card-body gap-3">
			<h2 class="card-title text-base">{$t('account.language')}</h2>
			<p class="text-sm text-base-content/70">{$t('account.languageIntro')}</p>
			<div class="join">
				{#each LOCALES as l (l.id)}
					<button type="button" class="btn btn-sm join-item" class:btn-active={$locale === l.id} aria-pressed={$locale === l.id}
						onclick={() => locale.set(l.id)}>{l.label}</button>
				{/each}
			</div>
		</div>
	</div>
	{#if isOn($features, 'personal_notifications')}<MyNotifications />{/if}
</div>
