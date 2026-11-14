<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, ApiError } from '#lib/api.js';
	import { token } from '#lib/stores.js';
	import { t, locale, LOCALES } from '#lib/i18n.js';

	// Why an SSO login bounced back here (/login?error=<code>).
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const ssoErrors = {
		sso_failed: 'login.sso_failed',
		sso_no_account: 'login.sso_no_account',
		sso_email_unverified: 'login.sso_email_unverified',
		sso_identity_conflict: 'login.sso_identity_conflict',
		sso_no_email: 'login.sso_no_email',
		sso_account_disabled: 'login.sso_account_disabled'
	};

	let mode = $state('login'); // 'login' | 'register' | 'forgot'
	let resetSent = $state(false);
	// Two-factor: after the password, the challenge and the code typed.
	let mfaToken = $state('');
	let mfaCode = $state('');
	let email = $state('');
	let password = $state('');
	let loading = $state(false);
	let error = $state('');
	/** @typedef {{ password_login_enabled: boolean, password_reset_email?: boolean, directory_login?: boolean, providers: { kind: string, name: string, login_url: string }[] }} AuthConfig */
	let config = $state(/** @type {AuthConfig | null} */ (null));
	let ownerLogin = $state(false); // reveals the password form when it is disabled (break-glass)

	let ssoError = $derived(page.url.searchParams.get('error'));
	let providers = $derived(config?.providers ?? []);
	let passwordForm = $derived(config === null || config.password_login_enabled || config.directory_login || ownerLogin);

	onMount(async () => {
		try {
			config = await api.authConfig();
		} catch {
			config = { password_login_enabled: true, providers: [] };
		}
	});

	/** @param {SubmitEvent} e */
	async function submitCode(e) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			const out = await api.verifyMfa(mfaToken, mfaCode);
			token.set(out.token);
			goto('/');
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('login.genericError');
			if (err instanceof ApiError && err.message.includes('expired')) mfaToken = '';
		} finally {
			loading = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function submit(e) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			if (mode === 'forgot') {
				await api.requestPasswordReset(email);
				resetSent = true;
				return;
			}
			if (mode === 'register') {
				await api.register(email, password);
			}
			const out = await api.login(email, password);
			if (out.mfa_required) {
				mfaToken = out.mfa_token;
				return;
			}
			token.set(out.token);
			goto('/');
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('login.genericError');
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-[70vh] flex items-center justify-center">
	<div class="card w-full max-w-sm bg-base-100 shadow-xl">
		<div class="card-body">
			<div class="text-center mb-2">
				<div class="text-3xl text-primary">◈</div>
				<h1 class="text-2xl font-bold">Xila</h1>
				<p class="text-sm text-base-content/60">{$t('login.tagline')}</p>
			</div>

			{#if ssoError}
				<div class="alert alert-error py-2 text-sm mb-2">
					<span>{$t(ssoErrors[ssoError] ?? ssoErrors.sso_failed)}</span>
				</div>
			{/if}

			{#if providers.length > 0}
				<div class="flex flex-col gap-2">
					{#each providers as p (p.login_url)}
						<a href={p.login_url} class="btn btn-primary w-full" data-sveltekit-reload>
							{$t('login.continueWith', { name: p.name })}
						</a>
					{/each}
				</div>
			{/if}

			{#if mfaToken}
				<form onsubmit={submitCode} class="flex flex-col gap-3">
					<p class="text-sm text-base-content/70">
						{$t('login.mfaPrompt')}
					</p>
					<input
						bind:value={mfaCode}
						required
						autocomplete="one-time-code"
						inputmode="numeric"
						placeholder="123456"
						class="input input-bordered w-full text-center font-mono text-lg tracking-widest"
						aria-label={$t('login.mfaCode')}
					/>
					{#if error}
						<div class="alert alert-error py-2 text-sm"><span>{error}</span></div>
					{/if}
					<button class="btn btn-primary" disabled={loading || !mfaCode.trim()}>
						{#if loading}<span class="loading loading-spinner loading-sm"></span>{/if}
						{$t('login.verify')}
					</button>
					<button type="button" class="btn btn-link btn-xs text-base-content/50" onclick={() => ((mfaToken = ''), (mfaCode = ''), (error = ''))}>
						{$t('login.back')}
					</button>
				</form>
			{:else if passwordForm}
				{#if providers.length > 0}
					<div class="divider text-xs text-base-content/50 my-3">{$t('login.or')}</div>
				{/if}

				{#if mode === 'forgot'}
					<p class="text-sm text-base-content/70 mb-2">
						{$t('login.forgotIntro')}
					</p>
				{:else if config?.password_login_enabled}
					<div role="tablist" class="tabs tabs-boxed mb-2">
						<button
							role="tab"
							class="tab"
							class:tab-active={mode === 'login'}
							onclick={() => (mode = 'login')}>{$t('login.signIn')}</button
						>
						<button
							role="tab"
							class="tab"
							class:tab-active={mode === 'register'}
							onclick={() => (mode = 'register')}>{$t('login.register')}</button
						>
					</div>
				{:else if config?.directory_login && !ownerLogin}
					<p class="text-xs text-base-content/60 mb-2">{$t('login.directory')}</p>
				{:else if ownerLogin}
					<p class="text-xs text-base-content/60 mb-2">
						{$t('login.breakGlass')}
					</p>
				{/if}

				<form onsubmit={submit} class="flex flex-col gap-3">
					<label class="form-control">
						<span class="label-text mb-1">{config?.directory_login && mode === 'login' ? $t('login.emailOrUsername') : $t('login.email')}</span>
						<input
							type={config?.directory_login && mode === 'login' ? 'text' : 'email'}
							autocomplete="username"
							bind:value={email}
							required
							placeholder="you@company.com"
							class="input input-bordered w-full"
						/>
					</label>
					{#if mode !== 'forgot'}
						<label class="form-control">
							<span class="label-text mb-1">{$t('login.password')}</span>
							<input
								type="password"
								bind:value={password}
								required
								minlength="8"
								placeholder={$t('login.passwordPlaceholder')}
								class="input input-bordered w-full"
							/>
						</label>
					{/if}

					{#if error}
						<div class="alert alert-error py-2 text-sm"><span>{error}</span></div>
					{/if}

					{#if resetSent && mode === 'forgot'}
						<div class="alert alert-success py-2 text-sm">
							<span>{$t('login.resetSent')}</span>
						</div>
					{/if}

					<button class="btn {providers.length > 0 ? 'btn-outline' : 'btn-primary'}" disabled={loading || (mode === 'forgot' && resetSent)}>
						{#if loading}<span class="loading loading-spinner loading-sm"></span>{/if}
						{mode === 'login' ? $t('login.signIn') : mode === 'register' ? $t('login.createAccount') : $t('login.sendReset')}
					</button>
				</form>
				{#if mode === 'forgot'}
					<button class="btn btn-link btn-xs mt-1 text-base-content/50" onclick={() => ((mode = 'login'), (resetSent = false))}>
						{$t('login.backToSignIn')}
					</button>
				{:else if mode === 'login' && config?.password_reset_email}
					<button class="btn btn-link btn-xs mt-1 text-base-content/50" onclick={() => ((mode = 'forgot'), (error = ''))}>
						{$t('login.forgot')}
					</button>
				{/if}
			{:else}
				<button class="btn btn-link btn-xs mt-3 text-base-content/50" onclick={() => (ownerLogin = true)}>
					{$t('login.ownerSignIn')}
				</button>
			{/if}
			<select class="select select-ghost select-xs mx-auto mt-2 w-auto" bind:value={$locale} aria-label={$t('nav.language')}>
				{#each LOCALES as l (l.id)}<option value={l.id}>{l.label}</option>{/each}
			</select>
		</div>
	</div>
</div>
