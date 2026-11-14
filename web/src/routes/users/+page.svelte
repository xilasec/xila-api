<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify, me, features, isOn } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate, fmtDateOnly } from '#lib/format.js';
	import State from '#lib/components/State.svelte';

	/** @typedef {import('#lib/stores.js').User} User */
	let users = $state(/** @type {User[]} */ ([]));
	let loading = $state(true);
	let busy = $state('');
	let newEmail = $state('');
	let adding = $state(false);

	async function load() {
		loading = true;
		try {
			users = await api.listUsers();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {User} u */
	async function toggleAdmin(u) {
		busy = u.id;
		try {
			await api.setUserAdmin(u.id, !u.is_admin);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	// Pre-provision a passwordless account: their first SSO login links to it.
	/** @param {SubmitEvent} e */
	async function addUser(e) {
		e.preventDefault();
		adding = true;
		try {
			await api.createUser(newEmail);
			notify($t('users.added', { email: newEmail }), 'success');
			newEmail = '';
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			adding = false;
		}
	}

	// Run one per-user action with the row busy, then reload.
	/** @param {User} u @param {() => Promise<unknown>} fn @param {string} [done] */
	async function act(u, fn, done) {
		busy = u.id;
		try {
			await fn();
			if (done) notify(done, 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	/** @param {User} u */
	const deactivate = (u) =>
		confirm($t('users.deactivateConfirm', { email: u.email })) &&
		act(u, () => api.deactivateUser(u.id), $t('users.deactivated', { email: u.email }));
	/** @param {User} u */
	const reactivate = (u) => act(u, () => api.reactivateUser(u.id), $t('users.reactivated', { email: u.email }));
	/** @param {User} u */
	const resetMfa = (u) =>
		confirm($t('users.resetMfaConfirm', { email: u.email })) &&
		act(u, () => api.resetUserMfa(u.id), $t('users.mfaReset', { email: u.email }));
	/** @param {User} u */
	const remove = (u) =>
		confirm($t('users.deleteConfirm', { email: u.email })) &&
		act(u, () => api.deleteUser(u.id), $t('users.deleted', { email: u.email }));

	// A single-use link (24h) to hand over out of band: no SMTP needed.
	let resetLink = $state(/** @type {{ email: string, url: string, expires_at: string } | null} */ (null));
	/** @param {User} u */
	async function mintResetLink(u) {
		busy = u.id;
		try {
			const out = await api.passwordResetLink(u.id);
			const url = out.url.startsWith('/') ? window.location.origin + out.url : out.url;
			resetLink = { email: u.email, url, expires_at: out.expires_at };
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}
	async function copyResetLink() {
		if (resetLink) await navigator.clipboard.writeText(resetLink.url);
		notify($t('common.copied'), 'success');
	}

	/** @param {User} u */
	async function transfer(u) {
		if (!confirm($t('users.transferConfirm', { email: u.email }))) return;
		busy = u.id;
		try {
			await api.transferOwnership(u.id);
			notify($t('users.transferred', { email: u.email }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('users.title')}</h1>
	<p class="text-sm text-base-content/60">
		{$t('users.introPre')} <span class="font-medium">{$t('users.owner')}</span>
		{$t('users.introMid')} <span class="font-medium">{$t('users.members')}</span> {$t('users.introPost')}
	</p>
</div>

<form onsubmit={addUser} class="flex flex-wrap items-end gap-2 mb-4">
	<label class="form-control">
		<span class="label-text mb-1 text-xs">{$t('users.addSsoLabel')}</span>
		<input type="email" bind:value={newEmail} required placeholder="dana@company.com" class="input input-bordered input-sm w-72" />
	</label>
	<button class="btn btn-sm" disabled={adding || !newEmail}>{$t('users.addButton')}</button>
</form>

<State {loading} empty={!loading && users.length === 0} emptyText={$t('users.empty')} />
{#if !loading && users.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table">
			<thead><tr><th>{$t('users.colEmail')}</th><th>{$t('users.colRole')}</th><th>{$t('users.colJoined')}</th><th></th></tr></thead>
			<tbody>
				{#each users as u (u.id)}
					<tr class="hover">
						<td class="font-medium" class:opacity-50={u.disabled_at}>
							{u.email}
							{#if u.disabled_at}<span class="badge badge-error badge-outline badge-sm ml-1" title={$t('users.deactivatedAt', { date: fmtDate(u.disabled_at) })}>{$t('users.deactivatedBadge')}</span>{/if}
							{#if !u.has_password}<span class="badge badge-ghost badge-sm ml-1" title={$t('users.ssoOnlyTitle')}>{$t('users.ssoOnlyBadge')}</span>{/if}
							{#if u.mfa_enabled}<span class="badge badge-success badge-outline badge-sm ml-1" title={$t('users.mfaTitle')}>{$t('users.mfaBadge')}</span>{/if}
						</td>
						<td>
							{#if u.is_owner}<span class="badge badge-secondary badge-sm" title={$t('users.ownerTitle')}>{$t('users.ownerBadge')}</span>
							{:else if u.is_admin}<span class="badge badge-primary badge-sm">{$t('users.adminBadge')}</span>
								{#if u.admin_source === 'sso'}<span class="badge badge-ghost badge-sm" title={$t('users.viaSsoTitle')}>{$t('users.viaSsoBadge')}</span>{/if}
							{:else}<span class="badge badge-ghost badge-sm">{$t('users.memberBadge')}</span>{/if}
						</td>
						<td class="text-xs text-base-content/50">{fmtDateOnly(u.created_at)}</td>
						<td class="text-right">
							{#if u.is_owner}
								<span class="text-xs text-base-content/40">
									{u.id === $me?.id ? $t('users.youOwner') : $t('users.protected')}
								</span>
							{:else}
								<div class="flex justify-end gap-1">
									<button class="btn btn-ghost btn-xs" disabled={busy === u.id} onclick={() => toggleAdmin(u)}>
										{u.is_admin ? $t('users.revokeAdmin') : $t('users.makeAdmin')}
									</button>
									{#if u.id !== $me?.id}
										{#if u.disabled_at}
											<button class="btn btn-ghost btn-xs" disabled={busy === u.id} onclick={() => reactivate(u)}>{$t('users.reactivateButton')}</button>
										{:else}
											<button class="btn btn-ghost btn-xs" disabled={busy === u.id} onclick={() => mintResetLink(u)} title={$t('users.resetLinkTitle')}>{$t('users.resetLinkButton')}</button>
											{#if u.mfa_enabled && isOn($features, 'mfa')}<button class="btn btn-ghost btn-xs" disabled={busy === u.id} onclick={() => resetMfa(u)} title={$t('users.resetMfaTitle')}>{$t('users.resetMfaButton')}</button>{/if}
											<button class="btn btn-ghost btn-xs text-warning" disabled={busy === u.id} onclick={() => deactivate(u)}>{$t('users.deactivateButton')}</button>
										{/if}
										<button class="btn btn-ghost btn-xs text-error" disabled={busy === u.id} onclick={() => remove(u)}>{$t('users.deleteButton')}</button>
									{/if}
									{#if $me?.is_owner && u.id !== $me?.id && !u.disabled_at}
										<button class="btn btn-ghost btn-xs text-warning" disabled={busy === u.id} onclick={() => transfer(u)}>
											{$t('users.makeOwnerButton')}
										</button>
									{/if}
								</div>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if resetLink}
	<dialog class="modal modal-open">
		<div class="modal-box">
			<h3 class="font-bold text-lg">{$t('users.resetDialogTitle', { email: resetLink.email })}</h3>
			<p class="text-sm text-base-content/70 my-2">
				{$t('users.resetDialogIntro', { date: fmtDate(resetLink.expires_at) })}
			</p>
			<input class="input input-bordered input-sm w-full font-mono text-xs" readonly value={resetLink.url} onfocus={(e) => e.currentTarget.select()} />
			<div class="modal-action">
				<button class="btn btn-ghost btn-sm" onclick={copyResetLink}>{$t('common.copy')}</button>
				<button class="btn btn-sm" onclick={() => (resetLink = null)}>{$t('common.close')}</button>
			</div>
		</div>
	</dialog>
{/if}
