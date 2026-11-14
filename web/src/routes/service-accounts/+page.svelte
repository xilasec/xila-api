<script>
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { fmtDate } from '#lib/format.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	let loading = $state(true);
	let error = $state('');
	let accounts = $state(/** @type {any[]} */ ([]));
	let issuers = $state(/** @type {any[]} */ ([]));
	let bindings = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			[accounts, issuers, bindings, projects] = await Promise.all([
				api.listServiceAccounts(),
				api.listFederationIssuers(),
				api.listFederationBindings(),
				api.listProjects()
			]);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('svcacct.loadFailed');
		} finally {
			loading = false;
		}
	}

	onMount(load);

	/** @param {string | null} pid */
	const projectName = (pid) => (pid ? (projects.find((p) => p.id === pid)?.name ?? pid) : $t('svcacct.allItsProjects'));

	// --- service accounts ---
	/** @type {HTMLDialogElement} */
	let accountDialog;
	let accountForm = $state({ name: '', description: '' });

	function openAccount() {
		accountForm = { name: '', description: '' };
		accountDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function createAccount(e) {
		e.preventDefault();
		saving = true;
		try {
			const a = await api.createServiceAccount({ name: accountForm.name.trim(), description: accountForm.description.trim() });
			accountDialog.close();
			notify($t('svcacct.created', { email: a.email }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} a */
	async function toggleSuspend(a) {
		const suspending = !a.suspended_at;
		if (suspending && !confirm($t('svcacct.suspendConfirm', { name: a.name }))) return;
		try {
			await (suspending ? api.suspendServiceAccount(a.id) : api.resumeServiceAccount(a.id));
			notify(suspending ? $t('svcacct.suspended') : $t('svcacct.resumed'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} a */
	async function removeAccount(a) {
		if (!confirm($t('svcacct.removeAccountConfirm', { name: a.name }))) return;
		try {
			await api.deleteServiceAccount(a.id);
			notify($t('svcacct.accountDeleted'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// --- keys ---
	/** @type {HTMLDialogElement} */
	let keysDialog;
	let keysFor = $state(/** @type {any} */ (null));
	let keys = $state(/** @type {any[]} */ ([]));
	let keyForm = $state({ name: '', project_id: '', expires_in_days: '' });
	let createdKey = $state(/** @type {any} */ (null)); // { key, secret }

	/** @param {any} a */
	async function openKeys(a) {
		keysFor = a;
		keyForm = { name: '', project_id: '', expires_in_days: '' };
		createdKey = null;
		try {
			keys = await api.listServiceAccountKeys(a.id);
			keysDialog.showModal();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {SubmitEvent} e */
	async function createKey(e) {
		e.preventDefault();
		saving = true;
		try {
			createdKey = await api.createServiceAccountKey(keysFor.id, {
				name: keyForm.name.trim(),
				project_id: keyForm.project_id || null,
				expires_in_days: Number(keyForm.expires_in_days) || 0
			});
			keys = await api.listServiceAccountKeys(keysFor.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} k */
	async function revokeKey(k) {
		if (!confirm($t('svcacct.revokeKeyConfirm', { name: k.name }))) return;
		try {
			await api.deleteServiceAccountKey(keysFor.id, k.id);
			keys = await api.listServiceAccountKeys(keysFor.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function copyKey() {
		try {
			await navigator.clipboard.writeText(createdKey.secret);
			notify($t('svcacct.copied'), 'success');
		} catch {
			notify($t('svcacct.copyFailed'), 'warning');
		}
	}

	// --- issuers ---
	/** @type {HTMLDialogElement} */
	let issuerDialog;
	let issuerForm = $state({ id: '', name: '', issuer_url: '', audience: '', enabled: true });

	/** @param {any} [i] */
	function openIssuer(i) {
		issuerForm = i
			? { id: i.id, name: i.name, issuer_url: i.issuer_url, audience: i.audience, enabled: i.enabled }
			: { id: '', name: 'GitHub Actions', issuer_url: 'https://token.actions.githubusercontent.com', audience: location.origin, enabled: true };
		issuerDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function saveIssuer(e) {
		e.preventDefault();
		saving = true;
		const { id, ...data } = issuerForm;
		try {
			await (id ? api.updateFederationIssuer(id, data) : api.createFederationIssuer(data));
			issuerDialog.close();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} i */
	async function testIssuer(i) {
		try {
			const res = await api.testFederationIssuer(i.id);
			notify(res.ok ? $t('svcacct.testOk', { name: i.name }) : $t('svcacct.testFailed', { name: i.name, error: res.error }), res.ok ? 'success' : 'error');
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} i */
	async function removeIssuer(i) {
		if (!confirm($t('svcacct.removeIssuerConfirm', { name: i.name }))) return;
		try {
			await api.deleteFederationIssuer(i.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// --- bindings ---
	/** @type {HTMLDialogElement} */
	let bindingDialog;
	let bindingForm = $state({
		id: '',
		name: '',
		issuer_id: '',
		service_account_id: '',
		project_id: '',
		enabled: true,
		conditions: /** @type {{claim: string, value: string}[]} */ ([])
	});

	/** @param {any} [b] */
	function openBinding(b) {
		bindingForm = b
			? {
					id: b.id,
					name: b.name,
					issuer_id: b.issuer_id,
					service_account_id: b.service_account_id,
					project_id: b.project_id ?? '',
					enabled: b.enabled,
					conditions: Object.entries(b.conditions).map(([claim, value]) => ({ claim, value: String(value) }))
				}
			: {
					id: '',
					name: '',
					issuer_id: issuers[0]?.id ?? '',
					service_account_id: accounts[0]?.id ?? '',
					project_id: '',
					enabled: true,
					conditions: [
						{ claim: 'repository', value: '' },
						{ claim: 'ref', value: 'refs/heads/main' }
					]
				};
		bindingDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function saveBinding(e) {
		e.preventDefault();
		saving = true;
		const { id, conditions, ...rest } = bindingForm;
		/** @type {Record<string, string>} */
		const conds = {};
		for (const c of conditions) if (c.claim.trim()) conds[c.claim.trim()] = c.value.trim();
		const data = { ...rest, project_id: rest.project_id || null, conditions: conds };
		try {
			await (id ? api.updateFederationBinding(id, data) : api.createFederationBinding(data));
			bindingDialog.close();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} b */
	async function removeBinding(b) {
		if (!confirm($t('svcacct.removeBindingConfirm', { name: b.name }))) return;
		try {
			await api.deleteFederationBinding(b.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('svcacct.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('svcacct.intro')}
		</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openAccount}>{$t('svcacct.newButton')}</button>
</div>

<State {loading} {error} />

{#if !loading && !error}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mt-4">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('svcacct.colName')}</th><th>{$t('svcacct.colEmail')}</th><th>{$t('svcacct.colKeys')}</th><th>{$t('svcacct.colCreated')}</th><th>{$t('svcacct.colStatus')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each accounts as a (a.id)}
					<tr class="hover">
						<td>
							<div class="font-medium">{a.name}</div>
							{#if a.description}<div class="text-xs text-base-content/60">{a.description}</div>{/if}
						</td>
						<td class="font-mono text-xs">{a.email}</td>
						<td class="text-xs">{a.active_keys}</td>
						<td class="text-xs text-base-content/60">{fmtDate(a.created_at)}</td>
						<td>
							{#if a.suspended_at}
								<span class="badge badge-error badge-sm">{$t('svcacct.suspendedBadge')}</span>
							{:else}
								<span class="badge badge-success badge-sm">{$t('svcacct.activeBadge')}</span>
							{/if}
						</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => openKeys(a)}>{$t('svcacct.keysButton')}</button>
							<button class="btn btn-ghost btn-xs" onclick={() => toggleSuspend(a)}>{a.suspended_at ? $t('svcacct.resumeButton') : $t('svcacct.suspendButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => removeAccount(a)}>{$t('svcacct.deleteButton')}</button>
						</td>
					</tr>
				{:else}
					<tr><td colspan="6" class="text-center text-base-content/50">{$t('svcacct.empty')}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>

	<div class="flex items-center justify-between mt-10 mb-2">
		<div>
			<h2 class="text-xl font-bold">{$t('svcacct.issuersTitle')}</h2>
			<p class="text-sm text-base-content/60">
				{$t('svcacct.issuersIntroPre')} <code>POST /api/v1/auth/token</code> {$t('svcacct.issuersIntroPost')}
			</p>
		</div>
		<button class="btn btn-sm" onclick={() => openIssuer()}>{$t('svcacct.addIssuerButton')}</button>
	</div>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('svcacct.colName')}</th><th>{$t('svcacct.colIssuerUrl')}</th><th>{$t('svcacct.colAudience')}</th><th>{$t('svcacct.colStatus')}</th><th></th></tr></thead>
			<tbody>
				{#each issuers as i (i.id)}
					<tr class="hover">
						<td class="font-medium">{i.name}</td>
						<td class="font-mono text-xs">{i.issuer_url}</td>
						<td class="font-mono text-xs">{i.audience}</td>
						<td>
							<span class="badge badge-sm {i.enabled ? 'badge-success' : 'badge-ghost'}">{i.enabled ? $t('svcacct.enabledBadge') : $t('svcacct.disabledBadge')}</span>
						</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => testIssuer(i)}>{$t('svcacct.testButton')}</button>
							<button class="btn btn-ghost btn-xs" onclick={() => openIssuer(i)}>{$t('svcacct.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => removeIssuer(i)}>{$t('svcacct.deleteButton')}</button>
						</td>
					</tr>
				{:else}
					<tr><td colspan="5" class="text-center text-base-content/50">{$t('svcacct.noIssuers')}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>

	<div class="flex items-center justify-between mt-10 mb-2">
		<div>
			<h2 class="text-xl font-bold">{$t('svcacct.bindingsTitle')}</h2>
			<p class="text-sm text-base-content/60">
				{$t('svcacct.bindingsIntroPre')}<code>*</code> {$t('svcacct.bindingsIntroMid1')} <code>/</code> {$t('svcacct.bindingsIntroMid2')} <code>**</code> {$t('svcacct.bindingsIntroMid3')} <code>repository</code> {$t('svcacct.bindingsIntroOr')} <code>project_path</code> {$t('svcacct.bindingsIntroPost')}
			</p>
		</div>
		<button class="btn btn-sm" disabled={issuers.length === 0 || accounts.length === 0} onclick={() => openBinding()}>{$t('svcacct.addBindingButton')}</button>
	</div>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('svcacct.colName')}</th><th>{$t('svcacct.colIssuer')}</th><th>{$t('svcacct.colConditions')}</th><th>{$t('svcacct.colServiceAccount')}</th><th>{$t('svcacct.colProject')}</th><th></th></tr></thead>
			<tbody>
				{#each bindings as b (b.id)}
					<tr class="hover" class:opacity-50={!b.enabled}>
						<td class="font-medium">{b.name}</td>
						<td class="text-xs">{b.issuer_name}</td>
						<td class="font-mono text-xs">
							{#each Object.entries(b.conditions) as [claim, value]}<div>{claim} = {value}</div>{/each}
						</td>
						<td class="text-xs">{b.service_account_name}</td>
						<td class="text-xs">{projectName(b.project_id)}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => openBinding(b)}>{$t('svcacct.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => removeBinding(b)}>{$t('svcacct.deleteButton')}</button>
						</td>
					</tr>
				{:else}
					<tr><td colspan="6" class="text-center text-base-content/50">{$t('svcacct.noBindings')}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<dialog bind:this={accountDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('svcacct.newAccountTitle')}</h3>
		<form onsubmit={createAccount} class="flex flex-col gap-3">
			<Field label={$t('svcacct.nameLabel')} required hint={$t('svcacct.nameHint', { email: '<name>@service-accounts.invalid' })}>
				<input bind:value={accountForm.name} required pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?" placeholder="ci-web" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('svcacct.descriptionLabel')}>
				<input bind:value={accountForm.description} placeholder={$t('svcacct.descriptionPlaceholder')} class="input input-bordered w-full" />
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => accountDialog.close()}>{$t('svcacct.cancelButton')}</button>
				<button class="btn btn-primary" disabled={saving}>{$t('svcacct.createButton')}</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<dialog bind:this={keysDialog} class="modal">
	<div class="modal-box max-w-2xl">
		<h3 class="font-bold text-lg mb-2">{$t('svcacct.keysDialogTitle', { name: keysFor?.name })}</h3>
		{#if createdKey}
			<div class="alert alert-warning py-2 text-sm mb-2"><span>{$t('svcacct.copyNowWarning')}</span></div>
			<div class="join w-full mb-4">
				<input readonly value={createdKey.secret} class="input input-bordered input-sm join-item flex-1 font-mono text-xs" />
				<button class="btn btn-sm join-item" onclick={copyKey}>{$t('common.copy')}</button>
			</div>
		{/if}
		<table class="table table-sm mb-4">
			<thead><tr><th>{$t('svcacct.colName')}</th><th>{$t('svcacct.colPrefix')}</th><th>{$t('svcacct.colScope')}</th><th>{$t('svcacct.colLastUsed')}</th><th>{$t('svcacct.colExpires')}</th><th></th></tr></thead>
			<tbody>
				{#each keys as k (k.id)}
					<tr>
						<td>{k.name}</td>
						<td class="font-mono text-xs">{k.prefix}…</td>
						<td class="text-xs">{projectName(k.project_id)}</td>
						<td class="text-xs">{k.last_used_at ? fmtDate(k.last_used_at) : $t('common.never')}</td>
						<td class="text-xs">{fmtDate(k.expires_at)}</td>
						<td class="text-right"><button class="btn btn-ghost btn-xs text-error" onclick={() => revokeKey(k)}>{$t('svcacct.revokeButton')}</button></td>
					</tr>
				{:else}
					<tr><td colspan="6" class="text-center text-base-content/50">{$t('svcacct.noKeys')}</td></tr>
				{/each}
			</tbody>
		</table>
		{#if keysFor?.suspended_at}
			<p class="text-sm text-base-content/60">{$t('svcacct.resumeToIssue')}</p>
		{:else}
			<form onsubmit={createKey} class="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
				<Field label={$t('svcacct.keyNameLabel')} required>
					<input bind:value={keyForm.name} required placeholder={$t('svcacct.keyNamePlaceholder')} class="input input-bordered input-sm w-full" />
				</Field>
				<Field label={$t('svcacct.scopeLabel')}>
					<select bind:value={keyForm.project_id} class="select select-bordered select-sm w-full">
						<option value="">{$t('svcacct.allItsProjectsLower')}</option>
						{#each projects as p}<option value={p.id}>{p.name}</option>{/each}
					</select>
				</Field>
				<Field label={$t('svcacct.expiresInLabel')} hint={$t('svcacct.expiresInHint')}>
					<input bind:value={keyForm.expires_in_days} type="number" min="1" placeholder="30" class="input input-bordered input-sm w-full" />
				</Field>
				<div class="sm:col-span-3 flex justify-end">
					<button class="btn btn-primary btn-sm" disabled={saving}>{$t('svcacct.issueKeyButton')}</button>
				</div>
			</form>
		{/if}
		<div class="modal-action">
			<button class="btn" onclick={() => keysDialog.close()}>{$t('svcacct.closeButton')}</button>
		</div>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<dialog bind:this={issuerDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{issuerForm.id ? $t('svcacct.editIssuerTitle') : $t('svcacct.trustIssuerTitle')}</h3>
		<form onsubmit={saveIssuer} class="flex flex-col gap-3">
			<Field label={$t('svcacct.nameLabel')} required>
				<input bind:value={issuerForm.name} required class="input input-bordered w-full" />
			</Field>
			<Field label={$t('svcacct.issuerUrlLabel')} required hint={$t('svcacct.issuerUrlHint')}>
				<input bind:value={issuerForm.issuer_url} required type="url" class="input input-bordered w-full font-mono text-sm" />
			</Field>
			<Field label={$t('svcacct.audienceLabel')} required hint={$t('svcacct.audienceHint')}>
				<input bind:value={issuerForm.audience} required class="input input-bordered w-full font-mono text-sm" />
			</Field>
			<label class="label cursor-pointer justify-start gap-2">
				<input type="checkbox" bind:checked={issuerForm.enabled} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('svcacct.enabledLabel')}</span>
			</label>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => issuerDialog.close()}>{$t('svcacct.cancelButton')}</button>
				<button class="btn btn-primary" disabled={saving}>{$t('svcacct.saveButton')}</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<dialog bind:this={bindingDialog} class="modal">
	<div class="modal-box max-w-2xl">
		<h3 class="font-bold text-lg mb-4">{bindingForm.id ? $t('svcacct.editBindingTitle') : $t('svcacct.newBindingTitle')}</h3>
		<form onsubmit={saveBinding} class="flex flex-col gap-3">
			<Field label={$t('svcacct.nameLabel')} required>
				<input bind:value={bindingForm.name} required placeholder={$t('svcacct.bindingNamePlaceholder')} class="input input-bordered w-full" />
			</Field>
			<div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
				<Field label={$t('svcacct.issuerLabel')} required>
					<select bind:value={bindingForm.issuer_id} required class="select select-bordered w-full">
						{#each issuers as i}<option value={i.id}>{i.name}</option>{/each}
					</select>
				</Field>
				<Field label={$t('svcacct.serviceAccountLabel')} required>
					<select bind:value={bindingForm.service_account_id} required class="select select-bordered w-full">
						{#each accounts as a}<option value={a.id}>{a.name}</option>{/each}
					</select>
				</Field>
				<Field label={$t('svcacct.projectLabel')} hint={$t('svcacct.projectHint')}>
					<select bind:value={bindingForm.project_id} class="select select-bordered w-full">
						<option value="">{$t('svcacct.allItsProjectsLower')}</option>
						{#each projects as p}<option value={p.id}>{p.name}</option>{/each}
					</select>
				</Field>
			</div>
			<div>
				<div class="label-text font-medium mb-1">{$t('svcacct.claimConditionsLabel')} <span class="text-error">*</span></div>
				{#each bindingForm.conditions as c, idx}
					<div class="join w-full mb-2">
						<input bind:value={c.claim} placeholder={$t('svcacct.claimPlaceholder')} class="input input-bordered input-sm join-item w-1/3 font-mono" />
						<input bind:value={c.value} placeholder={$t('svcacct.valuePlaceholder')} class="input input-bordered input-sm join-item flex-1 font-mono" />
						<button type="button" class="btn btn-sm join-item" onclick={() => bindingForm.conditions.splice(idx, 1)}>✕</button>
					</div>
				{/each}
				<button type="button" class="btn btn-ghost btn-xs" onclick={() => bindingForm.conditions.push({ claim: '', value: '' })}>{$t('svcacct.addCondition')}</button>
			</div>
			<label class="label cursor-pointer justify-start gap-2">
				<input type="checkbox" bind:checked={bindingForm.enabled} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('svcacct.enabledLabel')}</span>
			</label>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => bindingDialog.close()}>{$t('svcacct.cancelButton')}</button>
				<button class="btn btn-primary" disabled={saving}>{$t('svcacct.saveButton')}</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
