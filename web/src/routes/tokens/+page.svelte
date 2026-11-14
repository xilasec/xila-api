<script>
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import { fmtDate } from '$lib/format.js';
	import State from '$lib/components/State.svelte';
	import Field from '$lib/components/Field.svelte';

	let loading = $state(true);
	let error = $state('');
	let tokens = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);

	/** @type {HTMLDialogElement} */
	let dialog;
	let form = $state({ name: '', project_id: '', expires_in_days: '' });
	let created = $state(/** @type {any} */ (null)); // { token, secret }
	let copied = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			[tokens, projects] = await Promise.all([api.listTokens(), api.listProjects()]);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('appr.loadFailed');
		} finally {
			loading = false;
		}
	}

	onMount(load);

	/** @param {string} pid */
	const projectName = (pid) => projects.find((p) => p.id === pid)?.name ?? pid;

	function openCreate() {
		form = { name: '', project_id: '', expires_in_days: '' };
		created = null;
		copied = false;
		dialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function create(e) {
		e.preventDefault();
		saving = true;
		try {
			const res = await api.createToken({
				name: form.name.trim(),
				project_id: form.project_id || null,
				expires_in_days: Number(form.expires_in_days) || 0
			});
			created = res; // { token, secret }
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	async function copySecret() {
		try {
			await navigator.clipboard.writeText(created.secret);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			notify($t('tok.copyFailed'), 'warning');
		}
	}

	/** @param {any} tok */
	async function revoke(tok) {
		if (!confirm($t('tok.confirmRevoke', { name: tok.name }))) return;
		try {
			await api.deleteToken(tok.id);
			notify($t('tok.revokedToast'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="flex items-center justify-between mb-6">
	<div>
		<h1 class="text-2xl font-bold">{$t('tok.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('tok.subtitle')}</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openCreate}>{$t('tok.newKey')}</button>
</div>

<State {loading} {error} empty={!loading && !error && tokens.length === 0}
	emptyText={$t('tok.empty')} />

{#if !loading && !error && tokens.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('tok.colName')}</th><th>{$t('tok.colPrefix')}</th><th>{$t('tok.colScope')}</th><th>{$t('tok.colLastUsed')}</th><th>{$t('tok.colExpires')}</th><th></th></tr>
			</thead>
			<tbody>
				{#each tokens as tok (tok.id)}
					<tr class="hover">
						<td class="font-medium">{tok.name}</td>
						<td class="font-mono text-xs">{tok.prefix}…</td>
						<td class="text-xs">
							{#if tok.project_id}
								<span class="badge badge-ghost badge-sm">{projectName(tok.project_id)}</span>
							{:else}
								<span class="text-base-content/50">{$t('tok.allProjects')}</span>
							{/if}
						</td>
						<td class="text-xs text-base-content/60">{tok.last_used_at ? fmtDate(tok.last_used_at) : $t('tok.never')}</td>
						<td class="text-xs text-base-content/60">{tok.expires_at ? fmtDate(tok.expires_at) : $t('tok.never')}</td>
						<td class="text-right">
							<button class="btn btn-ghost btn-xs text-error" onclick={() => revoke(tok)}>{$t('tok.revoke')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<!-- Create / reveal modal -->
<dialog bind:this={dialog} class="modal">
	<div class="modal-box">
		{#if created}
			<h3 class="font-bold text-lg mb-2">{$t('tok.keyCreated')}</h3>
			<div class="alert alert-warning py-2 text-sm mb-3">
				<span>{$t('tok.copyWarning')}</span>
			</div>
			<div class="join w-full mb-4">
				<input readonly value={created.secret} class="input input-bordered input-sm join-item flex-1 font-mono text-xs" />
				<button class="btn btn-sm join-item" onclick={copySecret}>{copied ? $t('tok.copied') : $t('tok.copy')}</button>
			</div>
			<p class="text-xs text-base-content/60 mb-4">
				{$t('tok.bearerHint')}
				<code class="text-xs">curl -H "Authorization: Bearer {created.token.prefix}…"</code>
			</p>
			<div class="modal-action">
				<button class="btn btn-primary" onclick={() => dialog.close()}>{$t('tok.done')}</button>
			</div>
		{:else}
			<h3 class="font-bold text-lg mb-4">{$t('tok.newKeyHeading')}</h3>
			<form onsubmit={create} class="flex flex-col gap-3">
				<Field label={$t('home.name')} required hint={$t('tok.nameHint')}>
					<input bind:value={form.name} required placeholder="github-ci" class="input input-bordered w-full" />
				</Field>
				<Field label={$t('tok.colScope')} hint={$t('tok.scopeHint')}>
					<select bind:value={form.project_id} class="select select-bordered w-full">
						<option value="">{$t('tok.allProjectsOption')}</option>
						{#each projects as p}<option value={p.id}>{p.name}</option>{/each}
					</select>
				</Field>
				<Field label={$t('tok.expiresInDays')} hint={$t('tok.expiresHint')}>
					<input bind:value={form.expires_in_days} type="number" min="1" placeholder="90" class="input input-bordered w-full" />
				</Field>
				<div class="modal-action">
					<button type="button" class="btn btn-ghost" onclick={() => dialog.close()}>{$t('common.cancel')}</button>
					<button class="btn btn-primary" disabled={saving}>
						{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('tok.createKey')}
					</button>
				</div>
			</form>
		{/if}
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
