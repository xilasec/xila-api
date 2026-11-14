<script>
	// A project's pull connectors (Dependency-Track / DefectDojo). Tokens are
	// write-only: the API only says whether one is stored, and leaving the field
	// blank on save keeps it (changing the URL needs a new one). Adding, editing,
	// testing and removing need project owner; "Pull now" needs editor.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { fmtDate } from '#lib/format.js';
	import { t } from '#lib/i18n.js';
	import Field from '#lib/components/Field.svelte';
	import State from '#lib/components/State.svelte';

	/** @type {{ projectId: string, onpulled?: () => void }} */
	let { projectId, onpulled = () => {} } = $props();

	/** @typedef {import('#lib/i18n.js').MessageKey} MessageKey */
	/** @type {{ id: string, label: string, url: string, remote: MessageKey, remoteHint: MessageKey, tokenHint: MessageKey }[]} */
	const KINDS = [
		{
			id: 'dependency-track',
			label: 'Dependency-Track',
			url: 'https://dtrack.example.com',
			remote: 'conn.dtRemoteLabel',
			remoteHint: 'conn.dtRemoteHint',
			tokenHint: 'conn.dtTokenHint'
		},
		{
			id: 'defectdojo',
			label: 'DefectDojo',
			url: 'https://defectdojo.example.com',
			remote: 'conn.ddRemoteLabel',
			remoteHint: 'conn.ddRemoteHint',
			tokenHint: 'conn.ddTokenHint'
		}
	];

	/** @returns {{ kind: string, name: string, base_url: string, remote_project: string, token?: string, version: string, enabled: boolean }} */
	const blank = () => ({ kind: 'dependency-track', name: '', base_url: '', remote_project: '', token: '', version: '', enabled: true });

	let connectors = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let busy = $state('');
	let editing = $state(/** @type {string | null} */ (null)); // null = closed, 'new', or a connector id
	let form = $state(blank());

	const kind = $derived(KINDS.find((k) => k.id === form.kind) ?? KINDS[0]);
	const current = $derived(connectors.find((c) => c.id === editing));
	/** @param {string} id */
	const kindLabel = (id) => KINDS.find((k) => k.id === id)?.label ?? id;

	async function load() {
		try {
			connectors = await api.listConnectors(projectId);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	$effect(() => {
		projectId;
		loading = true;
		load().finally(() => (loading = false));
	});

	/** @param {unknown} err @param {MessageKey} what */
	function ownerError(err, what) {
		notify(err instanceof ApiError && err.status === 403 ? $t('conn.ownerError', { action: $t(what) }) : errorMessage(err));
	}

	function openNew() {
		form = blank();
		editing = 'new';
	}

	/** @param {any} c */
	function openEdit(c) {
		form = { kind: c.kind, name: c.name, base_url: c.base_url, remote_project: c.remote_project, token: '', version: c.version, enabled: c.enabled };
		editing = c.id;
	}

	/** @param {any} c */
	function replace(c) {
		connectors = connectors.map((x) => (x.id === c.id ? c : x));
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		busy = 'save';
		try {
			const body = { ...form };
			if (!body.token) delete body.token; // keep the stored one
			if (editing === 'new') {
				connectors = [...connectors, await api.createConnector(projectId, body)];
			} else if (editing) {
				replace(await api.updateConnector(projectId, editing, body));
			}
			editing = null;
			notify($t('conn.saved'), 'success');
		} catch (err) {
			ownerError(err, 'conn.action.configure');
		} finally {
			busy = '';
		}
	}

	/** @param {any} c */
	async function test(c) {
		busy = 'test:' + c.id;
		try {
			const res = await api.testConnector(projectId, c.id);
			notify($t('conn.connectionOk', { suffix: res.remote_name ? ' — ' + res.remote_name : '' }), 'success');
		} catch (err) {
			ownerError(err, 'conn.action.test');
		} finally {
			busy = '';
		}
	}

	/** @param {any} c */
	async function pull(c) {
		busy = 'pull:' + c.id;
		try {
			const res = await api.pullConnector(projectId, c.id);
			replace(res.connector);
			notify($t('conn.pulled', { imported: res.imported, new: res.new, closed: res.closed }), 'success');
			onpulled();
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('conn.pullForbidden') : errorMessage(err));
			await load(); // the failure is recorded on the connector
		} finally {
			busy = '';
		}
	}

	/** @param {any} c */
	async function remove(c) {
		if (!confirm($t('conn.confirmRemove', { kind: kindLabel(c.kind) }))) return;
		busy = 'remove:' + c.id;
		try {
			await api.deleteConnector(projectId, c.id);
			connectors = connectors.filter((x) => x.id !== c.id);
			if (editing === c.id) editing = null;
			notify($t('conn.removed'), 'success');
		} catch (err) {
			ownerError(err, 'conn.action.remove');
		} finally {
			busy = '';
		}
	}
</script>

<p class="text-sm text-base-content/60 mb-3">
	{$t('conn.intro')}
</p>

<State {loading} empty={!loading && connectors.length === 0 && editing === null} emptyText={$t('conn.empty')} />
{#if !loading}
	{#if connectors.length}
		<div class="overflow-x-auto mb-3">
			<table class="table table-sm bg-base-100 shadow-sm">
				<thead>
					<tr><th>{$t('conn.colSource')}</th><th>{$t('conn.colRemote')}</th><th>{$t('conn.colVersion')}</th><th>{$t('conn.colLastPull')}</th><th></th></tr>
				</thead>
				<tbody>
					{#each connectors as c (c.id)}
						<tr>
							<td>
								<div class="font-medium">{c.name || kindLabel(c.kind)}</div>
								<div class="text-xs text-base-content/50">{c.base_url}</div>
								{#if !c.enabled}<span class="badge badge-ghost badge-xs">{$t('conn.disabled')}</span>{/if}
							</td>
							<td class="font-mono text-xs">{c.remote_project}</td>
							<td>{c.version || $t('conn.defaultVersion')}</td>
							<td class="text-xs">
								{#if c.last_error}
									<div class="text-error" title={c.last_error}>{$t('conn.failedAt', { date: fmtDate(c.last_pulled_at) })}</div>
									<div class="text-error/80 max-w-xs truncate" title={c.last_error}>{c.last_error}</div>
									{#if c.last_success_at}<div class="text-base-content/50">{$t('conn.lastOk', { date: fmtDate(c.last_success_at) })}</div>{/if}
								{:else if c.last_success_at}
									<div>{fmtDate(c.last_success_at)}</div>
									<div class="text-base-content/50">{$t('conn.findingsCount', { count: c.last_count })}</div>
								{:else}
									<span class="text-base-content/50">{$t('common.never')}</span>
								{/if}
							</td>
							<td class="text-right whitespace-nowrap">
								<button class="btn btn-primary btn-xs" disabled={busy !== ''} onclick={() => pull(c)}>
									{#if busy === 'pull:' + c.id}<span class="loading loading-spinner loading-xs"></span>{/if}
									{$t('conn.pullNow')}
								</button>
								<button class="btn btn-outline btn-xs" disabled={busy !== ''} onclick={() => test(c)}>{$t('conn.test')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy !== ''} onclick={() => openEdit(c)}>{$t('common.edit')}</button>
								<button class="btn btn-ghost btn-xs text-error" disabled={busy !== ''} onclick={() => remove(c)}>{$t('common.remove')}</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	{#if editing === null}
		<button class="btn btn-sm" onclick={openNew}>{$t('conn.addConnector')}</button>
	{:else}
		<form onsubmit={save} class="card bg-base-100 shadow-sm max-w-3xl">
			<div class="card-body gap-3">
				<h3 class="font-semibold">{editing === 'new' ? $t('conn.newConnector') : $t('conn.editConnector')}</h3>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label={$t('conn.fieldSource')} required>
						<select bind:value={form.kind} class="select select-bordered select-sm">
							{#each KINDS as k}<option value={k.id}>{k.label}</option>{/each}
						</select>
					</Field>
					<Field label={$t('conn.fieldName')} hint={$t('conn.nameHint')}>
						<input bind:value={form.name} maxlength="100" class="input input-bordered input-sm" />
					</Field>
					<Field label={$t('conn.fieldBaseUrl')} required hint={$t('conn.baseUrlHint')}>
						<input bind:value={form.base_url} type="url" required placeholder={kind.url} class="input input-bordered input-sm" />
					</Field>
					<Field label={$t(kind.remote)} required hint={$t(kind.remoteHint)}>
						<input bind:value={form.remote_project} required class="input input-bordered input-sm font-mono" />
					</Field>
					<Field
						label={$t('conn.fieldToken')}
						required={!current?.has_token || form.base_url !== current?.base_url}
						hint={$t('conn.tokenHintSuffix', { hint: $t(kind.tokenHint) })}
					>
						<input
							bind:value={form.token}
							type="password"
							autocomplete="new-password"
							required={!current?.has_token || form.base_url !== current?.base_url}
							placeholder={current?.has_token ? $t('it.storedKeep') : ''}
							class="input input-bordered input-sm"
						/>
					</Field>
					<Field label={$t('conn.fieldImportVersion')} hint={$t('conn.importVersionHint')}>
						<input bind:value={form.version} placeholder={$t('conn.importVersionPlaceholder')} class="input input-bordered input-sm" />
					</Field>
				</div>
				<label class="label cursor-pointer gap-2 justify-start">
					<input type="checkbox" bind:checked={form.enabled} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('conn.pullOnSchedule')}</span>
				</label>
				<div class="flex flex-wrap gap-2">
					<button class="btn btn-primary btn-sm" disabled={busy !== ''}>{$t('common.save')}</button>
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (editing = null)}>{$t('common.cancel')}</button>
				</div>
			</div>
		</form>
	{/if}
{/if}
