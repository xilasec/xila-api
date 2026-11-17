<script>
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { fmtDate } from '#lib/format.js';
	import { CHANNEL_TYPES, EVENT_TYPES, channelHint, channelPlaceholder, channelInputType, defaultRules, defaultKafka, kafkaPayload, kafkaFromChannel, describeRules } from '#lib/channels.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import ChannelRules from '#lib/components/ChannelRules.svelte';
	import KafkaChannelFields from '#lib/components/KafkaChannelFields.svelte';
	import { t, labelOf, contentLocale } from '#lib/i18n.js';

	let loading = $state(true);
	let error = $state('');
	let channels = $state(/** @type {any[]} */ ([]));
	let deliveries = $state(/** @type {any[]} */ ([]));
	let pending = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);
	let testing = $state('');

	/** @type {HTMLDialogElement} */
	let dialog;
	let form = $state({ name: '', type: 'slack', url: '', events: '*', project_id: '', secret: '', rules: defaultRules(), kafka: defaultKafka() });

	/** @type {HTMLDialogElement} */
	let editDialog;
	let editing = $state(/** @type {any} */ (null)); // { id, name, events, enabled, rules, kafka }

	/** @param {any} ch */
	function openEdit(ch) {
		editing = {
			id: ch.id, name: ch.name, events: ch.events.length === 1 ? ch.events[0] : '*', enabled: ch.enabled,
			type: ch.type, has_secret: ch.has_secret, secret: '', clear_secret: false,
			kafka: ch.type === 'kafka' ? kafkaFromChannel(ch) : defaultKafka(),
			rules: { min_severity: ch.min_severity, filter: ch.filter ?? '', summary: ch.summary, summary_hour: ch.summary_hour, summary_weekday: ch.summary_weekday }
		};
		editDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function saveEdit(e) {
		e.preventDefault();
		saving = true;
		try {
			/** @type {Record<string, any>} */
			const body = {
				name: editing.name, enabled: editing.enabled,
				events: editing.events === '*' ? ['*'] : [editing.events], ...editing.rules
			};
			if (editing.type === 'kafka') body.kafka = kafkaPayload(editing.kafka);
			// Write-only: send it only to rotate (a value) or remove ("").
			const secretField = editing.type === 'kafka' ? 'sasl_password' : 'signing_secret';
			if (editing.clear_secret) body[secretField] = '';
			else if (editing.type === 'kafka' ? editing.kafka.sasl_password : editing.secret) {
				body[secretField] = editing.type === 'kafka' ? editing.kafka.sasl_password : editing.secret;
			}
			await api.updateChannel(editing.id, body);
			editDialog.close();
			notify($t('notif.updated'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {string | null} id */
	const projectName = (id) => (id ? (projects.find((p) => p.id === id)?.name ?? id) : $t('notif.allProjects'));

	async function load() {
		loading = true;
		error = '';
		try {
			[channels, deliveries, pending, projects] = await Promise.all([
				api.listChannels(),
				api.listDeliveries().catch(() => []),
				api.listPendingDeliveries().catch(() => []),
				api.listProjects().catch(() => [])
			]);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('notif.loadFailed');
		} finally {
			loading = false;
		}
	}

	onMount(load);

	function openCreate() {
		form = { name: '', type: 'slack', url: '', events: '*', project_id: '', secret: '', rules: defaultRules(), kafka: defaultKafka() };
		dialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function create(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.createChannel({
				name: form.name,
				type: form.type,
				url: form.url,
				events: form.events === '*' ? ['*'] : [form.events],
				project_id: form.project_id || null,
				...(form.type === 'webhook' && form.secret ? { signing_secret: form.secret } : {}),
				...(form.type === 'kafka' ? { kafka: kafkaPayload(form.kafka), sasl_password: form.kafka.sasl_password } : {}),
				...form.rules
			});
			dialog.close();
			notify($t('notif.added'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} ch */
	async function test(ch) {
		testing = ch.id;
		try {
			await api.testChannel(ch.id);
			notify($t('notif.testSent', { name: ch.name }), 'success');
			deliveries = await api.listDeliveries().catch(() => deliveries);
		} catch (err) {
			notify($t('notif.testFailed', { error: errorMessage(err) }));
		} finally {
			testing = '';
		}
	}

	/** @param {any} ch */
	async function remove(ch) {
		if (!confirm($t('notif.confirmDelete', { name: ch.name }))) return;
		try {
			await api.deleteChannel(ch.id);
			notify($t('notif.deleted'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="flex items-center justify-between mb-5">
	<div>
		<h1 class="text-2xl font-bold">{$t('notif.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('notif.subtitle')}</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openCreate}>{$t('notif.addChannel')}</button>
</div>

<State {loading} {error} empty={!loading && !error && channels.length === 0}
	emptyText={$t('notif.empty')} />

{#if !loading && channels.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('notif.colName')}</th><th>{$t('notif.colType')}</th><th>{$t('notif.colEvents')}</th><th>{$t('notif.colScope')}</th><th>{$t('notif.colRules')}</th><th>{$t('notif.colUrl')}</th><th></th></tr></thead>
			<tbody>
				{#each channels as ch (ch.id)}
					<tr class="hover">
						<td class="font-medium">
							{ch.name}
							{#if !ch.enabled}<span class="badge badge-ghost badge-sm ml-1">{$t('notif.paused')}</span>{/if}
						</td>
						<td>
							<span class="badge badge-ghost badge-sm capitalize">{ch.type}</span>
							{#if ch.has_secret}<span class="badge badge-outline badge-sm" title={$t('notif.signedTitle')}>{$t('notif.signed')}</span>{/if}
						</td>
						<td class="text-xs">{ch.events.join(', ')}</td>
						<td class="text-xs">{projectName(ch.project_id)}</td>
						<td class="text-xs">{describeRules(ch, $t, $labelOf, $contentLocale)}</td>
						<td class="text-xs font-mono text-base-content/50 max-w-xs truncate" title={ch.url}>{ch.url}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => test(ch)} disabled={testing === ch.id}>
								{#if testing === ch.id}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('notif.test')}
							</button>
							<button class="btn btn-ghost btn-xs" onclick={() => openEdit(ch)}>{$t('common.edit')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(ch)}>{$t('common.delete')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if !loading && pending.length > 0}
	<h2 class="text-lg font-semibold mt-8 mb-1">{$t('notif.waiting')}</h2>
	<p class="text-xs text-base-content/60 mb-2">
		{$t('notif.waitingIntro')}
	</p>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('notif.colQueued')}</th><th>{$t('notif.colChannel')}</th><th>{$t('notif.colEvent')}</th><th>{$t('notif.colTries')}</th><th>{$t('notif.colNextTry')}</th><th>{$t('notif.colLastError')}</th></tr></thead>
			<tbody>
				{#each pending as p (p.id)}
					<tr class="hover">
						<td class="text-xs text-base-content/60">{fmtDate(p.created_at)}</td>
						<td class="text-xs">{p.channel_name}</td>
						<td class="text-xs"><span class="font-mono">{p.event_type}</span> {p.title}</td>
						<td class="text-xs">{p.attempts}</td>
						<td class="text-xs text-base-content/60">{fmtDate(p.next_attempt_at)}</td>
						<td class="text-xs text-error max-w-xs truncate" title={p.last_error}>
							{p.last_status ? `HTTP ${p.last_status} — ` : ''}{p.last_error}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if !loading && deliveries.length > 0}
	<h2 class="text-lg font-semibold mt-8 mb-2">{$t('notif.recent')}</h2>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('notif.colWhen')}</th><th>{$t('notif.colChannel')}</th><th>{$t('notif.colEvent')}</th><th>{$t('notif.colResult')}</th></tr></thead>
			<tbody>
				{#each deliveries as d (d.id)}
					<tr class="hover">
						<td class="text-xs text-base-content/60">{fmtDate(d.created_at)}</td>
						<td class="text-xs">{d.channel_name || '—'}</td>
						<td class="text-xs font-mono">{d.event_type}</td>
						<td class="text-xs">
							{#if d.delivered}
								<span class="badge badge-success badge-sm">{$t('notif.ok', { code: d.status_code ?? '' })}</span>
							{:else}
								<span class="badge badge-error badge-sm" title={d.error}>{$t('notif.failedTries', { count: d.attempts })}</span>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<dialog bind:this={dialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('notif.addTitle')}</h3>
		<form onsubmit={create} class="flex flex-col gap-3">
			<Field label={$t('notif.colName')} required>
				<input bind:value={form.name} required placeholder={$t('notif.namePlaceholder')} class="input input-bordered w-full" />
			</Field>
			<Field label={$t('notif.colType')} required>
				<select bind:value={form.type} class="select select-bordered w-full">
					{#each CHANNEL_TYPES as ct}<option value={ct.id}>{$t(ct.long)}</option>{/each}
				</select>
			</Field>
			<Field label={form.type === 'email' ? $t('notif.recipients') : form.type === 'kafka' ? $t('notif.kafkaTopic') : $t('notif.colUrl')} required hint={channelHint(form.type, $t)}>
				<input bind:value={form.url} required type={channelInputType(form.type)} placeholder={channelPlaceholder(form.type)} class="input input-bordered w-full" />
			</Field>
			{#if form.type === 'webhook'}
				<Field label={$t('notif.signingSecret')} hint={$t('notif.secretHint')}>
					<input bind:value={form.secret} type="password" autocomplete="new-password" minlength="16" class="input input-bordered w-full font-mono" />
				</Field>
			{/if}
			{#if form.type === 'kafka'}
				<KafkaChannelFields bind:kafka={form.kafka} />
			{/if}
			<div class="grid grid-cols-2 gap-3">
				<Field label={$t('notif.colEvents')}>
					<select bind:value={form.events} class="select select-bordered w-full">
						{#each EVENT_TYPES as e}<option value={e.id}>{$t(e.key)}</option>{/each}
					</select>
				</Field>
				<Field label={$t('notif.colScope')} hint={$t('notif.scopeHint')}>
					<select bind:value={form.project_id} class="select select-bordered w-full">
						<option value="">{$t('notif.allProjects')}</option>
						{#each projects as p}<option value={p.id}>{p.name}</option>{/each}
					</select>
				</Field>
			</div>
			<ChannelRules bind:rules={form.rules} />
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => dialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('common.add')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<dialog bind:this={editDialog} class="modal">
	<div class="modal-box">
		{#if editing}
			<h3 class="font-bold text-lg mb-4">{$t('notif.editTitle')}</h3>
			<form onsubmit={saveEdit} class="flex flex-col gap-3">
				<Field label={$t('notif.colName')} required>
					<input bind:value={editing.name} required class="input input-bordered w-full" />
				</Field>
				<Field label={$t('notif.colEvents')}>
					<select bind:value={editing.events} class="select select-bordered w-full">
						{#each EVENT_TYPES as e}<option value={e.id}>{$t(e.key)}</option>{/each}
					</select>
				</Field>
				<ChannelRules bind:rules={editing.rules} />
				{#if editing.type === 'webhook'}
					<Field label={$t('notif.signingSecret')} hint={editing.has_secret ? $t('notif.secretSet') : $t('notif.secretNotSet')}>
						<input bind:value={editing.secret} type="password" autocomplete="new-password" minlength="16" disabled={editing.clear_secret}
							placeholder={editing.has_secret ? '••••••••' : ''} class="input input-bordered w-full font-mono" />
					</Field>
					{#if editing.has_secret}
						<label class="label cursor-pointer justify-start gap-2">
							<input type="checkbox" bind:checked={editing.clear_secret} class="checkbox checkbox-sm" />
							<span class="label-text">{$t('notif.removeSecret')}</span>
						</label>
					{/if}
				{/if}
				{#if editing.type === 'kafka'}
					<KafkaChannelFields bind:kafka={editing.kafka} hasSecret={editing.has_secret} bind:clearSecret={editing.clear_secret} />
				{/if}
				<label class="label cursor-pointer justify-start gap-2">
					<input type="checkbox" bind:checked={editing.enabled} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('notif.enabled')}</span>
				</label>
				<div class="modal-action">
					<button type="button" class="btn btn-ghost" onclick={() => editDialog.close()}>{$t('common.cancel')}</button>
					<button class="btn btn-primary" disabled={saving}>
						{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('common.save')}
					</button>
				</div>
			</form>
		{/if}
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
