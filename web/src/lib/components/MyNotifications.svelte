<script>
	// The signed-in person's own subscriptions: events on findings assigned to
	// them and on projects they watch, by email and/or a personal Slack / Teams
	// webhook. The webhook URL is write-only (shown as "set").
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { SEVERITIES } from '#lib/format.js';
	import { EVENT_TYPES } from '#lib/channels.js';
	import { fmtDate } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';

	/** @type {{ id: string, key: import('#lib/i18n.js').MessageKey }[]} */
	const METHODS = [
		{ id: 'email', key: 'mynotif.emailMethod' },
		{ id: 'slack', key: 'mynotif.slackMethod' },
		{ id: 'teams', key: 'mynotif.teamsMethod' }
	];
	const EVENTS = EVENT_TYPES.filter((e) => !['exception.expired', 'ingestion.anomaly'].includes(e.id));

	let loading = $state(true);
	let saving = $state(false);
	let prefs = $state(/** @type {any} */ (null));
	let urls = $state(/** @type {Record<string, string>} */ ({ slack: '', teams: '' }));
	let deliveries = $state(/** @type {any[]} */ ([]));

	async function load() {
		loading = true;
		try {
			prefs = await api.myNotifications();
			deliveries = await api.myNotificationDeliveries();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			/** @type {Record<string, any>} */
			const methods = {};
			for (const m of METHODS) {
				const cur = prefs.methods[m.id];
				methods[m.id] = { enabled: cur.enabled, events: cur.events, min_severity: cur.min_severity };
				if (m.id !== 'email' && urls[m.id]) methods[m.id].url = urls[m.id];
			}
			prefs = await api.saveMyNotifications({ on_assigned: prefs.on_assigned, on_watched: prefs.on_watched, methods });
			urls = { slack: '', teams: '' };
			notify($t('mynotif.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {string} method */
	async function removeURL(method) {
		try {
			prefs = await api.saveMyNotifications({ methods: { [method]: { url: '', enabled: false } } });
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	onMount(load);
</script>

<div class="card bg-base-100 shadow-sm md:col-span-2">
	<form class="card-body gap-3" onsubmit={save}>
		<h2 class="card-title text-base">{$t('mynotif.title')}</h2>
		{#if loading || !prefs}
			<span class="loading loading-spinner loading-sm"></span>
		{:else}
			<p class="text-sm text-base-content/60">
				{$t('mynotif.introBefore')} <em>{$t('mynotif.watchButton')}</em> {$t('mynotif.introAfter')}
			</p>
			<div class="flex flex-wrap gap-4">
				<label class="label cursor-pointer gap-2"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={prefs.on_assigned} />
					<span class="label-text">{$t('mynotif.assigned')}</span></label>
				<label class="label cursor-pointer gap-2"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={prefs.on_watched} />
					<span class="label-text">{$t('mynotif.watched')}</span></label>
			</div>
			<div class="overflow-x-auto">
				<table class="table table-sm">
					<thead><tr><th>{$t('mynotif.sendBy')}</th><th>{$t('mynotif.on')}</th><th>{$t('mynotif.events')}</th><th>{$t('mynotif.fromSeverity')}</th><th>{$t('mynotif.webhookUrl')}</th></tr></thead>
					<tbody>
						{#each METHODS as m (m.id)}
							{@const cur = prefs.methods[m.id]}
							<tr>
								<td class="whitespace-nowrap">{$t(m.key)}</td>
								<td><input type="checkbox" class="toggle toggle-sm" bind:checked={cur.enabled} aria-label={$t('mynotif.enable', { method: $t(m.key) })} /></td>
								<td>
									<select class="select select-bordered select-xs" value={cur.events[0] ?? '*'}
										onchange={(e) => (cur.events = [e.currentTarget.value])} aria-label={$t('mynotif.events')}>
										{#each EVENTS as ev}<option value={ev.id}>{$t(ev.key)}</option>{/each}
									</select>
								</td>
								<td>
									<select class="select select-bordered select-xs" bind:value={cur.min_severity} aria-label={$t('mynotif.minSeverity')}>
										<option value="">{$t('mynotif.any')}</option>
										{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}+</option>{/each}
									</select>
								</td>
								<td>
									{#if m.id === 'email'}
										<span class="text-xs text-base-content/50">{$t('mynotif.yourAddress')}</span>
									{:else}
										<div class="flex items-center gap-1">
											<input type="url" class="input input-bordered input-xs w-64" bind:value={urls[m.id]}
												placeholder={cur.has_url ? $t('mynotif.urlSet') : 'https://…'} />
											{#if cur.has_url}<button type="button" class="btn btn-ghost btn-xs" onclick={() => removeURL(m.id)}>{$t('common.remove')}</button>{/if}
										</div>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if prefs.watching.length}
				<p class="text-xs text-base-content/60">
					{$t('mynotif.watching')} {#each prefs.watching as w, i}<a class="link" href="/projects/{w.project_id}">{w.project_name}</a>{i < prefs.watching.length - 1 ? ', ' : ''}{/each}
				</p>
			{/if}
			<div><button class="btn btn-primary btn-sm" disabled={saving}>{$t('common.save')}</button></div>
			{#if deliveries.length}
				<details>
					<summary class="cursor-pointer text-sm">{$t('mynotif.recent', { count: deliveries.length })}</summary>
					<ul class="mt-2 text-xs space-y-1">
						{#each deliveries.slice(0, 20) as d (d.id)}
							<li>
								<span class:text-success={d.delivered} class:text-error={!d.delivered}>{d.delivered ? '✓' : '✗'}</span>
								{d.event_type} · {d.channel_name} · {fmtDate(d.created_at)}
								{#if d.error}<span class="text-error"> — {d.error}</span>{/if}
							</li>
						{/each}
					</ul>
				</details>
			{/if}
		{/if}
	</form>
</div>
