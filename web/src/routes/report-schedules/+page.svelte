<script>
	// Report schedules: a user's own recurring report (project, portfolio or
	// evidence), delivered by email (the HTML attached) or as a link to a
	// notification channel. A leader job renders and delivers due schedules as
	// their owner.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	const WEEKDAYS = [0, 1, 2, 3, 4, 5, 6];
	const WEEKDAY_KEYS = /** @type {const} */ ([
		'reportsched.weekday.0',
		'reportsched.weekday.1',
		'reportsched.weekday.2',
		'reportsched.weekday.3',
		'reportsched.weekday.4',
		'reportsched.weekday.5',
		'reportsched.weekday.6'
	]);

	const blank = () => ({
		name: '',
		kind: 'project',
		project_id: '',
		framework_key: '',
		template_id: '',
		engagement_id: '',
		cadence: 'weekly',
		hour: 8,
		weekday: 1,
		day_of_month: 1,
		recipient_emails: '',
		recipient_channel_ids: /** @type {string[]} */ ([]),
		enabled: true
	});

	let schedules = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));
	let frameworks = $state(/** @type {any[]} */ ([]));
	let templates = $state(/** @type {any[]} */ ([]));
	let channels = $state(/** @type {any[]} */ ([]));
	let engagements = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);
	let editing = $state(/** @type {string | null} */ (null)); // null | 'new' | schedule id
	let form = $state(blank());
	let historyFor = $state(/** @type {any | null} */ (null));
	let runs = $state(/** @type {any[]} */ ([]));

	async function load() {
		try {
			const [s, p, f, t, c] = await Promise.all([
				api.listReportSchedules(),
				api.listProjects(),
				api.listFrameworks(),
				api.listReportTemplates(),
				api.listChannels()
			]);
			schedules = s.report_schedules ?? [];
			projects = p ?? [];
			frameworks = f ?? [];
			templates = t.templates ?? [];
			channels = c ?? [];
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {string} projectId */
	async function loadEngagements(projectId) {
		engagements = projectId ? await api.listEngagements(projectId) : [];
	}

	function openNew() {
		form = blank();
		engagements = [];
		editing = 'new';
	}

	/** @param {any} sch */
	function openEdit(sch) {
		form = {
			...blank(),
			...sch,
			project_id: sch.project_id ?? '',
			framework_key: sch.framework_key ?? '',
			template_id: sch.template_id ?? '',
			engagement_id: sch.engagement_id ?? '',
			weekday: sch.weekday ?? 1,
			day_of_month: sch.day_of_month ?? 1,
			recipient_emails: (sch.recipient_emails ?? []).join(', '),
			recipient_channel_ids: [...(sch.recipient_channel_ids ?? [])]
		};
		editing = sch.id;
		if (sch.project_id) loadEngagements(sch.project_id);
	}

	/** @param {string} id */
	function toggleChannel(id) {
		form.recipient_channel_ids = form.recipient_channel_ids.includes(id)
			? form.recipient_channel_ids.filter((/** @type {string} */ x) => x !== id)
			: [...form.recipient_channel_ids, id];
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		const body = {
			name: form.name,
			kind: form.kind,
			project_id: form.kind === 'portfolio' ? null : form.project_id || null,
			framework_key: form.kind === 'evidence' ? form.framework_key : '',
			template_id: form.kind === 'evidence' ? null : form.template_id || null,
			engagement_id: form.kind === 'project' ? form.engagement_id || null : null,
			cadence: form.cadence,
			hour: Number(form.hour),
			weekday: form.cadence === 'weekly' ? Number(form.weekday) : null,
			day_of_month: form.cadence === 'monthly' ? Number(form.day_of_month) : null,
			recipient_emails: form.recipient_emails
				.split(',')
				.map((/** @type {string} */ s) => s.trim())
				.filter(Boolean),
			recipient_channel_ids: form.recipient_channel_ids,
			enabled: form.enabled
		};
		try {
			if (editing === 'new') await api.createReportSchedule(body);
			else await api.updateReportSchedule(/** @type {string} */ (editing), body);
			editing = null;
			await load();
			notify($t('reportsched.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} sch */
	async function remove(sch) {
		if (!confirm($t('reportsched.deleteConfirm', { name: sch.name }))) return;
		try {
			await api.deleteReportSchedule(sch.id);
			schedules = schedules.filter((x) => x.id !== sch.id);
			notify($t('reportsched.deleted'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} sch */
	async function sendNow(sch) {
		try {
			await api.sendReportScheduleNow(sch.id);
			notify($t('reportsched.sent'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} sch */
	async function showHistory(sch) {
		historyFor = sch;
		try {
			const res = await api.listReportScheduleRuns(sch.id);
			runs = res.runs ?? [];
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} sch */
	function projectName(sch) {
		return projects.find((p) => p.id === sch.project_id)?.name ?? sch.project_name ?? '';
	}

	/** @param {any} sch */
	function reportLabel(sch) {
		if (sch.kind === 'portfolio') return $t('reportsched.kindPortfolio');
		if (sch.kind === 'evidence') return `${sch.framework_key} — ${projectName(sch)}`;
		return projectName(sch);
	}
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('reportsched.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('reportsched.intro')}</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openNew}>{$t('reportsched.newButton')}</button>
</div>

{#if editing}
	<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
		<Field label={$t('reportsched.nameLabel')} required>
			<input bind:value={form.name} required maxlength="200" class="input input-bordered input-sm" placeholder={$t('reportsched.namePlaceholder')} />
		</Field>
		<Field label={$t('reportsched.kindLabel')}>
			<select bind:value={form.kind} class="select select-bordered select-sm">
				<option value="project">{$t('reportsched.kindProject')}</option>
				<option value="portfolio">{$t('reportsched.kindPortfolio')}</option>
				<option value="evidence">{$t('reportsched.kindEvidence')}</option>
			</select>
		</Field>

		{#if form.kind !== 'portfolio'}
			<Field label={$t('reportsched.projectLabel')} required>
				<select
					bind:value={form.project_id}
					required
					class="select select-bordered select-sm"
					onchange={() => loadEngagements(form.project_id)}
				>
					<option value="" disabled>—</option>
					{#each projects as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
				</select>
			</Field>
		{/if}

		{#if form.kind === 'evidence'}
			<Field label={$t('reportsched.frameworkLabel')} required>
				<select bind:value={form.framework_key} required class="select select-bordered select-sm">
					<option value="" disabled>—</option>
					{#each frameworks as f (f.key)}<option value={f.key}>{f.name}</option>{/each}
				</select>
			</Field>
		{:else}
			<Field label={$t('reportsched.templateLabel')}>
				<select bind:value={form.template_id} class="select select-bordered select-sm">
					<option value="">{$t('reportsched.templateDefault')}</option>
					{#each templates as tpl (tpl.id)}<option value={tpl.id}>{tpl.name}</option>{/each}
				</select>
			</Field>
		{/if}

		{#if form.kind === 'project'}
			<Field label={$t('reportsched.engagementLabel')}>
				<select bind:value={form.engagement_id} class="select select-bordered select-sm">
					<option value="">{$t('reportsched.engagementNone')}</option>
					{#each engagements as e (e.id)}<option value={e.id}>{e.name}</option>{/each}
				</select>
			</Field>
		{/if}

		<Field label={$t('reportsched.cadenceLabel')}>
			<select bind:value={form.cadence} class="select select-bordered select-sm">
				<option value="daily">{$t('reportsched.cadenceDaily')}</option>
				<option value="weekly">{$t('reportsched.cadenceWeekly')}</option>
				<option value="monthly">{$t('reportsched.cadenceMonthly')}</option>
			</select>
		</Field>
		<Field label={$t('reportsched.hourLabel')}>
			<input type="number" min="0" max="23" bind:value={form.hour} class="input input-bordered input-sm" />
		</Field>

		{#if form.cadence === 'weekly'}
			<Field label={$t('reportsched.weekdayLabel')}>
				<select bind:value={form.weekday} class="select select-bordered select-sm">
					{#each WEEKDAYS as w (w)}<option value={w}>{$t(WEEKDAY_KEYS[w])}</option>{/each}
				</select>
			</Field>
		{:else if form.cadence === 'monthly'}
			<Field label={$t('reportsched.dayOfMonthLabel')} hint={$t('reportsched.dayOfMonthHint')}>
				<input type="number" min="1" max="28" bind:value={form.day_of_month} class="input input-bordered input-sm" />
			</Field>
		{/if}

		<div class="md:col-span-2">
			<Field label={$t('reportsched.emailsLabel')} hint={$t('reportsched.emailsHint')}>
				<input bind:value={form.recipient_emails} class="input input-bordered input-sm w-full" placeholder="a@x.io, b@x.io" />
			</Field>
		</div>
		<div class="md:col-span-2">
			<span class="label-text font-medium">{$t('reportsched.channelsLabel')}</span>
			<span class="label-text-alt text-base-content/50 ml-1">{$t('reportsched.channelsHint')}</span>
			<ul class="mt-1 flex flex-wrap gap-x-4 gap-y-1">
				{#each channels as ch (ch.id)}
					<li class="flex items-center gap-2 text-sm">
						<input
							type="checkbox"
							class="checkbox checkbox-sm"
							checked={form.recipient_channel_ids.includes(ch.id)}
							onchange={() => toggleChannel(ch.id)}
						/>
						<span>{ch.name}</span>
					</li>
				{/each}
			</ul>
		</div>
		<div class="md:col-span-2 flex items-center gap-2">
			<input type="checkbox" bind:checked={form.enabled} class="checkbox checkbox-sm" id="rs-enabled" />
			<label for="rs-enabled" class="label-text">{$t('reportsched.enabledLabel')}</label>
		</div>

		<div class="md:col-span-2 flex justify-end gap-2">
			<button type="button" class="btn btn-sm" onclick={() => (editing = null)}>{$t('reportsched.cancelButton')}</button>
			<button class="btn btn-sm btn-primary" disabled={saving}>
				{editing === 'new' ? $t('reportsched.createButton') : $t('reportsched.saveButton')}
			</button>
		</div>
	</form>
{/if}

<State {loading} empty={!loading && schedules.length === 0} emptyText={$t('reportsched.empty')} />

{#if !loading && schedules.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					<th>{$t('reportsched.colName')}</th>
					<th>{$t('reportsched.colReport')}</th>
					<th>{$t('reportsched.colCadence')}</th>
					<th>{$t('reportsched.colLastRun')}</th>
					<th>{$t('reportsched.colRecipients')}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each schedules as sch (sch.id)}
					<tr class:opacity-50={!sch.enabled}>
						<td class="font-medium">{sch.name}</td>
						<td class="text-xs">{reportLabel(sch)}</td>
						<td class="text-xs">{sch.cadence} @ {sch.hour}:00 UTC</td>
						<td class="text-xs">
							{#if sch.last_run_at}
								<span class:text-error={sch.last_run_status === 'failure'}>{new Date(sch.last_run_at).toLocaleString()}</span>
							{:else}
								{$t('reportsched.never')}
							{/if}
						</td>
						<td class="text-xs">{(sch.recipient_emails?.length ?? 0) + (sch.recipient_channel_ids?.length ?? 0)}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => sendNow(sch)}>{$t('reportsched.sendNowButton')}</button>
							<button class="btn btn-ghost btn-xs" onclick={() => showHistory(sch)}>{$t('reportsched.historyButton')}</button>
							<button class="btn btn-ghost btn-xs" onclick={() => openEdit(sch)}>{$t('reportsched.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(sch)}>{$t('reportsched.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if historyFor}
	<div class="modal modal-open">
		<div class="modal-box">
			<h3 class="font-bold text-lg">{$t('reportsched.historyTitle', { name: historyFor.name })}</h3>
			{#if runs.length === 0}
				<p class="text-base-content/50 py-4">{$t('reportsched.runEmpty')}</p>
			{:else}
				<table class="table table-sm mt-3">
					<thead>
						<tr>
							<th>{$t('reportsched.colStarted')}</th>
							<th>{$t('reportsched.colStatus')}</th>
							<th>{$t('reportsched.colRecipients')}</th>
							<th>{$t('reportsched.colError')}</th>
						</tr>
					</thead>
					<tbody>
						{#each runs as run (run.id)}
							<tr>
								<td class="text-xs">{new Date(run.started_at).toLocaleString()}</td>
								<td class="text-xs" class:text-error={run.status === 'failure'}>{run.status}</td>
								<td class="text-xs">{run.recipients}</td>
								<td class="text-xs">{run.error || '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
			<div class="modal-action">
				<button class="btn btn-sm" onclick={() => (historyFor = null)}>{$t('reportsched.closeButton')}</button>
			</div>
		</div>
	</div>
{/if}
