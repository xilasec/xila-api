<script>
	// Configures a project's issue tracker. The token is write-only: the API only
	// says whether one is stored, and leaving the field blank on save keeps it.
	// Templates, comment sync and the webhook receiver are M13 13.18. Saving /
	// testing / removing need project owner.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { SEVERITIES } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import Field from '#lib/components/Field.svelte';
	import State from '#lib/components/State.svelte';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	const KINDS = [
		{ id: 'github', label: 'GitHub Issues', url: 'https://api.github.com', target: 'owner/repo' },
		{ id: 'gitlab', label: 'GitLab Issues', url: 'https://gitlab.com', target: 'it.targetGitlab' },
		{ id: 'azure-devops', label: 'Azure DevOps Boards', url: '', target: 'it.targetAzure', done: 'Closed', reopen: 'Active' },
		{ id: 'linear', label: 'Linear', url: 'https://api.linear.app', target: 'it.targetLinear', done: 'completed', reopen: 'unstarted' },
		{ id: 'servicenow', label: 'ServiceNow', url: '', target: 'it.targetServiceNow', done: 'Resolved', reopen: 'New' },
		{ id: 'jira', label: 'Jira', url: 'https://your-site.atlassian.net', target: 'it.targetJira', done: 'Done', reopen: 'To Do' }
	];

	/** @returns {{ kind: string, base_url: string, target: string, token?: string, jira_email: string, auth_user: string, issue_type: string, done_transition: string, reopen_transition: string, min_severity: string, auto_create: boolean, labels: string, enabled: boolean, sync_comments: boolean, title_template: string, body_template: string }} */
	const blank = () => ({
		kind: 'github',
		base_url: '',
		target: '',
		token: '',
		jira_email: '',
		auth_user: '',
		issue_type: '',
		done_transition: '',
		reopen_transition: '',
		min_severity: 'high',
		auto_create: false,
		labels: '',
		enabled: true,
		sync_comments: false,
		title_template: '',
		body_template: ''
	});

	let tracker = $state(/** @type {any} */ (null)); // stored config, null = none
	let form = $state(blank());
	let loading = $state(true);
	let busy = $state(false);

	const kind = $derived(KINDS.find((k) => k.id === form.kind) ?? KINDS[0]);

	// Jira, Azure DevOps, Linear and ServiceNow all close/reopen an issue by
	// writing a state value of some kind (a workflow transition name, a
	// System.State value, a workflow state type, or a state field value);
	// only GitHub and GitLab have a plain open/closed flag instead.
	const hasTransitions = $derived(form.kind !== 'github' && form.kind !== 'gitlab');
	const hasIssueType = $derived(form.kind === 'jira' || form.kind === 'azure-devops');
	const transitionHintKey = $derived(
		/** @type {import('#lib/i18n.js').MessageKey} */ (
			{ 'azure-devops': 'it.azureStateHint', linear: 'it.linearStateHint', servicenow: 'it.snowStateHint' }[form.kind] ?? 'it.transitionHint'
		)
	);

	/** @param {any} t */
	function fill(t) {
		tracker = t;
		form = t
			? {
					kind: t.kind,
					base_url: t.base_url,
					target: t.target,
					token: '',
					jira_email: t.jira_email,
					auth_user: t.auth_user,
					issue_type: t.issue_type,
					done_transition: t.done_transition,
					reopen_transition: t.reopen_transition,
					min_severity: t.min_severity,
					auto_create: t.auto_create,
					labels: (t.labels ?? []).join(', '),
					enabled: t.enabled,
					sync_comments: t.sync_comments,
					title_template: t.title_template ?? '',
					body_template: t.body_template ?? ''
				}
			: blank();
	}

	let shownSecret = $state(''); // the secret just issued, shown this once
	let ownSecret = $state('');

	/** @param {string} [own] the tracker's own secret */
	async function setSecret(own) {
		busy = true;
		try {
			const out = await api.rotateIssueWebhookSecret(projectId, own);
			shownSecret = own ? '' : out.secret;
			ownSecret = '';
			tracker = { ...tracker, has_webhook_secret: true, webhook_url: out.webhook_url };
			notify($t('it.webhookSaved'), 'success');
		} catch (err) {
			ownerError(err, 'configure');
		} finally {
			busy = false;
		}
	}

	async function clearSecret() {
		if (!confirm($t('it.webhookConfirmOff'))) return;
		busy = true;
		try {
			await api.clearIssueWebhookSecret(projectId);
			shownSecret = '';
			tracker = { ...tracker, has_webhook_secret: false };
			notify($t('it.webhookCleared'), 'success');
		} catch (err) {
			ownerError(err, 'configure');
		} finally {
			busy = false;
		}
	}

	$effect(() => {
		const pid = projectId;
		loading = true;
		api
			.issueTracker(pid)
			.then(fill)
			.catch((err) => {
				if (err.status !== 404) notify(err.message);
				fill(null);
			})
			.finally(() => (loading = false));
	});

	/** @param {unknown} err @param {'configure' | 'test' | 'remove'} what */
	function ownerError(err, what) {
		notify(err instanceof ApiError && err.status === 403 ? $t(`it.owner.${what}`) : errorMessage(err));
	}
	/** @param {string} target a placeholder, or the message key of a described one */
	const targetHint = (target) => (target.startsWith('it.') ? $t(/** @type {import('#lib/i18n.js').MessageKey} */ (target)) : target);

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		busy = true;
		try {
			const body = {
				...form,
				labels: form.labels
					.split(',')
					.map((l) => l.trim())
					.filter(Boolean)
			};
			if (!body.token) delete body.token; // keep the stored one
			fill(await api.setIssueTracker(projectId, body));
			notify($t('it.saved'), 'success');
		} catch (err) {
			ownerError(err, 'configure');
		} finally {
			busy = false;
		}
	}

	async function test() {
		busy = true;
		try {
			await api.testIssueTracker(projectId);
			notify($t('it.ok'), 'success');
		} catch (err) {
			ownerError(err, 'test');
		} finally {
			busy = false;
		}
	}

	async function remove() {
		if (!confirm($t('it.confirmRemove'))) return;
		busy = true;
		try {
			await api.deleteIssueTracker(projectId);
			fill(null);
			notify($t('it.removed'), 'success');
		} catch (err) {
			ownerError(err, 'remove');
		} finally {
			busy = false;
		}
	}
</script>

<p class="text-sm text-base-content/60 mb-3">
	{$t('it.intro')}
</p>

<State {loading} />
{#if !loading}
	<form onsubmit={save} class="card bg-base-100 shadow-sm">
		<div class="card-body gap-3">
			<div class="flex flex-wrap items-center gap-2 text-sm">
				{#if tracker}
					<span class="badge badge-primary">{$t('it.configured')}</span>
					{#if !tracker.enabled}<span class="badge badge-ghost">{$t('it.disabled')}</span>{/if}
					{#if tracker.has_token}<span class="text-xs text-base-content/50">{$t('it.tokenStored')}</span>{/if}
				{:else}
					<span class="badge badge-ghost">{$t('it.notConfigured')}</span>
				{/if}
			</div>

			<div class="grid gap-3 sm:grid-cols-2">
				<Field label={$t('it.tracker')} required>
					<select bind:value={form.kind} class="select select-bordered select-sm">
						{#each KINDS as k}<option value={k.id}>{k.label}</option>{/each}
					</select>
				</Field>
				<Field label={$t('it.baseUrl')} required={kind.url === ''} hint={kind.url === '' ? '' : $t('it.blankDefault', { url: kind.url })}>
					<input bind:value={form.base_url} type="url" placeholder={kind.url} class="input input-bordered input-sm" />
				</Field>
				<Field label={$t('it.target')} required>
					<input
						bind:value={form.target}
						required={form.kind !== 'servicenow'}
						placeholder={form.kind === 'servicenow' ? 'incident' : targetHint(kind.target)}
						class="input input-bordered input-sm"
					/>
				</Field>
				<Field label={$t('it.token')} required={!tracker?.has_token} hint={$t('it.writeOnly')}>
					<input
						bind:value={form.token}
						type="password"
						autocomplete="new-password"
						required={!tracker?.has_token}
						placeholder={tracker?.has_token ? $t('it.storedKeep') : ''}
						class="input input-bordered input-sm"
					/>
				</Field>
				{#if form.kind === 'jira'}
					<Field label={$t('it.jiraEmail')} hint={$t('it.jiraEmailHint')}>
						<input bind:value={form.jira_email} type="email" class="input input-bordered input-sm" />
					</Field>
				{:else if form.kind === 'servicenow'}
					<Field label={$t('it.authUser')} hint={$t('it.authUserHint')}>
						<input bind:value={form.auth_user} class="input input-bordered input-sm" />
					</Field>
				{/if}
				{#if hasIssueType}
					<Field label={$t('it.issueType')} hint={form.kind === 'azure-devops' ? $t('it.workItemTypeHint') : ''}>
						<input bind:value={form.issue_type} placeholder="Bug" class="input input-bordered input-sm" />
					</Field>
				{/if}
				{#if hasTransitions}
					<Field label={$t('it.closeTransition')} hint={$t(transitionHintKey)}>
						<input bind:value={form.done_transition} placeholder={kind.done} class="input input-bordered input-sm" />
					</Field>
					<Field label={$t('it.reopenTransition')}>
						<input bind:value={form.reopen_transition} placeholder={kind.reopen} class="input input-bordered input-sm" />
					</Field>
				{/if}
				<Field label={$t('it.threshold')} hint={$t('it.thresholdHint')}>
					<select bind:value={form.min_severity} class="select select-bordered select-sm capitalize">
						{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
					</select>
				</Field>
				<Field label={$t('it.labels')} hint={$t('it.commaSeparated')}>
					<input bind:value={form.labels} placeholder="security, xila" class="input input-bordered input-sm" />
				</Field>
			</div>

			<div class="flex flex-wrap gap-4">
				<label class="label cursor-pointer gap-2">
					<input type="checkbox" bind:checked={form.auto_create} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('it.autoCreate')}</span>
				</label>
				<label class="label cursor-pointer gap-2">
					<input type="checkbox" bind:checked={form.enabled} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('it.enabled')}</span>
				</label>
				<label class="label cursor-pointer gap-2" title={$t('it.syncCommentsHint')}>
					<input type="checkbox" bind:checked={form.sync_comments} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('it.syncComments')}</span>
				</label>
			</div>

			<details class="collapse collapse-arrow border border-base-300" open={!!(form.title_template || form.body_template)}>
				<summary class="collapse-title text-sm font-medium">{$t('it.templates')}</summary>
				<div class="collapse-content grid gap-3">
					<p class="text-xs text-base-content/60">{$t('it.templateHint')}</p>
					<Field label={$t('it.titleTemplate')}>
						<input bind:value={form.title_template} maxlength="10000" placeholder={'[{{.Severity}}] {{.Title}}'} class="input input-bordered input-sm font-mono" />
					</Field>
					<Field label={$t('it.bodyTemplate')}>
						<textarea bind:value={form.body_template} maxlength="10000" rows="5" placeholder={'{{.Default}}'} class="textarea textarea-bordered textarea-sm font-mono"></textarea>
					</Field>
				</div>
			</details>

			<div class="flex flex-wrap gap-2">
				<button class="btn btn-primary btn-sm" disabled={busy}>{$t('common.save')}</button>
				{#if tracker}
					<button type="button" class="btn btn-outline btn-sm" disabled={busy} onclick={test}>{$t('it.testConnection')}</button>
					<button type="button" class="btn btn-ghost btn-sm text-error" disabled={busy} onclick={remove}>{$t('common.remove')}</button>
				{/if}
			</div>
		</div>
	</form>

	{#if tracker}
		<section class="card bg-base-100 shadow-sm mt-4" aria-labelledby="it-webhook">
			<div class="card-body gap-3">
				<div class="flex flex-wrap items-center gap-2">
					<h3 id="it-webhook" class="font-semibold">{$t('it.webhook')}</h3>
					<span class="badge {tracker.has_webhook_secret ? 'badge-success' : 'badge-ghost'}">
						{tracker.has_webhook_secret ? $t('it.webhookOn') : $t('it.webhookOff')}
					</span>
				</div>
				<p class="text-sm text-base-content/60">{$t('it.webhookIntro')}</p>
				<Field label={$t('it.webhookUrl')}>
					<input value={tracker.webhook_url} readonly class="input input-bordered input-sm font-mono" onfocus={(e) => e.currentTarget.select()} />
				</Field>
				<p class="text-xs text-base-content/70">
					{$t(/** @type {import('#lib/i18n.js').MessageKey} */ (`it.webhookHow.${tracker.kind}`))}
				</p>
				{#if shownSecret}
					<div class="alert alert-warning text-sm flex-col items-start" role="status">
						<span>{$t('it.webhookSecretOnce')}</span>
						<code class="break-all select-all">{shownSecret}</code>
					</div>
				{/if}
				<div class="flex flex-wrap items-end gap-2">
					<button type="button" class="btn btn-outline btn-sm" disabled={busy} onclick={() => setSecret()}>
						{tracker.has_webhook_secret ? $t('it.webhookRotate') : $t('it.webhookGenerate')}
					</button>
					{#if tracker.has_webhook_secret}
						<button type="button" class="btn btn-ghost btn-sm text-error" disabled={busy} onclick={clearSecret}>{$t('it.webhookDisable')}</button>
					{/if}
				</div>
				<div class="flex flex-wrap items-end gap-2">
					<Field label={$t('it.webhookOwnSecret')} hint={$t('it.webhookOwnSecretHint')}>
						<input bind:value={ownSecret} type="password" autocomplete="off" minlength="16" class="input input-bordered input-sm" />
					</Field>
					<button type="button" class="btn btn-outline btn-sm" disabled={busy || ownSecret.trim().length < 16} onclick={() => setSecret(ownSecret.trim())}>
						{$t('it.webhookUseOwn')}
					</button>
				</div>
			</div>
		</section>
	{/if}
{/if}
