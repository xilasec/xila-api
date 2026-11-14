<script>
	// Opt-in AI-assisted triage on one finding (AI_TRIAGE_ENABLED): ask the
	// configured model for a false-positive verdict, an exploitability
	// assessment or a fix. The exact prompt is shown before anything is sent;
	// answers are recorded proposals that change nothing until a person accepts
	// them. Model output is untrusted and rendered as plain text only.
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { fmtDate, fmtNumber, prettyStatus } from '$lib/format.js';
	import { t, labelOf } from '$lib/i18n.js';

	/** @type {{ finding: any, onchange: (f: any) => void, onrevision?: () => void }} */
	let { finding, onchange, onrevision = () => {} } = $props();

	/** @type {Record<string, import('$lib/i18n.js').MessageKey>} */
	const KINDS = {
		false_positive: 'ai.kind.false_positive',
		exploitability: 'ai.kind.exploitability',
		fix: 'ai.kind.fix'
	};
	/** @param {string} k */
	const kindLabel = (k) => (KINDS[k] ? $t(KINDS[k]) : k);
	/** @param {string} s */
	const stateLabel = (s) => (['proposed', 'accepted', 'rejected', 'superseded', 'invalid'].includes(s) ? $t(/** @type {import('$lib/i18n.js').MessageKey} */ ('ai.state.' + s)) : s);
	/** @type {Record<string, string>} */
	const STATE_CLASS = {
		proposed: 'badge-info',
		accepted: 'badge-success',
		rejected: 'badge-ghost',
		superseded: 'badge-ghost',
		invalid: 'badge-error'
	};

	let enabled = $state(false);
	let info = $state(/** @type {{ provider: string, model: string, opted_out: boolean }} */ ({ provider: '', model: '', opted_out: false }));
	let proposals = $state(/** @type {any[]} */ ([]));
	let kind = $state('false_positive');
	let preview = $state(/** @type {any} */ (null));
	let busy = $state(false);
	/** @type {Record<string, string>} */
	let notes = $state({});

	/** @param {string} id */
	async function load(id) {
		try {
			const d = await api.aiProposals(id);
			info = { provider: d.provider, model: d.model, opted_out: d.opted_out };
			proposals = d.proposals ?? [];
			enabled = true;
		} catch (err) {
			enabled = false; // 404 = AI triage is off; 403 = no access
			if (!(err instanceof ApiError && (err.status === 404 || err.status === 403))) notify(errorMessage(err));
		}
	}

	$effect(() => {
		const id = finding.id;
		preview = null;
		load(id);
	});

	// A different question means a different prompt: preview it again.
	$effect(() => {
		if (preview && preview.kind !== kind) preview = null;
	});

	async function showPrompt() {
		busy = true;
		try {
			preview = await api.aiPrompt(finding.id, kind);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	async function send() {
		busy = true;
		try {
			await api.askAI(finding.id, kind);
			notify($t('ai.recorded'), 'success');
			preview = null;
		} catch (err) {
			if (err instanceof ApiError && err.status === 403) notify($t('ai.askForbidden'));
			else notify(errorMessage(err));
		} finally {
			busy = false;
			await load(finding.id); // an invalid answer is recorded too
		}
	}

	/** @param {any} p @param {'accept' | 'reject'} action */
	async function decide(p, action) {
		busy = true;
		try {
			const res = await api.decideAIProposal(finding.id, p.id, action, notes[p.id] ?? '');
			if (action === 'accept') {
				if (res.finding) onchange(res.finding);
				if (res.assessment) notify($t('ai.acceptedAssessment'), 'success');
				else if (res.risk_acceptance) notify($t('ai.acceptedRisk'), 'success');
				else notify($t('ai.applied'), 'success');
				onrevision();
			}
			await load(finding.id);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('ai.decideForbidden') : errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {boolean} optOut */
	async function setOptOut(optOut) {
		busy = true;
		try {
			await api.setProjectAIOptOut(finding.project_id, optOut);
			preview = null;
			await load(finding.id);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('ai.optOutForbidden') : errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {any} p */
	function change(p) {
		/** @type {string[]} */
		const parts = [];
		if (p.proposed_status) parts.push($t('ai.changeStatus', { status: $labelOf('status', p.proposed_status) }));
		if (p.proposed_severity) parts.push($t('ai.changeSeverity', { severity: $labelOf('severity', p.proposed_severity) }));
		return parts.length ? parts.join(', ') : p.kind === 'fix' ? $t('ai.changeFixComment') : $t('ai.changeRationaleComment');
	}
</script>

{#if enabled}
	<div class="mt-6 rounded-box border border-dashed border-secondary bg-base-100 p-4 shadow-sm">
		<div class="mb-2 flex flex-wrap items-center gap-2">
			<h2 class="font-semibold">{$t('ai.title')}</h2>
			<span class="badge badge-secondary badge-sm">{$t('ai.generated')}</span>
			<span class="text-xs text-base-content/50">{info.provider} · {info.model}</span>
		</div>
		<p class="mb-3 text-xs text-base-content/60">
			{$t('ai.disclaimer')}
		</p>

		{#if info.opted_out}
			<div class="alert mb-3 py-2 text-sm">
				<span>{$t('ai.optedOut')}</span>
				<button class="btn btn-ghost btn-xs" disabled={busy} onclick={() => setOptOut(false)}>{$t('ai.allow')}</button>
			</div>
		{:else}
			<div class="flex flex-wrap items-end gap-2">
				<label class="form-control">
					<span class="label-text text-xs">{$t('ai.askFor')}</span>
					<select class="select select-bordered select-sm" bind:value={kind}>
						{#each Object.keys(KINDS) as k (k)}
							<option value={k}>{kindLabel(k)}</option>
						{/each}
					</select>
				</label>
				<button class="btn btn-outline btn-sm" disabled={busy} onclick={showPrompt}>{$t('ai.review')}</button>
				<button class="btn btn-ghost btn-xs ml-auto" disabled={busy} onclick={() => setOptOut(true)}>{$t('ai.optOut')}</button>
			</div>

			{#if preview}
				<div class="mt-3">
					<p class="mb-1 text-xs text-base-content/60">
						{$t('ai.sentTo', { model: preview.model, provider: preview.provider })}
					</p>
					<details class="mb-1 text-xs">
						<summary class="cursor-pointer text-base-content/60">{$t('ai.instructions')}</summary>
						<pre class="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-base-200 p-2">{preview.prompt.system}</pre>
					</details>
					<pre class="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-base-200 p-2 text-xs">{preview.prompt.user}</pre>
					<div class="mt-2 flex gap-2">
						<button class="btn btn-secondary btn-sm" disabled={busy} onclick={send}>
							{#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
							{$t('ai.send')}
						</button>
						<button class="btn btn-ghost btn-sm" disabled={busy} onclick={() => (preview = null)}>{$t('common.cancel')}</button>
					</div>
				</div>
			{/if}
		{/if}

		{#if proposals.length > 0}
			<ul class="mt-4 space-y-3">
				{#each proposals as p (p.id)}
					<li class="rounded border border-base-300 p-3 text-sm">
						<div class="mb-1 flex flex-wrap items-center gap-2">
							<span class="badge badge-secondary badge-outline badge-sm">{$t('ai.badge', { kind: kindLabel(p.kind) })}</span>
							<span class="badge badge-sm {STATE_CLASS[p.state] ?? ''}">{stateLabel(p.state)}</span>
							{#if p.verdict}<span class="font-medium">{prettyStatus(p.verdict)}</span>{/if}
							{#if p.confidence != null}<span class="text-xs text-base-content/60">{$t('ai.confidence', { pct: fmtNumber(p.confidence, { style: 'percent' }) })}</span>{/if}
							<span class="ml-auto text-xs text-base-content/50">
								{$t('ai.askedBy', { model: p.model, who: p.created_by_email || $t('ai.system'), when: fmtDate(p.created_at) })}
							</span>
						</div>
						{#if p.state === 'invalid'}
							<p class="text-error">{$t('ai.rejectedAnswer', { reason: p.invalid_reason })}</p>
							<details class="text-xs">
								<summary class="cursor-pointer text-base-content/60">{$t('ai.raw')}</summary>
								<pre class="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-base-200 p-2">{p.response}</pre>
							</details>
						{:else}
							<p class="whitespace-pre-wrap">{p.rationale}</p>
							{#if p.fix}
								<p class="mt-2 text-xs font-semibold uppercase text-base-content/50">{$t('ai.suggestedFix')}</p>
								<p class="whitespace-pre-wrap">{p.fix}</p>
							{/if}
							<p class="mt-2 text-xs text-base-content/60">{$t('ai.accepting', { change: change(p) })}</p>
						{/if}
						{#if p.state === 'proposed'}
							<div class="mt-2 flex flex-wrap items-center gap-2">
								<input class="input input-bordered input-xs w-64" placeholder={$t('ai.notePlaceholder')} maxlength="2000" bind:value={notes[p.id]} />
								<button class="btn btn-primary btn-xs" disabled={busy} onclick={() => decide(p, 'accept')}>{$t('ai.accept')}</button>
								<button class="btn btn-ghost btn-xs" disabled={busy} onclick={() => decide(p, 'reject')}>{$t('ai.reject')}</button>
							</div>
						{:else if p.decided_at && (p.state === 'accepted' || p.state === 'rejected')}
							<p class="mt-1 text-xs text-base-content/50">
								{$t('ai.decidedBy', { state: stateLabel(p.state), who: p.decided_by_email || $t('ai.someone'), when: fmtDate(p.decided_at) })}{p.decision_note ? ` — ${p.decision_note}` : ''}
							</p>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</div>
{/if}
