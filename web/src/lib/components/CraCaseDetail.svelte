<script>
	// One CRA Article 14 reporting case: its clock, the report content, the
	// next submission, and the history of who did what.
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t, labelOf } from '$lib/i18n.js';
	import { fmtDate } from '$lib/format.js';
	import { stageLabel, stateLabel, stateClass, deadlineClass, deadlineLabel, countdown } from '$lib/cra.js';
	import State from '$lib/components/State.svelte';

	/** @type {{ caseId: string, onchange?: () => void }} */
	let { caseId, onchange } = $props();

	let c = $state(/** @type {any} */ (null));
	let events = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let error = $state('');
	let busy = $state(false);
	let now = $state(Date.now());
	let form = $state({ exploitation: '', corrective_measures: '', user_mitigations: '', impact: '', malicious_actor: '', sensitivity: '', corrective_available_at: '' });
	let reference = $state('');
	let note = $state('');
	let reason = $state('');

	const SENSITIVITIES = ['', 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];

	/** ISO → value for <input type="datetime-local"> (local time). @param {string | null} iso */
	function toLocal(iso) {
		if (!iso) return '';
		const d = new Date(iso);
		return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
	}

	/** @param {any} data */
	function show(data) {
		c = data.case;
		events = data.events ?? [];
		form = {
			exploitation: c.exploitation,
			corrective_measures: c.corrective_measures,
			user_mitigations: c.user_mitigations,
			impact: c.impact,
			malicious_actor: c.malicious_actor,
			sensitivity: c.sensitivity,
			corrective_available_at: toLocal(c.corrective_available_at)
		};
	}

	async function load() {
		loading = true;
		error = '';
		try {
			show(await api.craCase(caseId));
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		caseId;
		load();
	});
	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(t);
	});

	/** @param {() => Promise<any>} fn @param {string} done */
	async function act(fn, done) {
		busy = true;
		try {
			await fn();
			show(await api.craCase(caseId));
			notify(done, 'success');
			onchange?.();
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('cracase.forbidden') : errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {SubmitEvent} e */
	function save(e) {
		e.preventDefault();
		/** @type {Record<string, string | null>} */
		const edit = {
			exploitation: form.exploitation,
			corrective_measures: form.corrective_measures,
			user_mitigations: form.user_mitigations,
			impact: form.impact,
			malicious_actor: form.malicious_actor,
			sensitivity: form.sensitivity
		};
		if (form.corrective_available_at && form.corrective_available_at !== toLocal(c.corrective_available_at)) {
			edit.corrective_available_at = new Date(form.corrective_available_at).toISOString();
		}
		act(() => api.updateCRACase(caseId, edit), $t('cracase.detailsSaved'));
	}

	function submitNext() {
		const stage = c.next_stage;
		act(() => api.submitCRACase(caseId, { stage, reference, note }), $t('cracase.recordedSubmitted', { stage: stageLabel(stage) })).then(() => {
			reference = '';
			note = '';
		});
	}

	/** @param {string} stage */
	function download(stage) {
		api.downloadCRAReport(caseId, stage, c.vuln_id).catch((err) => notify(errorMessage(err)));
	}

	let active = $derived(c && c.state !== 'closed' && c.state !== 'dismissed');
</script>

<State {loading} {error} />
{#if !loading && !error && c}
	<div class="flex flex-col gap-4">
		<div class="flex flex-wrap items-start gap-3">
			<div class="flex-1 min-w-0">
				<h3 class="font-semibold text-lg">{c.vuln_id} <span class="badge {stateClass(c.state)} badge-sm align-middle">{stateLabel(c.state)}</span></h3>
				<p class="text-sm text-base-content/70">{c.title}</p>
				<p class="text-xs text-base-content/50">
					{c.product_name || c.project_name}{c.product_version ? ` ${c.product_version}` : ''} ·
					{c.trigger === 'kev' ? $t('cracase.triggerKev') : c.trigger === 'weaponized' ? $t('cracase.triggerWeaponized') : $t('cracase.triggerManual')} ·
					{$t('cracase.aware', { date: fmtDate(c.aware_at) })}
					{#if c.finding}· <a class="link" href="/findings/{c.finding.id}">{$t('appr.colFinding')}</a> ({$labelOf('status', c.finding.status)}){/if}
				</p>
				{#if c.dismissed_reason}<p class="text-sm mt-1">{$t('cracase.dismissed', { reason: c.dismissed_reason })}</p>{/if}
			</div>
		</div>

		<div class="overflow-x-auto">
			<table class="table table-sm">
				<thead><tr><th>{$t('cracase.colSubmission')}</th><th>{$t('cracase.colDue')}</th><th>{$t('cracase.colStatus')}</th><th>{$t('cracase.colSent')}</th><th class="text-right">{$t('cracase.colPayload')}</th></tr></thead>
				<tbody>
					{#each c.deadlines as d (d.stage)}
						<tr class:bg-base-200={d.stage === c.next_stage}>
							<td>{stageLabel(d.stage)}</td>
							<td>
								{#if d.due_at}{fmtDate(d.due_at)}{#if !d.sent_at && active}<div class="text-xs {d.status === 'missed' ? 'text-error' : 'text-base-content/60'}">{countdown(d.due_at, now)}</div>{/if}
								{:else}<span class="text-xs text-base-content/50">{$t('cracase.startsWhenFix')}</span>{/if}
							</td>
							<td><span class="badge badge-sm {deadlineClass(d.status)}">{deadlineLabel(d.status)}</span></td>
							<td>{fmtDate(d.sent_at)}</td>
							<td class="text-right"><button class="btn btn-ghost btn-xs" onclick={() => download(d.stage)}>{$t('cracase.json')}</button></td>
						</tr>
					{/each}
				</tbody>
			</table>
			<p class="text-xs text-base-content/50 mt-1">{$t('cracase.jsonNote')}</p>
		</div>

		{#if active}
			<div class="flex flex-wrap items-end gap-2">
				{#if c.next_stage}
					<label class="form-control">
						<span class="label-text text-xs">{$t('cracase.platformReference')}</span>
						<input class="input input-bordered input-sm" bind:value={reference} placeholder={$t('common.optional')} />
					</label>
					<label class="form-control">
						<span class="label-text text-xs">{$t('cracase.note')}</span>
						<input class="input input-bordered input-sm" bind:value={note} placeholder={$t('common.optional')} />
					</label>
					<button class="btn btn-primary btn-sm" disabled={busy} onclick={submitNext}>{$t('cracase.recordSent', { stage: stageLabel(c.next_stage) })}</button>
				{:else if c.state === 'final_report_sent'}
					<button class="btn btn-primary btn-sm" disabled={busy} onclick={() => act(() => api.closeCRACase(caseId), $t('cracase.caseClosed'))}>{$t('cracase.closeCase')}</button>
				{/if}
				{#if c.state !== 'final_report_sent'}
					<div class="flex items-end gap-2 ml-auto">
						<label class="form-control">
							<span class="label-text text-xs">{$t('cracase.dismissReasonLabel')}</span>
							<input class="input input-bordered input-sm" bind:value={reason} placeholder={$t('cracase.dismissReasonPlaceholder')} />
						</label>
						<button class="btn btn-outline btn-sm" disabled={busy || !reason.trim()}
							onclick={() => act(() => api.dismissCRACase(caseId, reason), $t('cracase.caseDismissed'))}>{$t('cracase.dismiss')}</button>
					</div>
				{/if}
			</div>

			<form class="grid gap-2 md:grid-cols-2" onsubmit={save}>
				<label class="form-control md:col-span-2">
					<span class="label-text text-xs">{$t('cracase.exploitationLabel')}</span>
					<textarea class="textarea textarea-bordered textarea-sm" rows="2" bind:value={form.exploitation}></textarea>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.correctiveLabel')}</span>
					<textarea class="textarea textarea-bordered textarea-sm" rows="2" bind:value={form.corrective_measures}></textarea>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.userMitigationsLabel')}</span>
					<textarea class="textarea textarea-bordered textarea-sm" rows="2" bind:value={form.user_mitigations}></textarea>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.impactLabel')}</span>
					<textarea class="textarea textarea-bordered textarea-sm" rows="2" bind:value={form.impact}></textarea>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.maliciousActorLabel')}</span>
					<textarea class="textarea textarea-bordered textarea-sm" rows="2" bind:value={form.malicious_actor}></textarea>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.sensitivityLabel')}</span>
					<select class="select select-bordered select-sm" bind:value={form.sensitivity}>
						{#each SENSITIVITIES as s}<option value={s}>{s || '—'}</option>{/each}
					</select>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cracase.correctiveAvailableLabel')}</span>
					<input type="datetime-local" class="input input-bordered input-sm" bind:value={form.corrective_available_at} />
				</label>
				<div class="md:col-span-2"><button class="btn btn-sm" type="submit" disabled={busy}>{$t('cracase.saveDetails')}</button></div>
			</form>
		{/if}

		<div>
			<h4 class="font-semibold text-sm mb-1">{$t('cracase.history')}</h4>
			<ul class="text-sm flex flex-col gap-1">
				{#each events as e (e.id)}
					<li>
						<span class="text-base-content/50">{fmtDate(e.created_at)}</span> ·
						{e.stage ? $t('cracase.stageSubmitted', { stage: stageLabel(e.stage) }) : e.from_state === e.to_state ? $t('cracase.detailsUpdated') : stateLabel(e.to_state)}
						{#if e.reference}<span class="badge badge-ghost badge-sm">{e.reference}</span>{/if}
						· {e.actor_email || $t('cracase.systemActor')}
						{#if e.note}<span class="text-base-content/60"> — {e.note}</span>{/if}
					</li>
				{/each}
			</ul>
		</div>
	</div>
{/if}
