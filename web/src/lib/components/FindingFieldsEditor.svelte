<script>
	// Inline edit of a finding's title, severity and planned remediation date.
	// A title / severity set here overrides the scanner's and survives re-scans
	// until reset. Saves with If-Match: if someone else changed the finding in
	// the meantime, nothing is written and the page reloads with their version.
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { SEVERITIES } from '$lib/format.js';
	import { t, labelOf } from '$lib/i18n.js';

	/** @type {{ finding: any, onsaved: (f: any) => void, onconflict: () => void }} */
	let { finding, onsaved, onconflict } = $props();

	let open = $state(false);
	let saving = $state(false);
	let form = $state({ title: '', severity: '', planned: '' });

	function start() {
		form = {
			title: finding.title,
			severity: finding.severity,
			planned: finding.planned_remediation_at ? String(finding.planned_remediation_at).slice(0, 10) : ''
		};
		open = true;
	}

	/** @param {Record<string, any>} body */
	async function save(body) {
		saving = true;
		try {
			const f = await api.editFindingFields(finding.id, body, finding.updated_at);
			open = false;
			onsaved(f);
		} catch (err) {
			if (err instanceof ApiError && err.status === 412) {
				notify($t('fields.conflict'));
				open = false;
				onconflict();
			} else {
				notify(errorMessage(err));
			}
		} finally {
			saving = false;
		}
	}

	/** @param {SubmitEvent} e */
	function submit(e) {
		e.preventDefault();
		/** @type {Record<string, any>} */
		const body = {};
		if (form.title.trim() !== finding.title) body.title = form.title.trim();
		if (form.severity !== finding.severity) body.severity = form.severity;
		const current = finding.planned_remediation_at ? String(finding.planned_remediation_at).slice(0, 10) : '';
		if (form.planned !== current) body.planned_remediation_at = form.planned || null;
		if (Object.keys(body).length === 0) {
			open = false;
			return;
		}
		save(body);
	}
</script>

{#if !open}
	<div class="flex flex-wrap items-center gap-2 text-xs">
		<button class="btn btn-ghost btn-xs" onclick={start} title={$t('fields.editTitle')}>{$t('common.edit')}</button>
		{#if finding.title_manual}
			<span class="badge badge-outline badge-xs" title={$t('fields.editedTitleTitle')}>{$t('fields.editedTitle')}</span>
			<button class="link link-hover text-base-content/60" disabled={saving} onclick={() => save({ reset_title: true })}>{$t('fields.useScanner')}</button>
		{/if}
		{#if finding.severity_manual}
			<span class="badge badge-outline badge-xs" title={$t('fields.manualSeverityTitle')}>{$t('fields.manualSeverity')}</span>
			<button class="link link-hover text-base-content/60" disabled={saving} onclick={() => save({ reset_severity: true })}>{$t('fields.useScanner')}</button>
		{/if}
	</div>
{:else}
	<form onsubmit={submit} class="mt-2 grid gap-2 rounded-box bg-base-200 p-3 md:grid-cols-[1fr_auto_auto_auto] md:items-end">
		<label class="form-control">
			<span class="label-text text-xs">{$t('fields.title')}</span>
			<input bind:value={form.title} required class="input input-bordered input-sm w-full" />
		</label>
		<label class="form-control">
			<span class="label-text text-xs">{$t('fields.severity')}</span>
			<select bind:value={form.severity} class="select select-bordered select-sm capitalize">
				{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
			</select>
		</label>
		<label class="form-control">
			<span class="label-text text-xs">{$t('fields.plannedFix')}</span>
			<input type="date" bind:value={form.planned} class="input input-bordered input-sm" />
		</label>
		<div class="flex gap-1">
			<button class="btn btn-primary btn-sm" disabled={saving}>
				{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('common.save')}
			</button>
			<button type="button" class="btn btn-ghost btn-sm" onclick={() => (open = false)}>{$t('common.cancel')}</button>
		</div>
		<p class="text-xs text-base-content/60 md:col-span-4">
			{$t('fields.note')}
		</p>
	</form>
{/if}
