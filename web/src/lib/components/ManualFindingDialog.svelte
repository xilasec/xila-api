<script>
	// Report a finding by hand (pentest, code review, bug bounty). It is filed as
	// scanner "manual" and runs the normal pipeline: triage rules, dedup, SLA,
	// alerts. Picking a template copies its write-up into the form, so what is
	// submitted is exactly what's on screen.
	import { api, errorMessage } from '$lib/api.js';
	import { notify, features, isOn } from '$lib/stores.js';
	import { SEVERITIES, CATEGORIES } from '$lib/format.js';
	import { t, labelOf } from '$lib/i18n.js';
	import Field from '$lib/components/Field.svelte';

	/** @type {{ projectId: string, engagements?: any[], engagementId?: string, oncreated?: (f: any) => void }} */
	let { projectId, engagements = [], engagementId = '', oncreated = () => {} } = $props();

	const blank = () => ({
		title: '', severity: 'medium', category: 'dast', description: '', impact: '', mitigation: '',
		steps_to_reproduce: '', references: '', cwe: '', cve: '', url: '', file_path: '', line: '',
		package: '', package_version: '', tags: '', engagement_id: engagementId, template_id: ''
	});

	/** @type {HTMLDialogElement} */
	let dialog;
	let form = $state(blank());
	let templates = $state(/** @type {any[]} */ ([]));
	let loadedEngagements = $state(/** @type {any[]} */ ([]));
	// The caller may already hold the project's engagements; else fetch them.
	const engagementOptions = $derived(engagements.length ? engagements : loadedEngagements);
	let busy = $state(false);

	export async function open() {
		form = blank();
		dialog.showModal();
		try {
			[templates, loadedEngagements] = await Promise.all([
				api.listFindingTemplates(),
				engagements.length || !isOn($features, 'engagements') ? Promise.resolve([]) : api.listEngagements(projectId)
			]);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	function useTemplate() {
		const t = templates.find((x) => x.id === form.template_id);
		if (!t) return;
		form = {
			...form,
			title: t.title, severity: t.severity, category: t.category, description: t.description,
			impact: t.impact, mitigation: t.mitigation, references: (t.references ?? []).join('\n'),
			cwe: t.cwe ?? '', cve: (t.cve ?? []).join(', '), tags: (t.tags ?? []).join(', ')
		};
	}

	/** @param {string} s @param {string} sep */
	const list = (s, sep) => s.split(sep).map((/** @type {string} */ x) => x.trim()).filter(Boolean);

	/** @param {SubmitEvent} e */
	async function submit(e) {
		e.preventDefault();
		busy = true;
		try {
			const f = await api.createManualFinding(projectId, {
				title: form.title, severity: form.severity, category: form.category,
				description: form.description, impact: form.impact, mitigation: form.mitigation,
				steps_to_reproduce: form.steps_to_reproduce, references: list(form.references, '\n'),
				cwe: form.cwe === '' ? null : Number(form.cwe), cve: list(form.cve, ','),
				url: form.url, file_path: form.file_path, line: form.line === '' ? null : Number(form.line),
				package: form.package, package_version: form.package_version, tags: list(form.tags, ','),
				engagement_id: form.engagement_id, template_id: form.template_id
			});
			dialog.close();
			notify($t('mfd.created'), 'success');
			oncreated(f);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

<dialog bind:this={dialog} class="modal">
	<form class="modal-box max-w-3xl space-y-3" onsubmit={submit}>
		<h3 class="font-bold text-lg">{$t('mfd.title')}</h3>
		{#if templates.length}
			<Field label={$t('mfd.template')} hint={$t('mfd.templateHint')}>
				<select class="select select-bordered select-sm" bind:value={form.template_id} onchange={useTemplate}>
					<option value="">{$t('common.noneDash')}</option>
					{#each templates as t (t.id)}<option value={t.id}>{t.title}</option>{/each}
				</select>
			</Field>
		{/if}
		<Field label={$t('writeup.title')} required>
			<input class="input input-bordered input-sm" bind:value={form.title} required maxlength="300" />
		</Field>
		<div class="grid grid-cols-3 gap-3">
			<Field label={$t('fields.severity')} required>
				<select class="select select-bordered select-sm" bind:value={form.severity}>
					{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
				</select>
			</Field>
			<Field label={$t('mfd.category')}>
				<select class="select select-bordered select-sm" bind:value={form.category}>
					{#each CATEGORIES as c}<option value={c}>{$labelOf('category', c)}</option>{/each}
				</select>
			</Field>
			{#if isOn($features, 'engagements')}
				<Field label={$t('mfd.engagement')}>
					<select class="select select-bordered select-sm" bind:value={form.engagement_id}>
						<option value="">{$t('common.noneDash')}</option>
						{#each engagementOptions as e (e.id)}<option value={e.id}>{e.name}</option>{/each}
					</select>
				</Field>
			{/if}
		</div>
		<Field label={$t('writeup.description')}>
			<textarea class="textarea textarea-bordered textarea-sm h-24" bind:value={form.description}></textarea>
		</Field>
		<Field label={$t('writeup.steps')}>
			<textarea class="textarea textarea-bordered textarea-sm h-20" bind:value={form.steps_to_reproduce}></textarea>
		</Field>
		<div class="grid grid-cols-2 gap-3">
			<Field label={$t('writeup.impact')}>
				<textarea class="textarea textarea-bordered textarea-sm h-16" bind:value={form.impact}></textarea>
			</Field>
			<Field label={$t('writeup.mitigation')}>
				<textarea class="textarea textarea-bordered textarea-sm h-16" bind:value={form.mitigation}></textarea>
			</Field>
		</div>
		<div class="grid grid-cols-3 gap-3">
			<Field label={$t('mfd.fieldUrl')}><input class="input input-bordered input-sm" bind:value={form.url} placeholder="https://app.example.com/api/orders/42" /></Field>
			<Field label={$t('mfd.fieldFile')}><input class="input input-bordered input-sm" bind:value={form.file_path} /></Field>
			<Field label={$t('mfd.fieldLine')}><input class="input input-bordered input-sm" type="number" min="1" bind:value={form.line} /></Field>
			<Field label={$t('finding.cwe')}><input class="input input-bordered input-sm" type="number" min="1" bind:value={form.cwe} placeholder="639" /></Field>
			<Field label={$t('mfd.cves')} hint={$t('it.commaSeparated')}><input class="input input-bordered input-sm" bind:value={form.cve} /></Field>
			<Field label={$t('wf.tags')} hint={$t('it.commaSeparated')}><input class="input input-bordered input-sm" bind:value={form.tags} placeholder="pentest-2025" /></Field>
			<Field label={$t('finding.package')}><input class="input input-bordered input-sm" bind:value={form.package} /></Field>
			<Field label={$t('mfd.fieldPackageVersion')}><input class="input input-bordered input-sm" bind:value={form.package_version} /></Field>
		</div>
		<Field label={$t('writeup.references')} hint={$t('writeup.onePerLine')}>
			<textarea class="textarea textarea-bordered textarea-sm h-16" bind:value={form.references}></textarea>
		</Field>
		<div class="modal-action">
			<button type="button" class="btn btn-sm" onclick={() => dialog.close()}>{$t('common.cancel')}</button>
			<button class="btn btn-sm btn-primary" disabled={busy}>
				{#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('proj.reportFinding')}
			</button>
		</div>
	</form>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
