<script>
	// Report templates: branding and section layout of the printable reports.
	// Anyone printing a report picks one in the Report menu; only instance
	// admins manage them.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import { SEVERITIES } from '#lib/format.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const SECTION_LABELS = {
		summary: 'reporttpl.section.summary',
		severity: 'reporttpl.section.severity',
		compliance: 'reporttpl.section.compliance',
		findings: 'reporttpl.section.findings',
		details: 'reporttpl.section.details',
		projects: 'reporttpl.section.projects'
	};
	const MAX_LOGO = 300_000;
	const blank = () => ({
		name: '', brand: '', classification: '', intro: '', footer: '', accent_color: '', logo: '',
		sections: ['summary', 'severity', 'findings', 'details'], min_severity: 'info', max_findings: 20
	});

	let templates = $state(/** @type {any[]} */ ([]));
	let allSections = $state(Object.keys(SECTION_LABELS));
	let loading = $state(true);
	let saving = $state(false);
	let editing = $state(/** @type {string | null} */ (null)); // null | 'new' | template id
	let form = $state(blank());

	async function load() {
		try {
			const res = await api.listReportTemplates();
			templates = res.templates ?? [];
			if (res.sections?.length) allSections = res.sections;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	function openNew() {
		form = blank();
		editing = 'new';
	}

	/** @param {any} tpl */
	function openEdit(tpl) {
		form = { ...blank(), ...tpl, sections: [...tpl.sections] };
		editing = tpl.id;
	}

	/** @param {string} s */
	function toggle(s) {
		form.sections = form.sections.includes(s) ? form.sections.filter((x) => x !== s) : [...form.sections, s];
	}

	/** @param {string} s @param {number} d */
	function move(s, d) {
		const i = form.sections.indexOf(s);
		const j = i + d;
		if (i < 0 || j < 0 || j >= form.sections.length) return;
		const next = [...form.sections];
		[next[i], next[j]] = [next[j], next[i]];
		form.sections = next;
	}

	/** @param {Event & { currentTarget: HTMLInputElement }} e */
	function pickLogo(e) {
		const file = e.currentTarget.files?.[0];
		if (!file) return;
		if (!['image/png', 'image/jpeg', 'image/svg+xml'].includes(file.type)) {
			notify($t('reporttpl.logoNotImage'));
			return;
		}
		const reader = new FileReader();
		reader.onload = () => {
			const uri = String(reader.result);
			if (uri.length > MAX_LOGO) notify($t('reporttpl.logoTooLarge'));
			else form.logo = uri;
		};
		reader.readAsDataURL(file);
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		const body = { ...form, max_findings: Number(form.max_findings) };
		try {
			if (editing === 'new') await api.createReportTemplate(body);
			else await api.updateReportTemplate(/** @type {string} */ (editing), body);
			editing = null;
			await load();
			notify($t('reporttpl.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} tpl */
	async function remove(tpl) {
		if (!confirm($t('reporttpl.deleteConfirm', { name: tpl.name }))) return;
		try {
			await api.deleteReportTemplate(tpl.id);
			templates = templates.filter((x) => x.id !== tpl.id);
			notify($t('reporttpl.deleted'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('reporttpl.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('reporttpl.intro')}
		</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openNew}>{$t('reporttpl.newButton')}</button>
</div>

{#if editing}
	<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
		<Field label={$t('reporttpl.nameLabel')} required><input bind:value={form.name} required maxlength="200" class="input input-bordered input-sm" placeholder={$t('reporttpl.namePlaceholder')} /></Field>
		<Field label={$t('reporttpl.brandLabel')} hint={$t('reporttpl.brandHint')}><input bind:value={form.brand} maxlength="200" class="input input-bordered input-sm" /></Field>
		<Field label={$t('reporttpl.classificationLabel')} hint={$t('reporttpl.classificationHint')}><input bind:value={form.classification} maxlength="200" class="input input-bordered input-sm" /></Field>
		<Field label={$t('reporttpl.accentLabel')}>
			<div class="flex items-center gap-2">
				<input type="color" class="h-8 w-12" value={form.accent_color || '#1f2937'} oninput={(e) => (form.accent_color = e.currentTarget.value)} />
				<span class="text-xs font-mono">{form.accent_color || $t('reporttpl.default')}</span>
				{#if form.accent_color}<button type="button" class="btn btn-ghost btn-xs" onclick={() => (form.accent_color = '')}>{$t('reporttpl.resetButton')}</button>{/if}
			</div>
		</Field>
		<Field label={$t('reporttpl.logoLabel')} hint={$t('reporttpl.logoHint')}>
			<div class="flex items-center gap-2">
				<input type="file" accept="image/png,image/jpeg,image/svg+xml" class="file-input file-input-bordered file-input-sm" onchange={pickLogo} />
				{#if form.logo}<img src={form.logo} alt={$t('reporttpl.logoAlt')} class="max-h-8" /><button type="button" class="btn btn-ghost btn-xs" onclick={() => (form.logo = '')}>{$t('reporttpl.removeButton')}</button>{/if}
			</div>
		</Field>
		<div class="grid grid-cols-2 gap-3">
			<Field label={$t('reporttpl.minSeverityLabel')} hint={$t('reporttpl.minSeverityHint')}>
				<select bind:value={form.min_severity} class="select select-bordered select-sm">{#each [...SEVERITIES].reverse() as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}</select>
			</Field>
			<Field label={$t('reporttpl.findingsListedLabel')}><input type="number" min="1" max="500" bind:value={form.max_findings} class="input input-bordered input-sm" /></Field>
		</div>
		<div class="md:col-span-2">
			<span class="label-text font-medium">{$t('reporttpl.sectionsLabel')} <span class="text-base-content/50 font-normal">{$t('reporttpl.sectionsHint')}</span></span>
			<ul class="mt-1 space-y-1">
				{#each [...form.sections, ...allSections.filter((s) => !form.sections.includes(s))] as s (s)}
					<li class="flex items-center gap-2 text-sm">
						<input type="checkbox" class="checkbox checkbox-sm" checked={form.sections.includes(s)} onchange={() => toggle(s)} />
						<span class="flex-1" class:text-base-content={form.sections.includes(s)} class:opacity-50={!form.sections.includes(s)}>{SECTION_LABELS[s] ? $t(SECTION_LABELS[s]) : s}</span>
						{#if form.sections.includes(s)}
							<button type="button" class="btn btn-ghost btn-xs" aria-label={$t('reporttpl.moveUp')} onclick={() => move(s, -1)}>↑</button>
							<button type="button" class="btn btn-ghost btn-xs" aria-label={$t('reporttpl.moveDown')} onclick={() => move(s, 1)}>↓</button>
						{/if}
					</li>
				{/each}
			</ul>
		</div>
		<div class="md:col-span-2">
			<Field label={$t('reporttpl.introLabel')} hint={$t('reporttpl.introHint')}><textarea bind:value={form.intro} class="textarea textarea-bordered textarea-sm h-24 w-full"></textarea></Field>
		</div>
		<div class="md:col-span-2">
			<Field label={$t('reporttpl.footerLabel')}><textarea bind:value={form.footer} class="textarea textarea-bordered textarea-sm h-16 w-full"></textarea></Field>
		</div>
		<div class="md:col-span-2 flex justify-end gap-2">
			<button type="button" class="btn btn-sm" onclick={() => (editing = null)}>{$t('reporttpl.cancelButton')}</button>
			<button class="btn btn-sm btn-primary" disabled={saving || form.sections.length === 0}>{editing === 'new' ? $t('reporttpl.createButton') : $t('reporttpl.saveButton')}</button>
		</div>
	</form>
{/if}

<State {loading} empty={!loading && templates.length === 0} emptyText={$t('reporttpl.empty')} />

{#if !loading && templates.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('reporttpl.colName')}</th><th>{$t('reporttpl.colBrand')}</th><th>{$t('reporttpl.colSections')}</th><th>{$t('reporttpl.colFindings')}</th><th></th></tr></thead>
			<tbody>
				{#each templates as tpl (tpl.id)}
					<tr>
						<td class="font-medium">{#if tpl.accent_color}<span class="inline-block w-2 h-2 rounded-full mr-1" style:background={tpl.accent_color}></span>{/if}{tpl.name}</td>
						<td class="text-xs">{tpl.brand || '—'}</td>
						<td class="text-xs">{tpl.sections.join(' → ')}</td>
						<td class="text-xs">{tpl.max_findings}, ≥ {tpl.min_severity}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => openEdit(tpl)}>{$t('reporttpl.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(tpl)}>{$t('reporttpl.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
