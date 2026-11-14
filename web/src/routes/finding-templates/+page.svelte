<script>
	// Finding templates: a team's standard write-ups for manual findings. Anyone
	// reporting a finding can pick one; only instance admins manage them.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t, labelOf } from '$lib/i18n.js';
	import { SEVERITIES, CATEGORIES } from '$lib/format.js';
	import State from '$lib/components/State.svelte';
	import Field from '$lib/components/Field.svelte';
	import Badge from '$lib/components/Badge.svelte';

	const blank = () => ({ title: '', severity: 'medium', category: 'dast', cwe: '', cve: '', description: '', impact: '', mitigation: '', references: '', tags: '' });

	let templates = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);
	let editing = $state(/** @type {string | null} */ (null)); // null | 'new' | template id
	let form = $state(blank());

	/** @param {string} s @param {string} sep */
	const list = (s, sep) => s.split(sep).map((/** @type {string} */ x) => x.trim()).filter(Boolean);

	async function load() {
		try {
			templates = await api.listFindingTemplates();
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
		form = {
			title: tpl.title, severity: tpl.severity, category: tpl.category, cwe: tpl.cwe ?? '', cve: tpl.cve.join(', '),
			description: tpl.description, impact: tpl.impact, mitigation: tpl.mitigation,
			references: tpl.references.join('\n'), tags: tpl.tags.join(', ')
		};
		editing = tpl.id;
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		const body = {
			...form, cwe: form.cwe === '' ? null : Number(form.cwe), cve: list(form.cve, ','),
			references: list(form.references, '\n'), tags: list(form.tags, ',')
		};
		try {
			if (editing === 'new') await api.createFindingTemplate(body);
			else await api.updateFindingTemplate(/** @type {string} */ (editing), body);
			editing = null;
			await load();
			notify($t('findingtpl.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} tpl */
	async function remove(tpl) {
		if (!confirm($t('findingtpl.deleteConfirm', { title: tpl.title }))) return;
		try {
			await api.deleteFindingTemplate(tpl.id);
			templates = templates.filter((x) => x.id !== tpl.id);
			notify($t('findingtpl.deleted'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('findingtpl.title')}</h1>
		<p class="text-sm text-base-content/60">
			{$t('findingtpl.intro')}
		</p>
	</div>
	<button class="btn btn-primary btn-sm" onclick={openNew}>{$t('findingtpl.newButton')}</button>
</div>

{#if editing}
	<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
		<div class="md:col-span-2">
			<Field label={$t('findingtpl.titleLabel')} required><input bind:value={form.title} required maxlength="300" class="input input-bordered input-sm w-full" placeholder={$t('findingtpl.titlePlaceholder')} /></Field>
		</div>
		<Field label={$t('findingtpl.severityLabel')} required>
			<select bind:value={form.severity} class="select select-bordered select-sm">{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}</select>
		</Field>
		<Field label={$t('findingtpl.categoryLabel')}>
			<select bind:value={form.category} class="select select-bordered select-sm">{#each CATEGORIES as c}<option value={c}>{$labelOf('category', c)}</option>{/each}</select>
		</Field>
		<Field label={$t('findingtpl.cweLabel')}><input type="number" min="1" bind:value={form.cwe} class="input input-bordered input-sm" placeholder="319" /></Field>
		<Field label={$t('findingtpl.cveLabel')} hint={$t('findingtpl.commaSeparated')}><input bind:value={form.cve} class="input input-bordered input-sm" /></Field>
		<div class="md:col-span-2">
			<Field label={$t('findingtpl.descriptionLabel')}><textarea bind:value={form.description} class="textarea textarea-bordered textarea-sm h-24 w-full"></textarea></Field>
		</div>
		<Field label={$t('findingtpl.impactLabel')}><textarea bind:value={form.impact} class="textarea textarea-bordered textarea-sm h-20"></textarea></Field>
		<Field label={$t('findingtpl.mitigationLabel')}><textarea bind:value={form.mitigation} class="textarea textarea-bordered textarea-sm h-20"></textarea></Field>
		<Field label={$t('findingtpl.referencesLabel')} hint={$t('findingtpl.oneLine')}><textarea bind:value={form.references} class="textarea textarea-bordered textarea-sm h-16"></textarea></Field>
		<Field label={$t('findingtpl.tagsLabel')} hint={$t('findingtpl.commaSeparated')}><input bind:value={form.tags} class="input input-bordered input-sm" /></Field>
		<div class="md:col-span-2 flex justify-end gap-2">
			<button type="button" class="btn btn-sm" onclick={() => (editing = null)}>{$t('findingtpl.cancelButton')}</button>
			<button class="btn btn-sm btn-primary" disabled={saving}>{editing === 'new' ? $t('findingtpl.createButton') : $t('findingtpl.saveButton')}</button>
		</div>
	</form>
{/if}

<State {loading} empty={!loading && templates.length === 0} emptyText={$t('findingtpl.empty')} />

{#if !loading && templates.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('findingtpl.colTitle')}</th><th>{$t('findingtpl.colSeverity')}</th><th>{$t('findingtpl.colCategory')}</th><th>{$t('findingtpl.colCwe')}</th><th>{$t('findingtpl.colTags')}</th><th></th></tr></thead>
			<tbody>
				{#each templates as tpl (tpl.id)}
					<tr>
						<td class="font-medium">{tpl.title}</td>
						<td><Badge kind="severity" value={tpl.severity} /></td>
						<td class="text-xs">{tpl.category}</td>
						<td class="text-xs">{tpl.cwe ? `CWE-${tpl.cwe}` : '—'}</td>
						<td class="text-xs">{tpl.tags.join(', ') || '—'}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => openEdit(tpl)}>{$t('findingtpl.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(tpl)}>{$t('findingtpl.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
