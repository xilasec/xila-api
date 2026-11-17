<script>
	// Custom parsers (instance admin, M12 12.4): map the fields of any CSV,
	// JSON or XML report onto findings without writing a Go parser. Field
	// mappings are edited as JSON here (one object per ParsedFinding field ->
	// {path|template|value, value_map}); the dry-run preview lets an admin
	// check the mapping against a pasted sample before saving.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	const CATEGORIES = ['sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license', 'cloud', 'kubernetes'];
	const FORMATS = ['csv', 'json', 'xml'];

	let loading = $state(true);
	let error = $state('');
	let parsers = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);
	let editing = $state(/** @type {any} */ (null));
	const blankFields = () =>
		JSON.stringify({ title: { path: 'name' }, severity: { path: 'severity' } }, null, 2);
	const blank = () => ({ name: '', category: 'sca', format: 'csv', record_selector: '', fieldsText: blankFields() });
	let form = $state(blank());
	let sample = $state('');
	let preview = $state(/** @type {any} */ (null));
	let previewError = $state('');
	let previewing = $state(false);

	async function load() {
		loading = true;
		error = '';
		try {
			parsers = await api.listCustomParsers();
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {any} p */
	function edit(p) {
		editing = p;
		form = {
			name: p.name, category: p.category, format: p.format, record_selector: p.record_selector ?? '',
			fieldsText: JSON.stringify(p.fields ?? {}, null, 2)
		};
		preview = null;
		previewError = '';
	}

	function reset() {
		editing = null;
		form = blank();
		preview = null;
		previewError = '';
	}

	/** @returns {{ name: string, category: string, format: string, record_selector: string, fields: any } | null} */
	function parseDefinition() {
		try {
			const fields = JSON.parse(form.fieldsText);
			return { name: form.name.trim(), category: form.category, format: form.format, record_selector: form.record_selector, fields };
		} catch {
			notify($t('customparsers.invalidJson'));
			return null;
		}
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		const def = parseDefinition();
		if (!def) return;
		saving = true;
		try {
			if (editing) await api.updateCustomParser(editing.id, def);
			else await api.createCustomParser(def);
			notify(editing ? $t('customparsers.updated') : $t('customparsers.created'), 'success');
			reset();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} p */
	async function remove(p) {
		if (!confirm($t('customparsers.deleteConfirm', { name: p.name }))) return;
		try {
			await api.deleteCustomParser(p.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function dryRun() {
		const def = parseDefinition();
		if (!def) return;
		previewing = true;
		previewError = '';
		preview = null;
		try {
			preview = await api.dryRunCustomParser(def, sample);
		} catch (err) {
			previewError = errorMessage(err);
		} finally {
			previewing = false;
		}
	}

	onMount(load);
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('customparsers.title')}</h1>
	<p class="text-sm text-base-content/60">{$t('customparsers.intro')}</p>
</div>

<form onsubmit={save} class="card bg-base-100 shadow-sm mb-4">
	<div class="card-body grid gap-3 md:grid-cols-2">
		<Field label={$t('customparsers.nameLabel')} hint={$t('customparsers.nameHint')}>
			<input bind:value={form.name} required pattern={'[a-z][a-z0-9-]{1,63}'} disabled={!!editing}
				class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<Field label={$t('customparsers.categoryLabel')}>
			<select bind:value={form.category} class="select select-bordered select-sm w-full">
				{#each CATEGORIES as c}<option value={c}>{c}</option>{/each}
			</select>
		</Field>
		<Field label={$t('customparsers.formatLabel')}>
			<select bind:value={form.format} class="select select-bordered select-sm w-full">
				{#each FORMATS as f}<option value={f}>{f}</option>{/each}
			</select>
		</Field>
		<Field label={$t('customparsers.selectorLabel')} hint={$t('customparsers.selectorHint')}>
			<input bind:value={form.record_selector} class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<div class="md:col-span-2">
			<Field label={$t('customparsers.fieldsLabel')} hint={$t('customparsers.fieldsHint')}>
				<textarea bind:value={form.fieldsText} rows="8" class="textarea textarea-bordered w-full font-mono text-xs"></textarea>
			</Field>
		</div>
		<div class="md:col-span-2">
			<Field label={$t('customparsers.sampleLabel')} hint={$t('customparsers.sampleHint')}>
				<textarea bind:value={sample} rows="6" class="textarea textarea-bordered w-full font-mono text-xs"></textarea>
			</Field>
		</div>
		<div class="md:col-span-2 flex justify-end gap-2">
			<button type="button" class="btn btn-ghost btn-sm" disabled={previewing} onclick={dryRun}>{$t('customparsers.dryRunButton')}</button>
			{#if editing}<button type="button" class="btn btn-ghost btn-sm" onclick={reset}>{$t('customparsers.cancel')}</button>{/if}
			<button class="btn btn-primary btn-sm" disabled={saving}>{editing ? $t('customparsers.saveButton') : $t('customparsers.addButton')}</button>
		</div>
		{#if previewError}
			<div class="md:col-span-2 alert alert-error"><span>{previewError}</span></div>
		{/if}
		{#if preview}
			<div class="md:col-span-2">
				<h3 class="font-semibold text-sm mb-1">{$t('customparsers.previewTitle')}</h3>
				{#if (preview.findings ?? []).length === 0}
					<p class="text-sm text-base-content/60">{$t('customparsers.previewEmpty')}</p>
				{:else}
					<div class="overflow-x-auto bg-base-200 rounded-box">
						<table class="table table-xs">
							<thead><tr><th>title</th><th>severity</th><th>cve</th><th>rule_id</th></tr></thead>
							<tbody>
								{#each preview.findings as f}
									<tr><td>{f.title}</td><td>{f.severity}</td><td>{(f.cve ?? []).join(', ')}</td><td>{f.rule_id}</td></tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
				{#if (preview.record_errors ?? []).length > 0}
					<h4 class="font-semibold text-xs mt-2">{$t('customparsers.recordErrors')}</h4>
					<ul class="text-xs text-error">
						{#each preview.record_errors as re}<li>#{re.index}: {re.error}</li>{/each}
					</ul>
				{/if}
			</div>
		{/if}
	</div>
</form>

<State {loading} {error} empty={!loading && !error && parsers.length === 0} emptyText={$t('customparsers.empty')} />
{#if !loading && parsers.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('customparsers.colName')}</th><th>{$t('customparsers.colCategory')}</th><th>{$t('customparsers.colFormat')}</th><th></th></tr></thead>
			<tbody>
				{#each parsers as p (p.id)}
					<tr class="hover">
						<td class="font-mono text-xs">{p.name}</td>
						<td>{p.category}</td>
						<td>{p.format}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => edit(p)}>{$t('customparsers.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(p)}>{$t('customparsers.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
