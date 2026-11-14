<script>
	// Advisory feed rules (admin): mute, re-rate or tag incoming advisories
	// before they're matched against inventory.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t, labelOf } from '$lib/i18n.js';
	import State from '$lib/components/State.svelte';
	import Field from '$lib/components/Field.svelte';
	import { SEVERITIES } from '$lib/format.js';

	const ACTIONS = [
		{ id: 'mute', label: 'feedrules.muteAction' },
		{ id: 'set_severity', label: 'feedrules.setSeverityAction' },
		{ id: 'add_tags', label: 'feedrules.addTagsActionOpt' }
	];
	let loading = $state(true);
	let error = $state('');
	let rules = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);
	let editing = $state(/** @type {any} */ (null));
	const blank = () => ({
		name: '', description: '', enabled: true, position: 0, sources: '', id_glob: '', ecosystems: '', package_glob: '',
		severities: /** @type {string[]} */ ([]), cvss_min: '', cvss_max: '', expression: '', action: 'mute', severity: 'low', tags: ''
	});
	let form = $state(blank());

	async function load() {
		loading = true;
		error = '';
		try {
			rules = await api.listFeedRules();
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {string} s */
	const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
	/** @param {any} v */
	const num = (v) => (v === '' || v === null || v === undefined ? null : Number(v));

	/** @param {any} r */
	function edit(r) {
		editing = r;
		form = {
			name: r.name, description: r.description, enabled: r.enabled, position: r.position,
			sources: (r.sources ?? []).join(', '), id_glob: r.id_glob, ecosystems: (r.ecosystems ?? []).join(', '),
			package_glob: r.package_glob, severities: [...(r.severities ?? [])], cvss_min: r.cvss_min ?? '',
			cvss_max: r.cvss_max ?? '', expression: r.expression, action: r.action, severity: r.severity || 'low',
			tags: (r.tags ?? []).join(', ')
		};
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		const body = {
			name: form.name, description: form.description, enabled: form.enabled, position: Number(form.position) || 0,
			sources: list(form.sources), id_glob: form.id_glob.trim(), ecosystems: list(form.ecosystems),
			package_glob: form.package_glob.trim(), severities: form.severities, cvss_min: num(form.cvss_min),
			cvss_max: num(form.cvss_max), expression: form.expression.trim(), action: form.action,
			severity: form.action === 'set_severity' ? form.severity : '', tags: form.action === 'add_tags' ? list(form.tags) : []
		};
		try {
			if (editing) await api.updateFeedRule(editing.id, body);
			else await api.createFeedRule(body);
			editing = null;
			form = blank();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} r */
	async function remove(r) {
		if (!confirm($t('feedrules.deleteConfirm', { name: r.name }))) return;
		try {
			await api.deleteFeedRule(r.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {string} s */
	function toggleSeverity(s) {
		form.severities = form.severities.includes(s) ? form.severities.filter((x) => x !== s) : [...form.severities, s];
	}

	/** @param {any} r */
	const what = (r) =>
		[r.sources?.length && $t('feedrules.fromLabel', { sources: r.sources.join('/') }), r.id_glob && $t('feedrules.idLabel', { glob: r.id_glob }), r.ecosystems?.length && r.ecosystems.join('/'),
			r.package_glob && $t('feedrules.pkgLabel', { glob: r.package_glob }), r.severities?.length && r.severities.join('/'),
			r.cvss_min != null && $t('feedrules.cvssGe', { value: r.cvss_min }), r.cvss_max != null && $t('feedrules.cvssLe', { value: r.cvss_max }), r.expression && `⟨${r.expression}⟩`]
			.filter(Boolean).join(' · ') || $t('feedrules.everyAdvisory');

	onMount(load);
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('feedrules.title')}</h1>
	<p class="text-sm text-base-content/60">
		{$t('feedrules.intro', { setSeverity: $t('feedrules.setSeverity'), addTags: $t('feedrules.addTagsAction') })}
	</p>
</div>

<form onsubmit={save} class="card bg-base-100 shadow-sm mb-4">
	<div class="card-body grid gap-3 md:grid-cols-3">
		<Field label={$t('feedrules.nameLabel')} required><input bind:value={form.name} required class="input input-bordered input-sm w-full" /></Field>
		<Field label={$t('feedrules.actionLabel')}>
			<select bind:value={form.action} class="select select-bordered select-sm w-full">
				{#each ACTIONS as a}<option value={a.id}>{$t(/** @type {import('$lib/i18n.js').MessageKey} */ (a.label))}</option>{/each}
			</select>
		</Field>
		{#if form.action === 'set_severity'}
			<Field label={$t('feedrules.severityLabel')}>
				<select bind:value={form.severity} class="select select-bordered select-sm w-full">
					{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
				</select>
			</Field>
		{:else if form.action === 'add_tags'}
			<Field label={$t('feedrules.tagsLabel')} hint={$t('feedrules.tagsHint')}><input bind:value={form.tags} class="input input-bordered input-sm w-full" /></Field>
		{:else}
			<div></div>
		{/if}
		<Field label={$t('feedrules.sourcesLabel')} hint={$t('feedrules.sourcesHint')}><input bind:value={form.sources} class="input input-bordered input-sm w-full" /></Field>
		<Field label={$t('feedrules.idGlobLabel')}><input bind:value={form.id_glob} placeholder="GHSA-*" class="input input-bordered input-sm w-full font-mono" /></Field>
		<Field label={$t('feedrules.ecosystemsLabel')} hint={$t('feedrules.ecosystemsHint')}><input bind:value={form.ecosystems} class="input input-bordered input-sm w-full" /></Field>
		<Field label={$t('feedrules.packageGlobLabel')}><input bind:value={form.package_glob} placeholder="@babel/*" class="input input-bordered input-sm w-full font-mono" /></Field>
		<Field label={$t('feedrules.cvssFromLabel')}><input type="number" step="0.1" min="0" max="10" bind:value={form.cvss_min} class="input input-bordered input-sm w-full" /></Field>
		<Field label={$t('feedrules.cvssToLabel')}><input type="number" step="0.1" min="0" max="10" bind:value={form.cvss_max} class="input input-bordered input-sm w-full" /></Field>
		<div class="md:col-span-3">
			<span class="label-text font-medium">{$t('feedrules.severitiesLabel')}</span>
			<div class="flex gap-1 mt-1">
				{#each SEVERITIES as s}
					<button type="button" class="btn btn-xs" class:btn-primary={form.severities.includes(s)} onclick={() => toggleSeverity(s)}>{$labelOf('severity', s)}</button>
				{/each}
			</div>
		</div>
		<div class="md:col-span-3"><Field label={$t('feedrules.expressionLabel')}>
			<input bind:value={form.expression} class="input input-bordered input-sm w-full font-mono" placeholder={'advisory.cvss < 4.0 && pkg.ecosystem == "npm"'} />
		</Field></div>
		<label class="label cursor-pointer justify-start gap-2">
			<input type="checkbox" class="checkbox checkbox-sm" bind:checked={form.enabled} /><span class="label-text">{$t('feedrules.enabledLabel')}</span>
		</label>
		<Field label={$t('feedrules.positionLabel')} hint={$t('feedrules.positionHint')}><input type="number" bind:value={form.position} class="input input-bordered input-sm w-24" /></Field>
		<div class="flex justify-end gap-2 self-end">
			{#if editing}<button type="button" class="btn btn-ghost btn-sm" onclick={() => { editing = null; form = blank(); }}>{$t('feedrules.cancel')}</button>{/if}
			<button class="btn btn-primary btn-sm" disabled={saving}>{editing ? $t('feedrules.saveButton') : $t('feedrules.addButton')}</button>
		</div>
	</div>
</form>

<State {loading} {error} empty={!loading && !error && rules.length === 0} emptyText={$t('feedrules.empty')} />
{#if !loading && rules.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('feedrules.colPos')}</th><th>{$t('feedrules.colName')}</th><th>{$t('feedrules.colWhen')}</th><th>{$t('feedrules.colThen')}</th><th></th></tr></thead>
			<tbody>
				{#each rules as r (r.id)}
					<tr class="hover" class:opacity-50={!r.enabled}>
						<td>{r.position}</td>
						<td class="font-medium">{r.name}</td>
						<td class="text-xs">{what(r)}</td>
						<td class="text-xs">{r.action === 'set_severity' ? $t('feedrules.thenSeverity', { severity: r.severity }) : r.action === 'add_tags' ? $t('feedrules.thenTags', { tags: r.tags.join(', ') }) : $t('feedrules.thenMute')}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => edit(r)}>{$t('feedrules.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(r)}>{$t('feedrules.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
