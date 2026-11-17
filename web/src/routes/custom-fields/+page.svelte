<script>
	// Custom fields (instance admin): typed fields on projects, assets and
	// findings. Values are edited on each record's page, filtered with
	// ?cf.<key>= on the lists, exported as columns, and readable in CEL as
	// project.custom.<key> / finding.custom.<key>.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	const ENTITIES = ['finding', 'project', 'asset'];
	/** @param {string} e */
	const entityLabel = (e) => $t(/** @type {import('#lib/i18n.js').MessageKey} */ (`customfields.entity.${e}`));
	const TYPES = ['text', 'number', 'date', 'enum', 'user'];

	let loading = $state(true);
	let error = $state('');
	let fields = $state(/** @type {any[]} */ ([]));
	let saving = $state(false);
	let editing = $state(/** @type {any} */ (null));
	const blank = () => ({ entity: 'finding', key: '', label: '', type: 'text', options: '', required: false, computed: false, expression: '' });
	let form = $state(blank());

	async function load() {
		loading = true;
		error = '';
		try {
			fields = await api.listCustomFields();
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {any} f */
	function edit(f) {
		editing = f;
		form = {
			entity: f.entity, key: f.key, label: f.label, type: f.type, options: (f.options ?? []).join(', '),
			required: f.required, computed: !!f.computed, expression: f.expression ?? ''
		};
	}

	function reset() {
		editing = null;
		form = blank();
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		const body = {
			entity: form.entity, key: form.key.trim(), label: form.label.trim(), type: form.type,
			required: form.computed ? false : form.required,
			options: form.type === 'enum' ? form.options.split(',').map((o) => o.trim()).filter(Boolean) : [],
			computed: form.computed, expression: form.computed ? form.expression.trim() : ''
		};
		try {
			if (editing) await api.updateCustomField(editing.id, body);
			else await api.createCustomField(body);
			notify(editing ? $t('customfields.updated') : $t('customfields.created'), 'success');
			reset();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} f */
	async function remove(f) {
		if (!confirm($t('customfields.deleteConfirm', { label: f.label, entity: entityLabel(f.entity) }))) return;
		try {
			await api.deleteCustomField(f.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	onMount(load);
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('customfields.title')}</h1>
	<p class="text-sm text-base-content/60">
		{$t('customfields.introPre')}
		<code>?cf.&lt;key&gt;=</code>{$t('customfields.introPost')} <code>finding.custom.&lt;key&gt;</code>
		{$t('customfields.introAnd')} <code>project.custom.&lt;key&gt;</code>{$t('customfields.introEnd')}
	</p>
</div>

<form onsubmit={save} class="card bg-base-100 shadow-sm mb-4">
	<div class="card-body grid gap-3 md:grid-cols-3">
		<Field label={$t('customfields.onLabel')}>
			<select bind:value={form.entity} class="select select-bordered select-sm w-full" disabled={!!editing}>
				{#each ENTITIES as e}<option value={e}>{entityLabel(e)}</option>{/each}
			</select>
		</Field>
		<Field label={$t('customfields.keyLabel')} hint={$t('customfields.keyHint')}>
			<input bind:value={form.key} required pattern={'[a-z][a-z0-9_]{0,39}'} disabled={!!editing}
				class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<Field label={$t('customfields.labelLabel')}>
			<input bind:value={form.label} required class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('customfields.typeLabel')}>
			<select bind:value={form.type} class="select select-bordered select-sm w-full" disabled={!!editing}>
				{#each TYPES as ty}<option value={ty} disabled={form.computed && ty === 'user'}>{$t(/** @type {import('#lib/i18n.js').MessageKey} */ ('customfields.type.' + ty))}</option>{/each}
			</select>
		</Field>
		{#if form.type === 'enum'}
			<Field label={$t('customfields.optionsLabel')} hint={$t('customfields.optionsHint')}>
				<input bind:value={form.options} required class="input input-bordered input-sm w-full" />
			</Field>
		{/if}
		<label class="label cursor-pointer justify-start gap-2 self-end">
			<input type="checkbox" class="checkbox checkbox-sm" bind:checked={form.computed}
				disabled={form.type === 'user'} onchange={() => { if (form.computed) form.required = false; }} />
			<span class="label-text">{$t('customfields.computedLabel')}</span>
		</label>
		{#if !form.computed}
			<label class="label cursor-pointer justify-start gap-2 self-end">
				<input type="checkbox" class="checkbox checkbox-sm" bind:checked={form.required} />
				<span class="label-text">{$t('customfields.requiredLabel')}</span>
			</label>
		{/if}
		{#if form.computed}
			<Field label={$t('customfields.expressionLabel')} hint={$t('customfields.expressionHint')}>
				<textarea bind:value={form.expression} required rows="2"
					class="textarea textarea-bordered textarea-sm w-full font-mono md:col-span-3"></textarea>
			</Field>
		{/if}
		<div class="md:col-span-3 flex justify-end gap-2">
			{#if editing}<button type="button" class="btn btn-ghost btn-sm" onclick={reset}>{$t('customfields.cancel')}</button>{/if}
			<button class="btn btn-primary btn-sm" disabled={saving}>{editing ? $t('customfields.saveButton') : $t('customfields.addButton')}</button>
		</div>
	</div>
</form>

<State {loading} {error} empty={!loading && !error && fields.length === 0} emptyText={$t('customfields.empty')} />
{#if !loading && fields.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('customfields.colOn')}</th><th>{$t('customfields.colLabel')}</th><th>{$t('customfields.colKey')}</th><th>{$t('customfields.colType')}</th><th>{$t('customfields.colRequired')}</th><th></th></tr></thead>
			<tbody>
				{#each fields as f (f.id)}
					<tr class="hover">
						<td>{entityLabel(f.entity)}</td>
						<td class="font-medium">{f.label}{#if f.computed} <span class="badge badge-ghost badge-sm" title={f.expression}>{$t('customfields.computedBadge')}</span>{/if}</td>
						<td class="font-mono text-xs">{f.key}</td>
						<td>{$t(/** @type {import('#lib/i18n.js').MessageKey} */ ('customfields.type.' + f.type))}{#if f.type === 'enum'} <span class="text-xs text-base-content/60">({f.options.join(', ')})</span>{/if}</td>
						<td>{f.required ? $t('customfields.yes') : ''}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => edit(f)}>{$t('customfields.editButton')}</button>
							<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(f)}>{$t('customfields.deleteButton')}</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
