<script>
	// Custom-field values of one project, asset or finding: shows every field that
	// applies (definitions from the admin's Custom fields page) and, for editors,
	// edits them in one save. The server validates the type, enum options and who
	// a user field may name; its 400 message is shown as is.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	/** @type {{ kind: 'projects' | 'assets' | 'findings', id: string, projectId: string, values?: Record<string, any>, canEdit?: boolean, onsaved?: (values: Record<string, any>) => void }} */
	let { kind, id, projectId, values = {}, canEdit = false, onsaved = () => {} } = $props();

	const entity = $derived(kind === 'projects' ? 'project' : kind === 'assets' ? 'asset' : 'finding');
	let fields = $state(/** @type {any[]} */ ([]));
	let users = $state(/** @type {any[]} */ ([]));
	let editing = $state(false);
	let saving = $state(false);
	let draft = $state(/** @type {Record<string, any>} */ ({}));

	$effect(() => {
		const e = entity;
		const pid = projectId;
		if (!pid) return;
		api.listCustomFields({ entity: e, project_id: pid })
			.then(async (f) => {
				fields = f;
				// User fields show (and pick) people who can see the project.
				if (f.some((/** @type {any} */ x) => x.type === 'user')) users = await api.projectAssignees(pid).catch(() => []);
			})
			.catch(() => (fields = []));
	});

	/** @param {any} f @param {any} v */
	function display(f, v) {
		if (v === undefined || v === null || v === '') return '—';
		if (f.type === 'user') return users.find((u) => u.user_id === v)?.email ?? v;
		return String(v);
	}

	function startEdit() {
		/** @type {Record<string, any>} */
		const d = {};
		for (const f of fields) d[f.key] = values?.[f.key] ?? '';
		draft = d;
		editing = true;
	}

	async function save() {
		saving = true;
		/** @type {Record<string, any>} */
		const patch = {};
		for (const f of fields) {
			if (f.computed) continue; // read-only: the server recomputes it
			const v = draft[f.key];
			if (v === '' || v === null || v === undefined) patch[f.key] = null;
			else patch[f.key] = f.type === 'number' ? Number(v) : v;
		}
		try {
			const out = await api.setCustomValues(kind, id, patch);
			editing = false;
			onsaved(out);
			notify($t('cf.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}
</script>

{#if fields.length > 0}
	<div class="bg-base-100 rounded-box shadow-sm p-4" data-testid="custom-fields">
		<div class="flex items-center justify-between mb-2">
			<h3 class="font-semibold">{$t('cf.title')}</h3>
			{#if canEdit && !editing}
				<button class="btn btn-ghost btn-xs" onclick={startEdit}>{$t('common.edit')}</button>
			{/if}
		</div>
		{#if editing}
			<div class="grid gap-3 md:grid-cols-2">
				{#each fields as f (f.id)}
					<label class="form-control w-full">
						<span class="label-text mb-1 font-medium">
							{f.label}{#if f.required}<span class="text-error"> *</span>{/if}
							{#if f.computed}<span class="badge badge-ghost badge-xs ml-1">{$t('customfields.computedBadge')}</span>{/if}
						</span>
						{#if f.computed}
							<span class="text-sm py-1">{display(f, values?.[f.key])}</span>
						{:else if f.type === 'enum'}
							<select bind:value={draft[f.key]} class="select select-bordered select-sm">
								<option value="">—</option>
								{#each f.options as o}<option value={o}>{o}</option>{/each}
							</select>
						{:else if f.type === 'user'}
							<select bind:value={draft[f.key]} class="select select-bordered select-sm">
								<option value="">—</option>
								{#each users as u (u.user_id)}<option value={u.user_id}>{u.email}</option>{/each}
							</select>
						{:else if f.type === 'number'}
							<input type="number" step="any" bind:value={draft[f.key]} class="input input-bordered input-sm" />
						{:else if f.type === 'date'}
							<input type="date" bind:value={draft[f.key]} class="input input-bordered input-sm" />
						{:else}
							<input bind:value={draft[f.key]} maxlength="1000" class="input input-bordered input-sm" />
						{/if}
					</label>
				{/each}
			</div>
			<div class="flex justify-end gap-2 mt-3">
				<button class="btn btn-sm" onclick={() => (editing = false)}>{$t('common.cancel')}</button>
				<button class="btn btn-sm btn-primary" disabled={saving} onclick={save}>{$t('common.save')}</button>
			</div>
		{:else}
			<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
				{#each fields as f (f.id)}
					<dt class="text-base-content/60">
						{f.label}{#if f.computed}<span class="badge badge-ghost badge-xs ml-1">{$t('customfields.computedBadge')}</span>{/if}
					</dt>
					<dd>{display(f, values?.[f.key])}</dd>
				{/each}
			</dl>
		{/if}
	</div>
{/if}
