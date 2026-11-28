<script>
	// A triage rule's side actions (M13 13.5): assign, add tags, comment and
	// notify alongside its action, plus a daily schedule and the age
	// condition that schedule exists for. Bound field by field to the rule form.
	import { t } from '#lib/i18n.js';

	/**
	 * @typedef {{ assign_user_id: string | null, assign_owner_from: string, only_if_unassigned: boolean,
	 *   add_tags: string, comment: string, notify: boolean, schedule: string, age_days_gt: string | number }} SideFields
	 */
	/** @type {{ form: SideFields, users: { id: string, email: string }[] }} */
	let { form = $bindable(), users } = $props();

	// One select drives both assign fields: a user id, the project's owner, or nobody.
	const assignee = $derived(form.assign_owner_from === 'project_owner' ? 'owner' : (form.assign_user_id ?? ''));
	/** @param {string} v */
	function setAssignee(v) {
		form.assign_owner_from = v === 'owner' ? 'project_owner' : '';
		form.assign_user_id = v && v !== 'owner' ? v : null;
	}
</script>

<fieldset class="md:col-span-2 border border-base-300 rounded-box p-3 grid gap-3 md:grid-cols-2">
	<legend class="px-1 text-sm font-semibold">{$t('rules.side.title')}</legend>
	<p class="md:col-span-2 text-xs text-base-content/60 -mt-1">{$t('rules.side.hint')}</p>
	<label class="form-control">
		<span class="label-text mb-1">{$t('rules.side.assign')}</span>
		<div class="flex gap-2 items-center">
			<select value={assignee} onchange={(e) => setAssignee(e.currentTarget.value)} class="select select-bordered select-sm flex-1">
				<option value="">{$t('rules.side.assignNobody')}</option>
				<option value="owner">{$t('rules.side.assignOwner')}</option>
				{#each users as u (u.id)}<option value={u.id}>{u.email}</option>{/each}
			</select>
			<label class="label cursor-pointer gap-1 py-0">
				<input type="checkbox" bind:checked={form.only_if_unassigned} class="checkbox checkbox-xs" />
				<span class="label-text text-xs">{$t('rules.side.onlyUnassigned')}</span>
			</label>
		</div>
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('rules.side.tags')}</span>
		<input bind:value={form.add_tags} placeholder={$t('rules.side.tagsPlaceholder')} class="input input-bordered input-sm" />
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('rules.side.comment')}</span>
		<input bind:value={form.comment} class="input input-bordered input-sm" />
	</label>
	<label class="label cursor-pointer justify-start gap-2 self-end">
		<input type="checkbox" bind:checked={form.notify} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('rules.side.notify')}</span>
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('rules.side.schedule')}</span>
		<select bind:value={form.schedule} class="select select-bordered select-sm">
			<option value="">{$t('rules.side.scheduleNone')}</option>
			<option value="daily">{$t('rules.side.scheduleDaily')}</option>
		</select>
	</label>
	<label class="form-control">
		<span class="label-text mb-1">{$t('rules.side.age')}</span>
		<input type="number" min="0" bind:value={form.age_days_gt} class="input input-bordered input-sm" />
	</label>
</fieldset>
