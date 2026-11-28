<script>
	// A project's assessment approval (M13 13.9): whether manual status and
	// severity changes wait for a second person (inherit follows the instance
	// default), and who decides. With approvers designated only they decide;
	// the server refuses anyone who can't see the project.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	/** @type {{ project: any, groups: any[] }} */
	let { project, groups } = $props();

	let setting = $state('inherit');
	let users = $state(/** @type {any[]} */ ([]));
	let userIds = $state(/** @type {string[]} */ ([]));
	let groupIds = $state(/** @type {string[]} */ ([]));
	let busy = $state(false);

	$effect(() => {
		setting = project.assessment_approval || 'inherit';
		Promise.all([api.getAssessmentApprovers(project.id), api.projectAssignees(project.id)]).then(([approvers, people]) => {
			users = people;
			userIds = approvers.filter((/** @type {any} */ a) => a.user_id).map((/** @type {any} */ a) => a.user_id);
			groupIds = approvers.filter((/** @type {any} */ a) => a.group_id).map((/** @type {any} */ a) => a.group_id);
		}, (err) => notify(errorMessage(err)));
	});

	/** @param {string[]} list @param {string} id @param {boolean} on */
	const toggled = (list, id, on) => (on ? [...list, id] : list.filter((v) => v !== id));

	async function save() {
		busy = true;
		try {
			await api.updateProject(project.id, { assessment_approval: setting });
			await api.setAssessmentApprovers(project.id, userIds, groupIds);
			notify($t('approval.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

<div class="card bg-base-100 shadow-sm mt-6">
	<div class="card-body gap-3">
		<h2 class="card-title text-base">{$t('approval.title')}</h2>
		<p class="text-sm text-base-content/60">{$t('approval.intro')}</p>
		<label class="form-control max-w-xs">
			<span class="label-text mb-1">{$t('approval.setting')}</span>
			<select bind:value={setting} class="select select-bordered select-sm">
				<option value="inherit">{$t('approval.inherit')}</option>
				<option value="required">{$t('approval.required')}</option>
				<option value="off">{$t('approval.off')}</option>
			</select>
		</label>
		<fieldset>
			<legend class="label-text mb-1">{$t('approval.approvers')}</legend>
			<p class="text-xs text-base-content/50 mb-2">{$t('approval.approversHint')}</p>
			<div class="grid gap-4 md:grid-cols-2">
				<div class="flex flex-col items-start">
					<div class="text-xs font-semibold mb-1">{$t('approval.people')}</div>
					{#each users as u (u.user_id)}
						<label class="label cursor-pointer justify-start gap-2 py-0.5">
							<input type="checkbox" class="checkbox checkbox-sm" checked={userIds.includes(u.user_id)}
								onchange={(e) => (userIds = toggled(userIds, u.user_id, e.currentTarget.checked))} />
							<span class="label-text">{u.email}</span>
						</label>
					{/each}
				</div>
				{#if groups.length > 0}
					<div class="flex flex-col items-start">
						<div class="text-xs font-semibold mb-1">{$t('approval.groups')}</div>
						{#each groups as g (g.id)}
							<label class="label cursor-pointer justify-start gap-2 py-0.5">
								<input type="checkbox" class="checkbox checkbox-sm" checked={groupIds.includes(g.id)}
									onchange={(e) => (groupIds = toggled(groupIds, g.id, e.currentTarget.checked))} />
								<span class="label-text">{g.name}</span>
							</label>
						{/each}
					</div>
				{/if}
			</div>
		</fieldset>
		<div>
			<button class="btn btn-sm btn-primary" disabled={busy} onclick={save}>{$t('common.save')}</button>
		</div>
	</div>
</div>
