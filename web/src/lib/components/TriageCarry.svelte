<script>
	// Carrying triage decisions (false positive, won't fix, reopen) across a
	// project's branches: on, and which branches share them. Risk acceptances
	// never carry; they are a decision about one version's exposure, not a
	// fact about the code.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	let data = $state(/** @type {{enabled: boolean, branch_regex: string} | null} */ (null));
	let form = $state({ enabled: false, branch_regex: '' });
	let busy = $state(false);

	$effect(() => {
		api.getTriageCarry(projectId).then((d) => {
			data = d;
			form = { enabled: d.enabled, branch_regex: d.branch_regex ?? '' };
		}, (err) => notify(errorMessage(err)));
	});

	async function save() {
		busy = true;
		try {
			data = await api.setTriageCarry(projectId, form);
			notify($t('carry.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

{#if data}
	<div class="card bg-base-100 shadow-sm mt-4">
		<div class="card-body gap-3">
			<h2 class="card-title text-base">{$t('carry.title')}</h2>
			<p class="text-sm text-base-content/60">{$t('carry.intro')}</p>
			<label class="label cursor-pointer justify-start gap-3">
				<input type="checkbox" class="toggle toggle-sm" bind:checked={form.enabled} />
				<span class="label-text">{$t('carry.enable')}</span>
			</label>
			{#if form.enabled}
				<label class="form-control max-w-md">
					<span class="label-text">{$t('carry.branchRegex')}</span>
					<input class="input input-bordered input-sm" bind:value={form.branch_regex} placeholder=".*" />
					<span class="label-text-alt">{$t('carry.branchRegexHint')}</span>
				</label>
			{/if}
			<div>
				<button class="btn btn-sm btn-primary" disabled={busy} onclick={save}>{$t('common.save')}</button>
			</div>
		</div>
	</div>
{/if}
