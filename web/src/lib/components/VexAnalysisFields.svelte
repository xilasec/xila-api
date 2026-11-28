<script>
	// The structured analysis (M13 13.2) that goes with a false positive or
	// won't fix: a CycloneDX justification and response codes, exported in VEX
	// documents. Both are optional; nothing is ever filled in for the user.
	import { t, labelOf } from '#lib/i18n.js';

	const JUSTIFICATIONS = [
		'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency',
		'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter',
		'protected_by_mitigating_control'
	];
	const RESPONSES = ['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available'];

	/** @type {{ justification: string, response: string[] }} */
	let { justification = $bindable(''), response = $bindable([]) } = $props();

	/** @param {string} r @param {boolean} on */
	function toggle(r, on) {
		response = on ? [...response, r].filter((v, i, a) => a.indexOf(v) === i) : response.filter((v) => v !== r);
	}
</script>

<label class="form-control">
	<span class="label-text mb-1">{$t('vex.justification')}</span>
	<select bind:value={justification} name="vex_justification" class="select select-bordered w-full">
		<option value="">{$t('vex.justificationNone')}</option>
		{#each JUSTIFICATIONS as j (j)}<option value={j}>{$labelOf('vexJustification', j)}</option>{/each}
	</select>
</label>
<fieldset class="form-control">
	<legend class="label-text mb-1">{$t('vex.response')}</legend>
	<div class="flex flex-wrap gap-x-4 gap-y-1">
		{#each RESPONSES as r (r)}
			<label class="label cursor-pointer gap-2 py-0">
				<input type="checkbox" class="checkbox checkbox-sm" checked={response.includes(r)}
					onchange={(e) => toggle(r, e.currentTarget.checked)} />
				<span class="label-text">{$labelOf('vexResponse', r)}</span>
			</label>
		{/each}
	</div>
	<span class="label-text-alt mt-1 text-base-content/50">{$t('vex.hint')}</span>
</fieldset>
