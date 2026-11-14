<script>
	// A finding's prose: description plus the write-up fields kept in metadata
	// (steps to reproduce, impact, mitigation, references) — filled by manual
	// reports and by imports that carry them (DefectDojo, SecObserve). Only a
	// manual finding's write-up is editable: a scanner's text belongs to the
	// scanner and would be overwritten by its next report anyway.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import Field from '#lib/components/Field.svelte';
	import { t } from '#lib/i18n.js';

	/** @type {{ finding: any, onsaved?: (f: any) => void }} */
	let { finding, onsaved = () => {} } = $props();

	/** @type {[string, import('#lib/i18n.js').MessageKey][]} */
	const SECTIONS = [
		['steps_to_reproduce', 'writeup.steps'],
		['impact', 'writeup.impact'],
		['mitigation', 'writeup.mitigation'],
		['references', 'writeup.references']
	];
	const meta = $derived(finding.metadata ?? {});
	const text = (/** @type {unknown} */ v) => (typeof v === 'string' ? v : '');
	const manual = $derived(finding.scanner === 'manual');

	let editing = $state(false);
	let saving = $state(false);
	let form = $state(/** @type {Record<string, string>} */ ({}));

	function edit() {
		form = {
			title: finding.title, description: finding.description,
			steps_to_reproduce: text(meta.steps_to_reproduce), impact: text(meta.impact),
			mitigation: text(meta.mitigation), references: text(meta.references)
		};
		editing = true;
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			const f = await api.updateFindingDetails(finding.id, {
				...form, references: form.references.split('\n').map((/** @type {string} */ x) => x.trim()).filter(Boolean)
			});
			editing = false;
			notify($t('writeup.saved'), 'success');
			onsaved(f);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('writeup.needsEditor') : errorMessage(err));
		} finally {
			saving = false;
		}
	}
</script>

{#if editing}
	<form class="space-y-2" onsubmit={save}>
		<Field label={$t('writeup.title')} required><input class="input input-bordered input-sm w-full" bind:value={form.title} required maxlength="300" /></Field>
		<Field label={$t('writeup.description')}><textarea class="textarea textarea-bordered textarea-sm h-24 w-full" bind:value={form.description}></textarea></Field>
		{#each SECTIONS as [key, label]}
			<Field label={$t(label)} hint={key === 'references' ? $t('writeup.onePerLine') : ''}>
				<textarea class="textarea textarea-bordered textarea-sm h-16 w-full" bind:value={form[key]}></textarea>
			</Field>
		{/each}
		<div class="flex justify-end gap-2">
			<button type="button" class="btn btn-sm" onclick={() => (editing = false)}>{$t('common.cancel')}</button>
			<button class="btn btn-sm btn-primary" disabled={saving}>{$t('common.save')}</button>
		</div>
	</form>
	<div class="divider my-1"></div>
{:else}
	{#if manual}
		<div class="flex justify-end -mb-2"><button class="btn btn-ghost btn-xs" onclick={edit}>{$t('writeup.edit')}</button></div>
	{/if}
	{#if finding.description}
		<p class="whitespace-pre-wrap text-sm text-base-content/80">{finding.description}</p>
	{/if}
	{#each SECTIONS as [key, label]}
		{#if text(meta[key]).trim()}
			<div>
				<h4 class="text-xs font-semibold uppercase text-base-content/50 mt-2">{$t(label)}</h4>
				{#if key === 'references'}
					<ul class="text-sm list-disc ml-5">
						{#each text(meta[key]).split('\n').filter((x) => x.trim()) as ref}
							<li class="break-all">{#if /^https?:\/\//.test(ref.trim())}<a class="link" href={ref.trim()} target="_blank" rel="noopener noreferrer">{ref}</a>{:else}{ref}{/if}</li>
						{/each}
					</ul>
				{:else}
					<p class="whitespace-pre-wrap text-sm text-base-content/80">{meta[key]}</p>
				{/if}
			</div>
		{/if}
	{/each}
	{#if finding.description || SECTIONS.some(([k]) => text(meta[k]).trim())}<div class="divider my-1"></div>{/if}
{/if}
