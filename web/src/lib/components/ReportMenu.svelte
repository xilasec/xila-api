<script>
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';

	/**
	 * Report dropdown: open the printable HTML report, or open it straight into
	 * the browser's print dialog ("Save as PDF"), in the default layout or one
	 * of the admin-defined report templates. `open({ print, template })` is an
	 * api.open*Report call.
	 */
	/** @type {{ open: (opts: { print: boolean, template: string }) => Promise<void>, label?: string }} */
	let { open, label = '' } = $props();

	let templates = $state(/** @type {any[] | null} */ (null)); // loaded on first open of the menu
	let template = $state('');

	async function loadTemplates() {
		if (templates) return;
		try {
			templates = (await api.listReportTemplates()).templates ?? [];
		} catch {
			templates = [];
		}
	}

	/** @param {boolean} print @param {MouseEvent & { currentTarget: HTMLButtonElement }} e */
	async function go(print, e) {
		e.currentTarget.blur(); // close the dropdown
		try {
			await open({ print, template });
		} catch (err) {
			notify(err ? errorMessage(err) : $t('report.failed'));
		}
	}
</script>

<div class="dropdown dropdown-end">
	<button type="button" tabindex="0" class="btn btn-sm btn-ghost gap-1" title={$t('report.title')}
		onfocus={loadTemplates} onmouseenter={loadTemplates}>▤ {label || $t('report.label')}</button>
	<ul class="dropdown-content menu menu-sm z-40 mt-1 w-56 rounded-box bg-base-100 p-2 shadow-lg">
		{#if templates?.length}
			<li class="menu-title">{$t('report.template')}</li>
			<li class="mb-1">
				<select class="select select-bordered select-xs w-full" bind:value={template} aria-label={$t('report.templateAria')}>
					<option value="">{$t('report.default')}</option>
					{#each templates as tpl (tpl.id)}<option value={tpl.id}>{tpl.name}</option>{/each}
				</select>
			</li>
		{/if}
		<li><button type="button" onclick={(e) => go(false, e)}>{$t('report.open')}</button></li>
		<li><button type="button" onclick={(e) => go(true, e)}>{$t('report.pdf')}</button></li>
	</ul>
</div>
