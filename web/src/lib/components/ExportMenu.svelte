<script>
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';

	/**
	 * Export dropdown (CSV / Excel) for the listing on screen.
	 * `run(format)` performs the download (an api.export* call bound to the
	 * active filter) and resolves to true when the server truncated it.
	 */
	/** @type {{ run: (format: 'csv' | 'xlsx') => Promise<unknown>, label?: string, disabled?: boolean }} */
	let { run, label = '', disabled = false } = $props();
	let busy = $state(false);

	/** @param {'csv' | 'xlsx'} format @param {MouseEvent & { currentTarget: HTMLElement }} e */
	async function exportAs(format, e) {
		e.currentTarget.blur(); // close the dropdown
		busy = true;
		try {
			const truncated = await run(format);
			if (truncated) notify($t('common.exportCapped'));
		} catch (err) {
			notify(err instanceof Error ? err.message : $t('common.exportFailed'));
		} finally {
			busy = false;
		}
	}
</script>

<div class="dropdown dropdown-end">
	<button type="button" tabindex="0" class="btn btn-sm btn-ghost gap-1" disabled={disabled || busy} title={$t('common.exportTitle')}>
		{#if busy}<span class="loading loading-spinner loading-xs"></span>{:else}⤓{/if}
		{label || $t('common.export')}
	</button>
	<ul class="dropdown-content menu menu-sm z-40 mt-1 w-40 rounded-box bg-base-100 p-2 shadow-lg">
		<li><button type="button" onclick={(e) => exportAs('csv', e)}>CSV</button></li>
		<li><button type="button" onclick={(e) => exportAs('xlsx', e)}>{$t('common.excel')}</button></li>
	</ul>
</div>
