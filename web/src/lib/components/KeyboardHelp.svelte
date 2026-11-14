<script>
	// The findings tables' keymap. Owns the `?` key (toggle); Esc closes it
	// natively. `enabled` lets a page with tabs scope it to the findings tab.
	import { SHORTCUTS, ignoreKey, releaseFocus } from '$lib/keyboard.js';
	import { t } from '$lib/i18n.js';

	/** @type {{ search?: boolean, enabled?: boolean }} */
	let { search = false, enabled = true } = $props();

	/** @type {HTMLDialogElement} */
	let dialog;
	const shortcuts = $derived(SHORTCUTS.filter((s) => search || !s.search));

	export function toggle() {
		if (dialog.open) dialog.close();
		else dialog.showModal();
	}

	/** @param {KeyboardEvent} e */
	function onkeydown(e) {
		if (!enabled || e.key !== '?') return;
		// While open, `?` closes it; otherwise the usual "not while typing" rule.
		if (!dialog.open && ignoreKey(e)) return;
		e.preventDefault();
		toggle();
	}
</script>

<svelte:window {onkeydown} />

<dialog bind:this={dialog} class="modal" aria-labelledby="kbd-help-title" onclose={() => releaseFocus(dialog)}>
	<div class="modal-box max-w-md">
		<h3 id="kbd-help-title" class="mb-3 text-lg font-bold">{$t('keys.title')}</h3>
		<table class="table table-sm">
			<tbody>
				{#each shortcuts as s (s.label)}
					<tr>
						<td class="whitespace-nowrap">
							{#each s.keys as k, i (k)}{#if i > 0}<span class="mx-1 text-base-content/40">{s.keys[0] === 'Shift' ? '+' : '/'}</span>{/if}<kbd class="kbd kbd-sm">{k}</kbd>{/each}
						</td>
						<td class="text-sm">{$t(s.label)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
		<p class="mt-3 text-xs text-base-content/50">{$t('keys.note')}</p>
		<div class="modal-action">
			<form method="dialog"><button class="btn btn-sm">{$t('home.closeButton')}</button></form>
		</div>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
