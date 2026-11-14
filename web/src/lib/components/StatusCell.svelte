<script>
	// A findings-table Status cell that turns into a compact <select> to change
	// the status in place. The page applies the pick (and asks for a reason when
	// it is an exception); Esc or leaving the select cancels.
	import { STATUSES } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import Badge from '#lib/components/Badge.svelte';

	/** @type {{ status: string, editing: boolean, disabled?: boolean, onedit: () => void, onpick: (status: string) => void, oncancel: () => void }} */
	let { status, editing, disabled = false, onedit, onpick, oncancel } = $props();

	/** @param {HTMLSelectElement} el */
	function focusOnMount(el) {
		el.focus();
	}

	/** @param {Event & { currentTarget: HTMLSelectElement }} e */
	function change(e) {
		const next = e.currentTarget.value;
		if (next === status) oncancel();
		else onpick(next);
	}

	/** @param {KeyboardEvent} e */
	function keydown(e) {
		if (e.key !== 'Escape') return;
		e.preventDefault();
		e.stopPropagation();
		oncancel();
	}
</script>

{#if editing}
	<select class="select select-bordered select-xs" value={status} use:focusOnMount onchange={change}
		onblur={oncancel} onkeydown={keydown} aria-label={$t('status.aria')}>
		{#each STATUSES as s (s)}<option value={s}>{$labelOf('status', s)}</option>{/each}
	</select>
{:else}
	<button type="button" class="cursor-pointer disabled:cursor-wait" {disabled} title={$t('status.changeTitle')} onclick={onedit}>
		<Badge kind="status" value={status} />
	</button>
{/if}
