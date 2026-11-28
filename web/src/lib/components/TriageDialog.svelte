<script>
	// Reason + optional expiry for an exception status (false positive, accept
	// risk, won't fix). `open()` resolves to the PATCH/bulk options, or null when
	// the user cancels — callers never apply an exception without one.
	import { t, labelOf } from '#lib/i18n.js';
	import { releaseFocus } from '#lib/keyboard.js';
	import VexAnalysisFields from '#lib/components/VexAnalysisFields.svelte';

	/** @typedef {{ reason: string, expires_at?: string, vex_justification?: string, vex_response?: string[] }} TriageOptions */

	/** @type {HTMLDialogElement} */
	let dialog;
	let status = $state('');
	let count = $state(1);
	let reason = $state('');
	let expires = $state('');
	let justification = $state('');
	let response = $state(/** @type {string[]} */ ([]));
	// The statuses a structured analysis describes (false positive, won't fix).
	const analysed = $derived(status === 'false_positive' || status === 'wont_fix');
	/** @type {((v: TriageOptions | null) => void) | null} */
	let resolve = null;

	/**
	 * @param {string} nextStatus
	 * @param {number} [n] how many findings the change applies to
	 * @returns {Promise<TriageOptions | null>}
	 */
	export function open(nextStatus, n = 1) {
		resolve?.(null);
		status = nextStatus;
		count = n;
		reason = '';
		expires = '';
		justification = '';
		response = [];
		dialog.showModal();
		return new Promise((r) => (resolve = r));
	}

	/** @param {TriageOptions | null} value */
	function finish(value) {
		const r = resolve;
		resolve = null;
		if (dialog.open) dialog.close();
		releaseFocus(dialog);
		r?.(value);
	}

	/** @param {SubmitEvent} e */
	function submit(e) {
		e.preventDefault();
		const text = reason.trim();
		if (!text) return;
		/** @type {TriageOptions} */
		const opts = { reason: text };
		if (expires) opts.expires_at = new Date(expires).toISOString();
		if (analysed && justification) opts.vex_justification = justification;
		if (analysed && response.length) opts.vex_response = response;
		finish(opts);
	}
</script>

<!-- Esc / backdrop close the dialog; `onclose` turns that into a cancel. -->
<dialog bind:this={dialog} class="modal" onclose={() => finish(null)}>
	<div class="modal-box">
		<h3 class="mb-1 text-lg font-bold capitalize">
			{$labelOf('status', status)}{count > 1 ? ` · ${$t('triage.findingsCount', { count })}` : ''}
		</h3>
		<p class="mb-4 text-sm text-base-content/60">
			{#if status === 'risk_accepted'}
				{$t('triage.riskIntro')}
			{:else}
				{$t('triage.intro')}
			{/if}
		</p>
		<form onsubmit={submit} class="flex flex-col gap-3">
			<label class="form-control">
				<span class="label-text mb-1">{$t('triage.reason')}</span>
				<!-- svelte-ignore a11y_autofocus -->
				<textarea bind:value={reason} required autofocus name="reason"
					placeholder={$t('triage.reasonPlaceholder')}
					class="textarea textarea-bordered h-24 w-full"></textarea>
			</label>
			<label class="form-control">
				<span class="label-text mb-1">{$t('triage.expires')} <span class="text-base-content/40">{$t('triage.expiresHint')}</span></span>
				<input type="date" bind:value={expires} name="expires" class="input input-bordered w-full" />
			</label>
			{#if analysed}
				<VexAnalysisFields bind:justification bind:response />
			{/if}
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => finish(null)}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={!reason.trim()}>{$t('common.confirm')}</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>
