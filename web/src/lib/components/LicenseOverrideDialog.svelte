<script>
	// Correct a component's license by hand: a concluded SPDX expression for a
	// package (optionally a version range) in one project. It replaces the
	// SBOM's declared license at every ingest, so it survives re-uploads.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import Field from '#lib/components/Field.svelte';

	/** @type {{ projectId: string, onsaved?: () => void }} */
	let { projectId, onsaved } = $props();

	/** @type {HTMLDialogElement | undefined} */
	let dialog = $state();
	let overrideId = $state('');
	let declared = $state('');
	let form = $state({ purl: '', version_range: '', license: '', comment: '' });
	let busy = $state(false);

	/** The package identity without version, qualifiers or subpath. @param {string} purl */
	const basePurl = (purl) => purl.split(/[@?#]/)[0];

	/** @param {any} c a component row */
	export async function open(c) {
		overrideId = c.license_override_id ?? '';
		declared = c.license_declared_expression || (overrideId ? '' : c.license_expression || c.license || '');
		form = { purl: basePurl(c.purl ?? ''), version_range: '', license: c.license_expression || '', comment: '' };
		if (overrideId) {
			try {
				const o = await api.getLicenseOverride(projectId, overrideId);
				form = { purl: o.purl, version_range: o.version_range ?? '', license: o.license, comment: o.comment ?? '' };
			} catch (err) {
				notify(errorMessage(err));
				return;
			}
		}
		dialog?.showModal();
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		busy = true;
		try {
			if (overrideId) await api.updateLicenseOverride(projectId, overrideId, form);
			else await api.createLicenseOverride(projectId, form);
			notify($t('licov.saved'), 'success');
			dialog?.close();
			onsaved?.();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	async function remove() {
		if (!overrideId || !confirm($t('licov.removeConfirm'))) return;
		busy = true;
		try {
			await api.deleteLicenseOverride(projectId, overrideId);
			notify($t('licov.removed'), 'success');
			dialog?.close();
			onsaved?.();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

<dialog bind:this={dialog} class="modal">
	<form class="modal-box space-y-3" onsubmit={save}>
		<h3 class="text-lg font-bold">{overrideId ? $t('licov.editTitle') : $t('licov.title')}</h3>
		<p class="text-sm text-base-content/70">{$t('licov.intro')}</p>
		{#if declared}<p class="text-sm">{$t('licov.declared')}: <code>{declared}</code></p>{/if}
		<Field label={$t('licov.purl')} required hint={$t('licov.purlHint')}>
			<input bind:value={form.purl} class="input input-bordered input-sm w-full font-mono" required />
		</Field>
		<Field label={$t('licov.range')} hint={$t('licov.rangeHint')}>
			<input bind:value={form.version_range} class="input input-bordered input-sm w-full font-mono" placeholder=">=1.2.0, <2.0.0" />
		</Field>
		<Field label={$t('licov.license')} required hint={$t('licov.licenseHint')}>
			<input bind:value={form.license} class="input input-bordered input-sm w-full font-mono" placeholder="MIT OR Apache-2.0" required />
		</Field>
		<Field label={$t('licov.comment')}>
			<textarea bind:value={form.comment} class="textarea textarea-bordered textarea-sm w-full" rows="2"></textarea>
		</Field>
		<div class="modal-action">
			{#if overrideId}<button type="button" class="btn btn-sm btn-ghost text-error mr-auto" disabled={busy} onclick={remove}>{$t('licov.remove')}</button>{/if}
			<button type="button" class="btn btn-sm btn-ghost" onclick={() => dialog?.close()}>{$t('common.cancel')}</button>
			<button class="btn btn-sm btn-primary" disabled={busy}>{$t('licov.save')}</button>
		</div>
	</form>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.cancel')}</button></form>
</dialog>
