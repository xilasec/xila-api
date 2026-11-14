<script>
	// A framework's manual controls for one project: what is attested (how,
	// by whom, until when) and what is still to attest. Attesting needs editor
	// on the project; the server enforces it.
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import Field from '$lib/components/Field.svelte';

	/** @type {{ projectId: string, framework: any, onchanged: () => void }} */
	let { projectId, framework, onchanged } = $props();

	const manual = $derived(framework.controls.filter((/** @type {any} */ c) => c.manual));
	let open = $state(false);
	let editing = $state(/** @type {any} */ (null));
	let form = $state({ note: '', evidence_url: '', expires: '' });
	let saving = $state(false);

	/** @param {any} c */
	function edit(c) {
		editing = c;
		form = {
			note: c.attestation?.note ?? '',
			evidence_url: c.attestation?.evidence_url ?? '',
			expires: c.attestation?.expires_at ? String(c.attestation.expires_at).slice(0, 10) : ''
		};
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.attestControl(projectId, framework.framework, editing.code, {
				note: form.note, evidence_url: form.evidence_url,
				expires_at: form.expires ? new Date(form.expires + 'T23:59:59Z').toISOString() : null
			});
			editing = null;
			onchanged();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} c */
	async function remove(c) {
		if (!confirm($t('mctrl.confirmRemove', { code: c.code }))) return;
		try {
			await api.removeAttestation(projectId, framework.framework, c.code);
			onchanged();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} c */
	const attested = (c) => c.attestation && !c.attestation.expired;
</script>

{#if manual.length > 0}
	<div class="mt-2">
		<button class="link link-hover text-sm" onclick={() => (open = !open)}>
			{open ? '▾' : '▸'} {$t('mctrl.toggle', { attested: manual.filter(attested).length, total: manual.length })}
		</button>
		{#if open}
			<ul class="mt-1 flex flex-col gap-1 text-sm">
				{#each manual as c (c.code)}
					<li class="flex items-start justify-between gap-2">
						<span>
							<span class="badge badge-xs mr-1" class:badge-success={attested(c)} class:badge-warning={!attested(c)}>{attested(c) ? $t('mctrl.attested') : $t('mctrl.toAttest')}</span>
							{c.code} · {c.title}
							{#if c.attestation}
								<div class="text-xs text-base-content/60">{c.attestation.note} — {c.attestation.attested_by}{#if c.attestation.expired} · <strong>{$t('mctrl.expired')}</strong>{/if}</div>
							{/if}
						</span>
						<span class="whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => edit(c)}>{c.attestation ? $t('common.edit') : $t('mctrl.attest')}</button>
							{#if c.attestation}<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(c)}>{$t('common.remove')}</button>{/if}
						</span>
					</li>
					{#if editing?.code === c.code}
						<li>
							<form onsubmit={save} class="grid gap-2 rounded-box bg-base-200 p-3">
								<Field label={$t('mctrl.howMet')} required>
									<textarea bind:value={form.note} required maxlength="4000" rows="2" class="textarea textarea-bordered textarea-sm w-full"></textarea>
								</Field>
								<div class="grid gap-2 md:grid-cols-2">
									<Field label={$t('mctrl.evidenceLink')}><input type="url" bind:value={form.evidence_url} placeholder="https://…" class="input input-bordered input-sm w-full" /></Field>
									<Field label={$t('mctrl.validUntil')}><input type="date" bind:value={form.expires} class="input input-bordered input-sm w-full" /></Field>
								</div>
								<div class="flex justify-end gap-2">
									<button type="button" class="btn btn-ghost btn-sm" onclick={() => (editing = null)}>{$t('common.cancel')}</button>
									<button class="btn btn-primary btn-sm" disabled={saving}>{$t('common.save')}</button>
								</div>
							</form>
						</li>
					{/if}
				{/each}
			</ul>
		{/if}
	</div>
{/if}
