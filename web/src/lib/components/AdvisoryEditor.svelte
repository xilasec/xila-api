<script>
	/** Editor for a private advisory in OSV shape: summary/severity/aliases and
	 *  the affected packages with their ranges (introduced / fixed /
	 *  last_affected / limit events) and explicit version lists. */
	import Field from '#lib/components/Field.svelte';
	import { t, labelOf } from '#lib/i18n.js';

	/** @type {{ value: any, readonly?: boolean, onsubmit: (body: any) => void, saving?: boolean, submitLabel?: string }} */
	let { value, readonly = false, onsubmit, saving = false, submitLabel = '' } = $props();

	const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
	// OSV ecosystem names (https://ossf.github.io/osv-schema/#defined-ecosystems)
	// that SBOM purls map to.
	const ECOSYSTEMS = ['npm', 'PyPI', 'Maven', 'Go', 'RubyGems', 'NuGet', 'Packagist', 'crates.io', 'Hex', 'Pub',
		'SwiftURL', 'Hackage', 'CRAN', 'ConanCenter', 'Bitnami', 'GitHub Actions'];
	// OSV event kinds — the schema's own vocabulary; also the JSON key sent to
	// the API, so these stay as the spec's English terms rather than a
	// translation that would no longer match the stored field name.
	const EVENT_KINDS = ['introduced', 'fixed', 'last_affected', 'limit'];

	/** @param {any} e */
	const toEvent = (e) => {
		const kind = EVENT_KINDS.find((k) => e[k]) ?? 'introduced';
		return { kind, version: e[kind] ?? '' };
	};
	/** @param {any} a */
	const toForm = (a) => ({
		id: a?.id ?? '',
		summary: a?.summary ?? '',
		details: a?.details ?? '',
		severity: a?.severity ?? 'high',
		cvss_vector: a?.cvss_vector ?? '',
		aliases: (a?.aliases ?? []).join(', '),
		published: a?.published ?? null,
		withdrawn: a?.withdrawn ?? null,
		affected: (a?.affected?.length ? a.affected : [null]).map((/** @type {any} */ af) => ({
			mode: af?.package?.purl ? 'purl' : 'ecosystem',
			ecosystem: af?.package?.ecosystem ?? 'npm',
			name: af?.package?.name ?? '',
			purl: af?.package?.purl ?? '',
			versions: (af?.versions ?? []).join(', '),
			ranges: (af?.ranges ?? (af ? [] : [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '' }] }])).map((/** @type {any} */ r) => ({
				type: r.type,
				events: (r.events ?? []).map(toEvent)
			}))
		}))
	});

	// Seeded (and re-seeded when the advisory changes, e.g. after a save) by the effect.
	let form = $state(toForm(null));
	$effect(() => {
		form = toForm(value);
	});

	/** @param {string} s */
	const list = (s) =>
		s
			.split(',')
			.map((x) => x.trim())
			.filter(Boolean);

	function body() {
		return {
			...(form.id ? { id: form.id } : {}),
			summary: form.summary,
			details: form.details,
			severity: form.severity,
			cvss_vector: form.cvss_vector,
			aliases: list(form.aliases),
			...(form.published ? { published: form.published } : {}),
			withdrawn: form.withdrawn,
			affected: form.affected.map((/** @type {any} */ af) => ({
				package: af.mode === 'purl' ? { purl: af.purl.trim() } : { ecosystem: af.ecosystem, name: af.name.trim() },
				versions: list(af.versions),
				ranges: af.ranges.map((/** @type {any} */ r) => ({
					type: r.type,
					events: r.events.filter((/** @type {any} */ e) => e.version.trim()).map((/** @type {any} */ e) => ({ [e.kind]: e.version.trim() }))
				}))
			}))
		};
	}

	/** @param {SubmitEvent} e */
	function submit(e) {
		e.preventDefault();
		onsubmit(body());
	}

	const addAffected = () =>
		form.affected.push({ mode: 'ecosystem', ecosystem: 'npm', name: '', purl: '', versions: '',
			ranges: [{ type: 'ECOSYSTEM', events: [{ kind: 'introduced', version: '0' }, { kind: 'fixed', version: '' }] }] });
	/** @param {any} af */
	const addRange = (af) => af.ranges.push({ type: 'ECOSYSTEM', events: [{ kind: 'introduced', version: '0' }, { kind: 'fixed', version: '' }] });
</script>

<form onsubmit={submit} class="grid gap-4">
	<div class="bg-base-100 rounded-box shadow-sm p-4 grid gap-3 md:grid-cols-2">
		<Field label={$t('advEd.summary')} required>
			<input bind:value={form.summary} required disabled={readonly} placeholder={$t('advisoryeditor.summaryPlaceholder')} class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('advEd.severity')} required>
			<select bind:value={form.severity} disabled={readonly} class="select select-bordered select-sm w-full">
				{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
			</select>
		</Field>
		<Field label={$t('advEd.aliasesLabel')} hint={$t('advEd.aliasesHint')}>
			<input bind:value={form.aliases} disabled={readonly} placeholder="CVE-2026-1234" class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<Field label={$t('advEd.cvssVectorLabel')}>
			<input bind:value={form.cvss_vector} disabled={readonly} placeholder="CVSS:3.1/AV:N/AC:L/…" class="input input-bordered input-sm w-full font-mono" />
		</Field>
		<div class="md:col-span-2">
			<Field label={$t('advEd.detailsLabel')}>
				<textarea bind:value={form.details} disabled={readonly} rows="4" class="textarea textarea-bordered textarea-sm w-full"></textarea>
			</Field>
		</div>
	</div>

	<div class="grid gap-3">
		<h2 class="font-semibold">{$t('advEd.affectedPackages')}</h2>
		<p class="text-xs text-base-content/60 -mt-2">
			{$t('advEd.affectedNote1')} <em>{$t('advEd.versionsWord')}</em> {$t('advEd.affectedNote2')}
			<code>introduced</code> {$t('advEd.affectedNote3')}<code>0</code>{$t('advEd.affectedNote4')} <code>fixed</code> {$t('advEd.affectedNote5')}
			<code>last_affected</code> {$t('advEd.affectedNote6')} <code>limit</code> {$t('advEd.affectedNote7')}
		</p>
		{#each form.affected as af, i}
			<div class="bg-base-100 rounded-box shadow-sm p-4 grid gap-3">
				<div class="flex flex-wrap items-end gap-2">
					<select bind:value={af.mode} disabled={readonly} class="select select-bordered select-sm">
						<option value="ecosystem">{$t('advEd.modeEcosystem')}</option>
						<option value="purl">{$t('advEd.modePurl')}</option>
					</select>
					{#if af.mode === 'ecosystem'}
						<select bind:value={af.ecosystem} disabled={readonly} class="select select-bordered select-sm">
							{#each ECOSYSTEMS as e}<option value={e}>{e}</option>{/each}
						</select>
						<input bind:value={af.name} required disabled={readonly} placeholder={af.ecosystem === 'Maven' ? 'com.acme:billing-core' : $t('advEd.namePlaceholderGeneric')} class="input input-bordered input-sm flex-1 min-w-48 font-mono" />
					{:else}
						<input bind:value={af.purl} required disabled={readonly} placeholder={$t('advEd.purlPlaceholder')} class="input input-bordered input-sm flex-1 min-w-48 font-mono" />
					{/if}
					{#if !readonly && form.affected.length > 1}
						<button type="button" class="btn btn-ghost btn-xs text-error" onclick={() => form.affected.splice(i, 1)}>{$t('advEd.removePackage')}</button>
					{/if}
				</div>

				{#each af.ranges as r, j}
					<div class="flex flex-wrap items-center gap-2 pl-2 border-l-2 border-base-300">
						<select bind:value={r.type} disabled={readonly} class="select select-bordered select-xs">
							<option value="ECOSYSTEM">ECOSYSTEM</option>
							<option value="SEMVER">SEMVER</option>
							<option value="GIT">GIT ({$t('advEd.gitIgnored')})</option>
						</select>
						{#each r.events as ev, k}
							<span class="join">
								<select bind:value={ev.kind} disabled={readonly} class="select select-bordered select-xs join-item">
									{#each EVENT_KINDS as kind}<option value={kind}>{kind}</option>{/each}
								</select>
								<input bind:value={ev.version} disabled={readonly} placeholder="1.2.3" class="input input-bordered input-xs join-item w-24 font-mono" />
								{#if !readonly}
									<button type="button" class="btn btn-xs join-item" aria-label={$t('advEd.removeEventAria')} onclick={() => r.events.splice(k, 1)}>×</button>
								{/if}
							</span>
						{/each}
						{#if !readonly}
							<button type="button" class="btn btn-ghost btn-xs" onclick={() => r.events.push({ kind: 'fixed', version: '' })}>{$t('advEd.addEvent')}</button>
							<button type="button" class="btn btn-ghost btn-xs text-error" onclick={() => af.ranges.splice(j, 1)}>{$t('advEd.removeRange')}</button>
						{/if}
					</div>
				{/each}
				{#if !readonly}
					<div><button type="button" class="btn btn-ghost btn-xs" onclick={() => addRange(af)}>{$t('advEd.addRange')}</button></div>
				{/if}
				<Field label={$t('advEd.versionsFieldLabel')} hint={$t('advEd.versionsFieldHint')}>
					<input bind:value={af.versions} disabled={readonly} placeholder="2.3.0, 2.3.1" class="input input-bordered input-sm w-full font-mono" />
				</Field>
			</div>
		{/each}
		{#if !readonly}
			<div><button type="button" class="btn btn-ghost btn-sm" onclick={addAffected}>{$t('advEd.addAffectedPackage')}</button></div>
		{/if}
	</div>

	{#if !readonly}
		<div class="flex justify-end">
			<button class="btn btn-primary btn-sm" disabled={saving}>
				{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}{submitLabel || $t('common.save')}
			</button>
		</div>
	{/if}
</form>
