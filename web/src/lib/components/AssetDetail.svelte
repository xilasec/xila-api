<script>
	// One asset's exposure, relationships and blast radius. Editing needs editor
	// on the asset's project (the server enforces it); relation targets can be
	// any asset the caller can see, in any project.
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import { SEVERITIES, severityClass, riskTone, fmtNumber } from '#lib/format.js';
	import Badge from '#lib/components/Badge.svelte';
	import ExposureBadge from '#lib/components/ExposureBadge.svelte';
	import Field from '#lib/components/Field.svelte';
	import State from '#lib/components/State.svelte';
	import CustomFieldsEditor from '#lib/components/CustomFieldsEditor.svelte';

	/** @type {{ asset: any, onchanged?: (a: any) => void }} */
	let { asset, onchanged = () => {} } = $props();

	const EXPOSURES = ['', 'internet', 'internal', 'isolated'];
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const KIND_LABEL_KEY = { built_from: 'asset.kindBuiltFrom', deployed_as: 'asset.kindDeployedAs', depends_on: 'asset.kindDependsOn' };
	const KIND_LABEL = $derived(Object.fromEntries(Object.entries(KIND_LABEL_KEY).map(([k, key]) => [k, $t(key)])));

	let exposureForm = $state({ exposure: '', reason: '' });
	let relations = $state(/** @type {any[]} */ ([]));
	let suggestions = $state(/** @type {any[]} */ ([]));
	let osPackages = $state(0);
	let blast = $state(/** @type {any} */ (null));
	let candidates = $state(/** @type {any[]} */ ([]));
	let relForm = $state({ kind: 'built_from', other: '', direction: 'from' });
	let loading = $state(true);
	let busy = $state(false);

	async function load() {
		const id = asset.id;
		try {
			const [rels, sugg, radius] = await Promise.all([
				api.assetRelations(id),
				api.assetRelationSuggestions(id),
				api.assetBlastRadius(id)
			]);
			relations = rels;
			suggestions = sugg.suggestions ?? [];
			osPackages = sugg.os_packages ?? 0;
			blast = radius;
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	$effect(() => {
		exposureForm = { exposure: asset.exposure ?? '', reason: asset.exposure_source === 'manual' ? asset.exposure_reason : '' };
		loading = true;
		load().finally(() => (loading = false));
		api.listAllAssets().then((a) => (candidates = a.filter((/** @type {any} */ c) => c.id !== asset.id))).catch(() => (candidates = []));
	});

	/** @param {SubmitEvent} e */
	async function saveExposure(e) {
		e.preventDefault();
		busy = true;
		try {
			const updated = await api.setAssetExposure(asset.id, { exposure: exposureForm.exposure, reason: exposureForm.reason });
			notify(updated.exposure ? $t('asset.exposureSaved') : $t('asset.exposureCleared'), 'success');
			onchanged(updated);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {{ from_asset_id: string, to_asset_id: string, kind: string }} body */
	async function relate(body) {
		busy = true;
		try {
			await api.createAssetRelation(asset.id, body);
			notify($t('asset.relationAdded'), 'success');
			relForm = { kind: 'built_from', other: '', direction: 'from' };
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {SubmitEvent} e */
	function addRelation(e) {
		e.preventDefault();
		if (!relForm.other) return;
		const [from, to] = relForm.direction === 'from' ? [asset.id, relForm.other] : [relForm.other, asset.id];
		relate({ from_asset_id: from, to_asset_id: to, kind: relForm.kind });
	}

	/** @param {any} r */
	async function removeRelation(r) {
		busy = true;
		try {
			await api.deleteAssetRelation(asset.id, r.id);
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {any} r @returns {string} */
	function describe(r) {
		const from = r.from_asset_id === asset.id ? $t('asset.thisAssetCap') : r.from?.name;
		const to = r.to_asset_id === asset.id ? $t('asset.thisAssetLower') : r.to?.name;
		return `${from} ${KIND_LABEL[r.kind] ?? r.kind} ${to}`;
	}
</script>

<div class="flex flex-col gap-5">
	<section>
		<h4 class="font-semibold mb-2 flex items-center gap-2">
			{$t('asset.risk')}
			<span class="font-mono {riskTone(asset.risk_score ?? 0)}">{fmtNumber(asset.risk_score ?? 0, { maximumFractionDigits: 1 })}</span>
		</h4>
		{#if asset.total_open}
			<div class="flex flex-wrap gap-1">
				{#each SEVERITIES as sev (sev)}
					{#if asset.open_by_severity?.[sev]}
						<span class="badge badge-sm {severityClass(sev)}">{$labelOf('severity', sev)}: {asset.open_by_severity[sev]}</span>
					{/if}
				{/each}
			</div>
		{:else}
			<span class="text-xs text-base-content/50">{$t('asset.noOpenFindings')}</span>
		{/if}
	</section>

	<section>
		<h4 class="font-semibold mb-2 flex items-center gap-2">
			{$t('asset.exposure')}
			<ExposureBadge exposure={asset.exposure} source={asset.exposure_source} reason={asset.exposure_reason} />
			{#if !asset.exposure}<span class="text-xs text-base-content/50 font-normal">{$t('asset.unknownNeverDiscounts')}</span>{/if}
		</h4>
		{#if asset.exposure_source === 'inferred'}
			<p class="text-xs text-base-content/60 mb-2">{$t('asset.inferredReason', { reason: asset.exposure_reason })}</p>
		{/if}
		<form onsubmit={saveExposure} class="flex flex-wrap items-end gap-2">
			<Field label={$t('asset.setByHand')} hint={$t('asset.manualHint')}>
				<select bind:value={exposureForm.exposure} class="select select-bordered select-sm">
					{#each EXPOSURES as x}<option value={x}>{x || $t('common.unknown')}</option>{/each}
				</select>
			</Field>
			<Field label={$t('asset.reasonLabel')}>
				<input bind:value={exposureForm.reason} maxlength="1000" placeholder={$t('asset.exposureReasonPlaceholder')} class="input input-bordered input-sm w-64" />
			</Field>
			<button class="btn btn-sm btn-primary" disabled={busy}>{$t('common.save')}</button>
		</form>
	</section>

	<section>
		<h4 class="font-semibold mb-2">{$t('asset.relationships')}</h4>
		<State {loading} empty={!loading && relations.length === 0} emptyText={$t('asset.noRelationships')} />
		{#if !loading && relations.length > 0}
			<ul class="flex flex-col gap-1 mb-3">
				{#each relations as r (r.id)}
					<li class="flex items-center gap-2 text-sm">
						<span>{describe(r)}</span>
						<button class="btn btn-ghost btn-xs" disabled={busy} onclick={() => removeRelation(r)}>{$t('common.remove')}</button>
					</li>
				{/each}
			</ul>
		{/if}
		<form onsubmit={addRelation} class="flex flex-wrap items-end gap-2">
			<Field label={$t('asset.direction')}>
				<select bind:value={relForm.direction} class="select select-bordered select-sm">
					<option value="from">{$t('asset.thisAssetFromOption')}</option>
					<option value="to">{$t('asset.thisAssetToOption')}</option>
				</select>
			</Field>
			<Field label={$t('asset.kind')}>
				<select bind:value={relForm.kind} class="select select-bordered select-sm">
					{#each Object.entries(KIND_LABEL) as [k, label]}<option value={k}>{label}</option>{/each}
				</select>
			</Field>
			<Field label={$t('asset.otherAsset')}>
				<select bind:value={relForm.other} required class="select select-bordered select-sm w-64">
					<option value="" disabled>{$t('asset.choose')}</option>
					{#each candidates as c (c.id)}<option value={c.id}>{c.type.replaceAll('_', ' ')} · {c.name}</option>{/each}
				</select>
			</Field>
			<button class="btn btn-sm btn-outline" disabled={busy || !relForm.other}>{$t('common.add')}</button>
		</form>
		{#if asset.type === 'container_image'}
			<div class="mt-3 text-sm">
				{#if suggestions.length > 0}
					<p class="text-base-content/60 mb-1">{$t('asset.suggestedFrom')}</p>
					<ul class="flex flex-col gap-1">
						{#each suggestions as s (s.from_asset_id + s.to_asset_id)}
							<li class="flex items-center gap-2">
								<span>
									{s.from_asset_id === asset.id ? $t('asset.thisImageCap') : s.other.name} {$t('asset.kindBuiltFrom')}
									{s.to_asset_id === asset.id ? $t('asset.thisImageLower') : s.other.name}
								</span>
								<span class="text-xs text-base-content/50">{s.reason}</span>
								<button class="btn btn-ghost btn-xs" disabled={busy}
									onclick={() => relate({ from_asset_id: s.from_asset_id, to_asset_id: s.to_asset_id, kind: s.kind })}>{$t('asset.accept')}</button>
							</li>
						{/each}
					</ul>
				{:else if !loading}
					<p class="text-xs text-base-content/50">
						{osPackages > 0
							? $t('asset.noOsNest', { count: osPackages })
							: $t('asset.noMatchingSbom')}
					</p>
				{/if}
			</div>
		{/if}
	</section>

	<section>
		<h4 class="font-semibold mb-2">{$t('asset.blastRadius')}</h4>
		<p class="text-xs text-base-content/60 mb-2">
			{$t('asset.blastIntro')}
		</p>
		<State {loading} empty={!loading && (blast?.affected ?? []).length === 0}
			emptyText={$t('asset.blastEmpty')} />
		{#if !loading && (blast?.affected ?? []).length > 0}
			<div class="overflow-x-auto">
				<table class="table table-xs">
					<thead><tr><th>{$t('asset.colAsset')}</th><th>{$t('asset.colVia')}</th><th>{$t('asset.colDepth')}</th><th>{$t('asset.colSharedFindings')}</th></tr></thead>
					<tbody>
						{#each blast.affected as e (e.asset.id)}
							<tr>
								<td>
									<span class="badge badge-ghost badge-xs">{e.asset.type.replaceAll('_', ' ')}</span>
									{e.asset.name}
									<ExposureBadge exposure={e.asset.exposure} source={e.asset.exposure_source} reason={e.asset.exposure_reason} size="xs" />
								</td>
								<td>{KIND_LABEL[e.via] ?? e.via}</td>
								<td>{e.depth}</td>
								<td>
									{#if e.shared_count === 0}<span class="text-base-content/50">{$t('asset.none')}</span>{/if}
									<div class="flex flex-col gap-0.5">
										{#each e.shared_findings as f (f.id)}
											<a class="link link-hover flex items-center gap-1" href={`/findings/${f.id}`}>
												<Badge kind="severity" value={f.severity} size="badge-xs" />
												<span class="truncate max-w-xs">{f.cve?.[0] ?? f.package_name} — {f.title}</span>
											</a>
										{/each}
										{#if e.shared_count > e.shared_findings.length}<span class="text-xs text-base-content/50">{$t('asset.moreShared', { count: e.shared_count - e.shared_findings.length })}</span>{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
	<CustomFieldsEditor kind="assets" id={asset.id} projectId={asset.project_id} values={asset.custom} canEdit
		onsaved={(v) => onchanged({ ...asset, custom: v })} />
</div>
