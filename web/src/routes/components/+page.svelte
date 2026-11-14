<script>
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto, replaceState } from '$app/navigation';
	import { api, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import { fmtDate } from '$lib/format.js';
	import State from '$lib/components/State.svelte';
	import VulnBadge from '$lib/components/VulnBadge.svelte';
	import ExportMenu from '$lib/components/ExportMenu.svelte';
	import LicenseBadge from '$lib/components/LicenseBadge.svelte';
	import OutdatedBadge from '$lib/components/OutdatedBadge.svelte';
	import IntegrityBadge from '$lib/components/IntegrityBadge.svelte';
	import AIBadge from '$lib/components/AIBadge.svelte';

	// Seed the query from the URL so a reload / shared link restores the search.
	const sp = $page.url.searchParams;
	let q = $state({
		name: sp.get('name') ?? '',
		contains: sp.get('contains') ?? '',
		version: sp.get('version') ?? '',
		purl: sp.get('purl') ?? '',
		latest: sp.get('latest') === 'true',
		vulnerable: sp.get('vulnerable') ?? '',
		outdated: sp.get('outdated') ?? '',
		integrity: sp.get('integrity') ?? '',
		kind: sp.get('kind') ?? '',
		license: sp.get('license') ?? '',
		license_category: sp.get('license_category') ?? ''
	});
	// ScanCode categories for the license-category filter.
	let licenseCategories = $state(/** @type {string[]} */ ([]));
	let cve = $state('');
	let results = $state(/** @type {any[]} */ ([]));
	let loading = $state(false);
	let searched = $state(false);

	function syncURL() {
		const params = new URLSearchParams();
		for (const k of /** @type {const} */ (['name', 'contains', 'version', 'purl', 'vulnerable', 'outdated', 'integrity', 'kind', 'license', 'license_category'])) if (q[k]) params.set(k, q[k]);
		if (q.latest) params.set('latest', 'true');
		replaceState('?' + params.toString(), {});
	}

	// The search as API filters — what's listed, and what Export downloads.
	function searchQuery() {
		const filters = {};
		if (q.name) filters.name = q.name; // exact match
		if (q.contains) filters.search = q.contains; // substring match
		if (q.version) filters.version = q.version;
		if (q.purl) filters.purl = q.purl;
		if (q.latest) filters.latest = true;
		if (q.vulnerable) filters.vulnerable = q.vulnerable;
		if (q.outdated) filters.outdated = q.outdated;
		if (q.integrity) filters.integrity = q.integrity;
		if (q.kind) filters.kind = q.kind;
		if (q.license) filters.license = q.license;
		if (q.license_category) filters.license_category = q.license_category;
		return filters;
	}

	/** @param {SubmitEvent} [e] */
	async function search(e) {
		// A user search updates the URL; the initial one runs from the URL, before
		// the router is ready for replaceState (which throws during onMount).
		if (e) {
			e.preventDefault();
			syncURL();
		}
		loading = true;
		searched = true;
		try {
			const res = await api.searchComponents({ ...searchQuery(), limit: 200 });
			results = res.components ?? [];
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	// Auto-run the search when arriving with query params (reload / shared link).
	onMount(() => {
		if (q.name || q.contains || q.version || q.purl || q.vulnerable || q.outdated || q.integrity || q.kind || q.license || q.license_category) search();
		api.listLicenses({ limit: 1 }).then((r) => (licenseCategories = r.categories ?? [])).catch(() => {});
	});

	/** @param {SubmitEvent} e */
	function openVuln(e) {
		e.preventDefault();
		if (cve.trim()) goto(`/vulnerabilities/${encodeURIComponent(cve.trim())}`);
	}
</script>

<div class="mb-5 flex flex-wrap items-end justify-between gap-3">
	<div>
		<h1 class="text-2xl font-bold">{$t('comp.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('comp.subtitle')}</p>
	</div>
	<form onsubmit={openVuln} class="join" title={$t('comp.whoShippedTitle')}>
		<input bind:value={cve} placeholder={$t('comp.cvePlaceholder')} class="input input-bordered input-sm join-item w-44" />
		<button class="btn btn-sm join-item">{$t('comp.whoShippedIt')}</button>
	</form>
</div>

<form onsubmit={search} class="card bg-base-100 shadow-sm mb-5">
	<div class="card-body flex-row flex-wrap items-end gap-3">
		<label class="form-control">
			<span class="label-text mb-1">{$t('comp.nameExact')} <span class="text-base-content/40">{$t('comp.exact')}</span></span>
			<input bind:value={q.name} placeholder={$t('comp.namePlaceholder')} class="input input-bordered input-sm" />
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('comp.nameContains')} <span class="text-base-content/40">{$t('comp.contains')}</span></span>
			<input bind:value={q.contains} placeholder={$t('comp.containsPlaceholder')} class="input input-bordered input-sm" />
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('comp.version')}</span>
			<input bind:value={q.version} placeholder={$t('comp.versionPlaceholder')} class="input input-bordered input-sm" />
		</label>
		<label class="form-control flex-1 min-w-48">
			<span class="label-text mb-1">{$t('comp.orPurl')}</span>
			<input bind:value={q.purl} placeholder="pkg:maven/…" class="input input-bordered input-sm w-full" />
		</label>
		<select bind:value={q.vulnerable} class="select select-bordered select-sm">
			<option value="">{$t('comp.vulnAny')}</option>
			<option value="true">{$t('comp.vulnOnly')}</option>
			<option value="false">{$t('comp.cleanOnly')}</option>
		</select>
		<select bind:value={q.outdated} class="select select-bordered select-sm" title={$t('comp.outdatedTitle')}>
			<option value="">{$t('comp.outdatedAny')}</option>
			<option value="true">{$t('comp.outdatedOnly')}</option>
			<option value="false">{$t('comp.latestOnly')}</option>
		</select>
		<select bind:value={q.integrity} class="select select-bordered select-sm" title={$t('comp.integrityTitle')}>
			<option value="">{$t('comp.integrityAny')}</option>
			<option value="mismatch">{$t('comp.integrityMismatch')}</option>
			<option value="verified">{$t('comp.integrityVerified')}</option>
			<option value="unknown">{$t('comp.integrityUnknown')}</option>
		</select>
		<select bind:value={q.kind} class="select select-bordered select-sm" title={$t('comp.kindTitle')}>
			<option value="">{$t('comp.kindAny')}</option>
			<option value="ai">{$t('comp.kindAi')}</option>
			<option value="model">{$t('comp.kindModel')}</option>
			<option value="dataset">{$t('comp.kindDataset')}</option>
			<option value="ai-service">{$t('comp.kindAiService')}</option>
			<option value="software">{$t('comp.kindSoftware')}</option>
		</select>
		<label class="form-control">
			<span class="label-text mb-1">{$t('comp.license')}</span>
			<input bind:value={q.license} placeholder={$t('comp.licensePlaceholder')} class="input input-bordered input-sm w-36" />
		</label>
		<select bind:value={q.license_category} class="select select-bordered select-sm" title={$t('comp.licenseCategoryTitle')}>
			<option value="">{$t('comp.licenseCategoryAny')}</option>
			{#each licenseCategories as cat (cat)}<option value={cat}>{cat}</option>{/each}
		</select>
		<label class="label cursor-pointer gap-2">
			<input type="checkbox" bind:checked={q.latest} class="checkbox checkbox-sm" />
			<span class="label-text">{$t('comp.latestOnlyCheckbox')}</span>
		</label>
		<button class="btn btn-primary btn-sm">{$t('comp.search')}</button>
	</div>
</form>

<State {loading} empty={searched && !loading && results.length === 0} emptyText={$t('comp.empty')} />
{#if !searched && !loading}
	<p class="text-sm text-base-content/50">
		{$t('comp.tip1')} <em>{$t('comp.tipVulnOnly')}</em> {$t('comp.tip2')}
	</p>
{/if}

{#if !loading && results.length > 0}
	<div class="mb-2 flex items-center justify-between gap-2">
		<p class="text-sm text-base-content/60">{$t('comp.occurrences', { count: results.length })}</p>
		<ExportMenu run={(/** @type {string} */ format) => api.exportComponents(searchQuery(), format)} />
	</div>
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr><th>{$t('comp.colProject')}</th><th>{$t('comp.colComponent')}</th><th>{$t('comp.colVersion')}</th><th>{$t('comp.colLatest')}</th><th>{$t('comp.colVulnerabilities')}</th><th>{$t('comp.colFile')}</th><th>{$t('comp.colArtifact')}</th><th>{$t('comp.colLicense')}</th><th>{$t('comp.colSeen')}</th></tr>
			</thead>
			<tbody>
				{#each results as c (c.id)}
					<tr class="hover">
						<td><a class="link link-primary" href={`/projects/${c.project_id}`}>{c.project_name}</a></td>
						<td>{c.name} <AIBadge {c} /></td>
						<td class="text-xs">{c.version || '—'}</td>
						<td><OutdatedBadge {c} /> <IntegrityBadge integrity={c.integrity} /></td>
						<td>
							<VulnBadge count={c.vuln_count} severity={c.max_severity} kev={c.kev} vulns={c.vulns} />
							{#each (c.vulns ?? []).slice(0, 3) as v (v)}
								<a class="link link-hover text-xs ml-1" href={`/vulnerabilities/${encodeURIComponent(v)}`}>{v}</a>
							{/each}
							{#if (c.vulns?.length ?? 0) > 3}<span class="text-xs text-base-content/50"> +{c.vulns.length - 3}</span>{/if}
						</td>
						<td class="text-xs font-mono text-base-content/70 max-w-xs truncate" title={c.file_path}>{c.file_path || '—'}</td>
						<td class="text-xs"><a class="link link-hover" href={`/sboms/${c.sbom_id}`}>{c.artifact || '—'}{#if c.sbom_version}<span class="text-base-content/50"> @{c.sbom_version}</span>{/if}</a></td>
						<td><LicenseBadge {c} /></td>
						<td class="text-xs text-base-content/60">{fmtDate(c.sbom_created_at)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
