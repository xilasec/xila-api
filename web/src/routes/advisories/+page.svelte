<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api.js';
	import { me, notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import State from '$lib/components/State.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import { fmtDate } from '$lib/format.js';

	let advisories = $state(/** @type {any[]} */ ([]));
	let hasMore = $state(false);
	let loading = $state(true);
	let q = $state('');
	let withdrawn = $state(false);

	// Admin: vulnerability sources + the local OSV mirror.
	let sources = $state(/** @type {any} */ (null));
	let importing = $state(false);
	let matching = $state(false);
	let osvText = $state('');
	let showImport = $state(false);

	async function load() {
		loading = true;
		try {
			const out = await api.listAdvisories({ q, withdrawn: withdrawn || undefined, limit: 200 });
			advisories = out.advisories ?? [];
			hasMore = out.pagination?.has_more ?? false;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}

	async function loadSources() {
		try {
			sources = await api.vulnSources();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	onMount(() => {
		load();
	});
	$effect(() => {
		if ($me?.is_admin && sources === null) loadSources();
	});

	/** @param {SubmitEvent} e */
	function search(e) {
		e.preventDefault();
		load();
	}

	/** @param {any} a */
	const packagesOf = (a) =>
		(a.affected ?? []).map((/** @type {any} */ af) => af.package?.purl || `${af.package?.ecosystem}/${af.package?.name}`).join(', ');

	/** @param {SubmitEvent} e */
	async function importOSV(e) {
		e.preventDefault();
		importing = true;
		try {
			const out = await api.importAdvisories(osvText);
			notify($t('adv.imported', { created: out.created, updated: out.updated }), 'success');
			osvText = '';
			showImport = false;
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			importing = false;
		}
	}

	/** @param {Event & { currentTarget: HTMLInputElement }} e */
	async function importFile(e) {
		const file = e.currentTarget.files?.[0];
		if (!file) return;
		importing = true;
		try {
			const out = await api.importOSVExport(file);
			notify($t('adv.mirrorImported', { inserted: out.inserted, updated: out.updated, unchanged: out.unchanged }), 'success');
			await loadSources();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			importing = false;
			e.currentTarget.value = '';
		}
	}

	async function rematch() {
		matching = true;
		try {
			const out = await api.runVulnMatch();
			notify(
				out.partial
					? $t('adv.matchedPartial', { sources: out.failed_sources.join(', '), count: out.findings })
					: $t('adv.matched', { count: out.findings }),
				out.partial ? 'error' : 'success'
			);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			matching = false;
		}
	}
</script>

<div class="flex flex-wrap items-center justify-between gap-2 mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('adv.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('adv.subtitle')}</p>
	</div>
	{#if $me?.is_admin}
		<div class="flex gap-2">
			<button class="btn btn-ghost btn-sm" onclick={() => (showImport = !showImport)}>{$t('adv.importOsv')}</button>
			<a class="btn btn-primary btn-sm" href="/advisories/new">{$t('adv.newAdvisory')}</a>
		</div>
	{/if}
</div>

{#if showImport}
	<form onsubmit={importOSV} class="bg-base-100 rounded-box shadow-sm p-4 mb-4 grid gap-2">
		<p class="text-xs text-base-content/60">{$t('adv.importHint1')} <code>id</code>{$t('adv.importHint2')}</p>
		<textarea bind:value={osvText} required rows="8" class="textarea textarea-bordered textarea-sm font-mono" placeholder={'{"id": "XILA-2026-0001", "summary": "…", "affected": [...]}'}></textarea>
		<div class="flex justify-end">
			<button class="btn btn-primary btn-sm" disabled={importing}>
				{#if importing}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('adv.import')}
			</button>
		</div>
	</form>
{/if}

{#if $me?.is_admin && sources}
	<div class="bg-base-100 rounded-box shadow-sm p-4 mb-4 flex flex-wrap items-center gap-4">
		<div>
			<div class="text-xs uppercase text-base-content/50">{$t('adv.vulnSources')}</div>
			<div class="flex gap-1 mt-1">
				{#each sources.sources as s}<span class="badge badge-ghost badge-sm">{s}</span>{/each}
			</div>
		</div>
		<div class="flex-1 min-w-48">
			<div class="text-xs uppercase text-base-content/50">{$t('adv.localMirror')}</div>
			<div class="text-sm">
				{$t('adv.mirrorCount', { count: sources.mirror?.advisories ?? 0 })}
				{#if sources.mirror?.ecosystems?.length}
					<span class="text-base-content/60">
						· {sources.mirror.ecosystems.map((/** @type {any} */ e) => `${e.ecosystem} ${e.advisories}`).join(' · ')}
					</span>
				{/if}
			</div>
		</div>
		<label class="btn btn-ghost btn-sm" class:btn-disabled={importing} title={$t('adv.uploadExportTitle')}>
			{#if importing}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('adv.uploadExport')}
			<input type="file" accept=".zip,application/zip" class="hidden" onchange={importFile} />
		</label>
		<button class="btn btn-ghost btn-sm" onclick={rematch} disabled={matching}>
			{#if matching}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('adv.rematch')}
		</button>
	</div>
{/if}

<form onsubmit={search} class="flex flex-wrap items-center gap-2 mb-3">
	<input bind:value={q} placeholder={$t('adv.searchPlaceholder')} class="input input-bordered input-sm w-72" />
	<label class="label cursor-pointer gap-2">
		<input type="checkbox" bind:checked={withdrawn} onchange={load} class="checkbox checkbox-sm" />
		<span class="label-text text-sm">{$t('adv.includeWithdrawn')}</span>
	</label>
	<button class="btn btn-sm">{$t('adv.search')}</button>
</form>

<State {loading} empty={!loading && advisories.length === 0} emptyText={$t('adv.empty')} />
{#if !loading && advisories.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('adv.colId')}</th><th>{$t('adv.colSummary')}</th><th>{$t('adv.colSeverity')}</th><th>{$t('adv.colPackages')}</th><th>{$t('adv.colAliases')}</th><th>{$t('adv.colPublished')}</th></tr></thead>
			<tbody>
				{#each advisories as a (a.id)}
					<tr class="hover" class:opacity-50={a.withdrawn}>
						<td class="font-mono whitespace-nowrap"><a class="link link-hover" href="/advisories/{encodeURIComponent(a.id)}">{a.id}</a></td>
						<td>
							{a.summary}
							{#if a.withdrawn}<span class="badge badge-ghost badge-sm ml-1">{$t('adv.withdrawn')}</span>{/if}
						</td>
						<td><Badge kind="severity" value={a.severity} /></td>
						<td class="text-xs font-mono">{packagesOf(a)}</td>
						<td class="text-xs font-mono">{(a.aliases ?? []).join(', ')}</td>
						<td class="text-xs whitespace-nowrap">{fmtDate(a.published)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if hasMore}<p class="text-xs text-base-content/60 mt-2">{$t('adv.showingNewest')}</p>{/if}
{/if}
