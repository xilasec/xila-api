<script>
	import { page } from '$app/state';
	import { untrack } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { fmtDate } from '#lib/format.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';

	const vulnId = $derived(decodeURIComponent(page.params.id ?? ''));
	let artifacts = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let error = $state('');

	async function load() {
		loading = true;
		error = '';
		try {
			artifacts = (await api.vulnerabilityTimeline(vulnId)).artifacts ?? [];
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('vulntl.loadFailed');
		} finally {
			loading = false;
		}
	}
	$effect(() => {
		vulnId;
		untrack(load);
	});

	const current = $derived(artifacts.filter((a) => a.currently_affected).length);
	/** @param {any} s */
	const label = (s) => s.version || fmtDate(s.created_at);
</script>

<div class="mb-5">
	<a href="/components" class="text-sm text-base-content/60 hover:text-base-content">{$t('vulntl.back')}</a>
	<h1 class="text-2xl font-bold mt-2">{vulnId}</h1>
	<p class="text-sm text-base-content/60">
		{$t('vulntl.subtitle')}
		<a class="link" href={`https://osv.dev/vulnerability/${encodeURIComponent(vulnId)}`} target="_blank" rel="noreferrer">OSV ↗</a>
	</p>
</div>

<State
	loading={loading}
	error={error}
	empty={!loading && !error && artifacts.length === 0}
	emptyText={$t('vulntl.empty')}
/>

{#if !loading && artifacts.length > 0}
	<div class="stats shadow bg-base-100 mb-4">
		<div class="stat">
			<div class="stat-title">{$t('vulntl.shipped')}</div>
			<div class="stat-value">{artifacts.length}</div>
		</div>
		<div class="stat">
			<div class="stat-title">{$t('vulntl.stillShipping')}</div>
			<div class="stat-value {current ? 'text-error' : 'text-success'}">{current}</div>
		</div>
	</div>

	{#each artifacts as a (a.project_id + a.artifact)}
		<div class="card bg-base-100 shadow-sm mb-3">
			<div class="card-body p-4">
				<div class="flex flex-wrap items-center justify-between gap-2">
					<div>
						<a class="font-semibold link link-hover" href={`/projects/${a.project_id}?tab=sboms`}>{a.project_name}</a>
						<span class="text-base-content/60"> / {a.artifact || $t('vulntl.unnamedArtifact')}</span>
						<span class="badge badge-sm ml-1 {a.is_default ? 'badge-primary' : 'badge-ghost'}" title={$t('vulntl.branchTitle')}>{a.version_name}</span>
					</div>
					{#if a.currently_affected}
						<span class="badge badge-error">{$t('vulntl.stillAffected')}</span>
					{:else}
						<span class="badge badge-success">{$t('vulntl.fixed')}</span>
					{/if}
				</div>
				<div class="text-sm text-base-content/70">
					{$t('vulntl.introducedIn')} <strong>{a.introduced_in ? label(a.introduced_in) : '—'}</strong>{#if a.fixed_in}
						· {$t('vulntl.fixedInShort')} <strong>{label(a.fixed_in)}</strong>{/if}
				</div>
				<div class="flex flex-wrap gap-1 mt-2">
					{#each a.snapshots as s (s.sbom_id)}
						<a href={`/sboms/${s.sbom_id}?tab=vulnerabilities`}
							class="badge badge-sm {s.affected ? 'badge-error' : 'badge-ghost'}"
							title="{fmtDate(s.created_at)}{s.packages.length ? ' · ' + s.packages.join(', ') : ' · ' + $t('vulntl.notAffected')}">
							{label(s)}
						</a>
					{/each}
				</div>
			</div>
		</div>
	{/each}
{/if}
