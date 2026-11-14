<script>
	// A component's freshness against its package registry: an "Outdated" badge
	// with "latest x.y (N behind)", "latest" when it is on the newest release,
	// and a dash when unknown (never shown as up to date).
	import { fmtDate } from '$lib/format.js';
	import { t } from '$lib/i18n.js';

	/** @type {{ c: { latest_version?: string|null, outdated?: boolean|null, versions_behind?: number|null, version_published_at?: string|null } }} */
	let { c } = $props();

	const released = $derived(c.version_published_at ? $t('badge.released', { date: fmtDate(c.version_published_at) }) : '');
</script>

{#if c.outdated === true}
	<span class="inline-flex flex-wrap items-center gap-1 text-xs" title={released}>
		<span class="badge badge-warning badge-xs whitespace-nowrap">{$t('badge.outdated')}</span>
		<span class="whitespace-nowrap">
			{$t('badge.latestVersion', { version: c.latest_version ?? '' })}{#if c.versions_behind != null}
				<span class="text-base-content/60"> {$t('badge.behind', { count: c.versions_behind })}</span>{/if}
		</span>
	</span>
{:else if c.outdated === false}
	<span class="text-xs text-success whitespace-nowrap" title={released}>{$t('badge.latest')}</span>
{:else}
	<span class="text-xs text-base-content/40" title={$t('badge.unknownTitle')}>—</span>
{/if}
