<script>
	import { me, features, isOn } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { SETTINGS_NAV, visible } from '#lib/nav.js';

	let sections = $derived(visible(SETTINGS_NAV, { admin: !!$me?.is_admin, on: (f) => isOn($features, f) }));
</script>

<svelte:head><title>{$t('nav.settings')} · Xila</title></svelte:head>

<div class="mb-6">
	<h1 class="text-2xl font-bold">{$t('nav.settings')}</h1>
	<p class="text-sm text-base-content/60">{$me?.is_admin ? $t('settings.subtitleAdmin') : $t('settings.subtitle')}</p>
</div>

<div class="space-y-8">
	{#each sections as section}
		<section>
			{#if section.key}<h2 class="mb-3 text-xs font-semibold uppercase tracking-wide text-base-content/60">{$t(section.key)}</h2>{/if}
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
				{#each section.items as item (item.href)}
					<a href={item.href} class="card border border-base-300 bg-base-100 transition-colors hover:border-primary">
						<div class="card-body gap-1 p-4">
							<h3 class="font-semibold">{$t(item.key)}</h3>
							{#if item.desc}<p class="text-sm text-base-content/60">{$t(item.desc)}</p>{/if}
						</div>
					</a>
				{/each}
			</div>
		</section>
	{/each}
</div>
