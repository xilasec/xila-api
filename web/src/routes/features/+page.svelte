<script>
	// Feature switches (instance admin): turn whole features off and on at
	// runtime. Off, a feature's API answers 404, its background work stops and
	// its pages and sections disappear; its data is kept for when it comes back.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify, me, features as featureStore } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';

	/** @typedef {{ key: string, enabled: boolean, available: boolean, owner_only: boolean, updated_at: string | null }} Feature */

	let loading = $state(true);
	let error = $state('');
	let list = $state(/** @type {Feature[]} */ ([]));
	let busy = $state('');

	/** @param {string} key @param {'name' | 'desc'} part */
	const text = (key, part) => $t(/** @type {import('#lib/i18n.js').MessageKey} */ (`feat.${key}.${part}`));

	/** @param {Feature[]} fs */
	function publish(fs) {
		list = fs;
		featureStore.set(Object.fromEntries(fs.map((f) => [f.key, f.enabled])));
	}

	async function load() {
		loading = true;
		error = '';
		try {
			publish((await api.features()).features);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {Feature} f */
	async function toggle(f) {
		busy = f.key;
		try {
			const next = await api.setFeature(f.key, !f.enabled);
			publish(list.map((x) => (x.key === f.key ? next : x)));
			notify($t(next.enabled ? 'feat.turnedOn' : 'feat.turnedOff').replace('{name}', text(f.key, 'name')), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	onMount(load);
</script>

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('feat.title')}</h1>
	<p class="text-sm text-base-content/60">{$t('feat.intro')}</p>
</div>

<State {loading} {error} />
{#if !loading && !error}
	<div class="card bg-base-100 shadow-sm">
		<div class="card-body p-0">
			<ul class="divide-y divide-base-200">
				{#each list as f (f.key)}
					{@const locked = !f.available || (f.owner_only && !$me?.is_owner)}
					<li class="flex items-start gap-4 p-4">
						<input type="checkbox" class="toggle toggle-primary mt-1" checked={f.enabled}
							disabled={locked || busy === f.key} onchange={() => toggle(f)}
							aria-label={text(f.key, 'name')} />
						<div class="min-w-0">
							<div class="font-medium flex flex-wrap items-center gap-2">
								{text(f.key, 'name')}
								{#if f.owner_only}<span class="badge badge-sm badge-warning badge-outline">{$t('feat.ownerOnly')}</span>{/if}
								{#if !f.available}<span class="badge badge-sm badge-ghost">{$t('feat.notConfigured')}</span>{/if}
							</div>
							<p class="text-sm text-base-content/70">{text(f.key, 'desc')}</p>
							{#if !f.available}
								<p class="text-xs text-base-content/50 mt-1">{$t('feat.notConfiguredHint')}</p>
							{:else if f.owner_only && !$me?.is_owner}
								<p class="text-xs text-base-content/50 mt-1">{$t('feat.ownerOnlyHint')}</p>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		</div>
	</div>
{/if}
