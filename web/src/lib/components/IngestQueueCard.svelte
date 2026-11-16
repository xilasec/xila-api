<script>
	// Instance admin only (M11 11.6/11.7): the ingest queue's current depth —
	// fair-queued across tenants and capped at one in-flight job per project,
	// so this never reflects a single burst starving everyone else — plus the
	// live overrides for the backpressure threshold and worker count per node.
	// Both apply on every node's next queue sample, no restart.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	let queue = $state(/** @type {any} */ (null));
	let settings = $state(/** @type {any} */ (null));
	let form = $state({ max_queue_depth: '', workers: '' });
	let saving = $state(false);
	let error = $state('');

	/** @param {any} s */
	function publish(s) {
		settings = s;
		form = {
			max_queue_depth: s.max_queue_depth ?? '',
			workers: s.workers ?? ''
		};
	}

	async function load() {
		try {
			const [q, s] = await Promise.all([api.ingestQueue(), api.ingestSettings()]);
			queue = q;
			publish(s);
		} catch (err) {
			error = errorMessage(err);
		}
	}

	async function save() {
		saving = true;
		try {
			publish(
				await api.setIngestSettings({
					max_queue_depth: form.max_queue_depth === '' ? null : Number(form.max_queue_depth),
					workers: form.workers === '' ? null : Number(form.workers)
				})
			);
			notify($t('ingest.saved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	onMount(load);
</script>

{#if queue?.async}
	<div class="card bg-base-100 shadow-sm mb-4">
		<div class="card-body p-5">
			<h3 class="font-semibold mb-1">{$t('ingest.title')}</h3>
			{#if error}
				<p class="text-sm text-error">{error}</p>
			{:else if queue}
				<div class="flex flex-wrap gap-4 text-sm mb-3">
					<span>{$t('ingest.pending', { count: queue.pending })}</span>
					<span>{$t('ingest.processing', { count: queue.processing })}</span>
					{#if queue.failed > 0}<span class="text-warning">{$t('ingest.failed', { count: queue.failed })}</span>{/if}
					<span class="opacity-70">{$t('ingest.oldestWait', { seconds: Math.round(queue.oldest_wait_seconds) })}</span>
					{#if queue.saturated}<span class="badge badge-error badge-sm">{$t('ingest.saturated')}</span>{/if}
				</div>
				<p class="text-xs text-base-content/60 mb-3">{$t('ingest.intro')}</p>
				<div class="flex flex-wrap items-end gap-3">
					<label class="form-control">
						<span class="label-text text-xs">{$t('ingest.maxQueueDepth')}</span>
						<input type="number" min="0" class="input input-bordered input-sm w-32"
							placeholder={$t('ingest.useDefault', { value: settings?.effective_max_queue_depth ?? 0 })}
							bind:value={form.max_queue_depth} />
					</label>
					<label class="form-control">
						<span class="label-text text-xs">{$t('ingest.workers')}</span>
						<input type="number" min="0" class="input input-bordered input-sm w-32"
							placeholder={$t('ingest.useDefault', { value: settings?.effective_workers ?? 0 })}
							bind:value={form.workers} />
					</label>
					<button class="btn btn-primary btn-sm" disabled={saving} onclick={save}>
						{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}
						{$t('ingest.save')}
					</button>
				</div>
				<p class="text-xs text-base-content/50 mt-2">
					{$t('ingest.effective', { depth: settings?.effective_max_queue_depth ?? 0, workers: settings?.effective_workers ?? 0 })}
				</p>
			{/if}
		</div>
	</div>
{/if}
