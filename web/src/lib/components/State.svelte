<script>
	/** Loading / error / empty helper for async sections. */
	import { t } from '$lib/i18n.js';
	let { loading = false, error = '', empty = false, emptyText = '' } = $props();
</script>

{#if loading}
	<div class="flex justify-center py-10">
		<span class="loading loading-spinner loading-lg text-primary"></span>
	</div>
{:else if error}
	<div class="alert alert-error my-4">
		<span>{error}</span>
	</div>
{:else if empty}
	<div class="py-12 text-center">
		<div class="mb-2 text-4xl text-primary/20">◈</div>
		<p class="text-base-content/50">{emptyText || $t('common.empty')}</p>
	</div>
{/if}
