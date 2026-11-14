<script>
	// A minimal prev/next pager driven by the API's {limit, offset, count, has_more}.
	import { t } from '$lib/i18n.js';
	import { fmtNumber } from '$lib/format.js';
	let { limit = 50, offset = 0, count = 0, hasMore = false, onchange } = $props();
</script>

{#if offset > 0 || hasMore}
	<div class="flex items-center justify-between mt-3 text-sm">
		<span class="text-base-content/50">
			{count === 0 ? '0' : `${fmtNumber(offset + 1)}–${fmtNumber(offset + count)}`}
		</span>
		<div class="join">
			<button class="btn btn-sm join-item" disabled={offset === 0}
				onclick={() => onchange(Math.max(0, offset - limit))}>{$t('common.prev')}</button>
			<button class="btn btn-sm join-item" disabled={!hasMore}
				onclick={() => onchange(offset + limit)}>{$t('common.next')}</button>
		</div>
	</div>
{/if}
