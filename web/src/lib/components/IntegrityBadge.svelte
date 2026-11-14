<script>
	// A component's hashes against the digests its registry publishes for the
	// version: nothing when unknown (no comparable hash), never "verified".
	import { t } from '$lib/i18n.js';

	/** @type {{ integrity?: string }} */
	let { integrity = '' } = $props();
</script>

{#if integrity === 'mismatch'}
	<span class="badge badge-error badge-xs whitespace-nowrap" title={$t('badge.mismatchTitle')}>{$t('badge.mismatch')}</span>
{:else if integrity === 'verified'}
	<span class="badge badge-success badge-outline badge-xs whitespace-nowrap" title={$t('badge.verifiedTitle')}>{$t('badge.verified')}</span>
{/if}
