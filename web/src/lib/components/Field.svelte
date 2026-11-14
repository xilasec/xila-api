<script>
	/** Labeled form field wrapper (label + control + optional hint). The control
	 *  goes inside the <label>, so it's associated without needing ids. */
	let { label, hint = '', required = false, children } = $props();
</script>

<label class="form-control w-full">
	<span class="label-text mb-1 font-medium">
		{label}{#if required}<span class="text-error"> *</span>{/if}
	</span>
	{@render children()}
	{#if hint}
		<span class="label-text-alt text-base-content/50 mt-1">{hint}</span>
	{/if}
</label>
