<script>
	// A component's AI inventory kind (model / dataset / AI service) as a badge;
	// clicking it opens the model card the ML-BOM carried. Nothing for software.
	import { t } from '$lib/i18n.js';

	/** @type {{ c: any }} */
	let { c } = $props();

	/** @type {HTMLDialogElement | undefined} */
	let dialog = $state();

	/** @type {Record<string, import('$lib/i18n.js').MessageKey>} */
	const LABEL_KEY = { model: 'aibadge.model', dataset: 'aibadge.dataset', 'ai-service': 'aibadge.aiService' };
	const styles = /** @type {Record<string, string>} */ ({ model: 'badge-secondary', dataset: 'badge-accent', 'ai-service': 'badge-info' });
	const labelKey = $derived(LABEL_KEY[c?.kind ?? '']);
	const ml = $derived(c?.ml ?? {});

	// Only http(s) links are rendered as links: the URLs come from the SBOM.
	/** @param {string} u */
	const isWeb = (u) => /^https?:\/\//i.test(u ?? '');

	/** @param {{ group?: string, name: string, version?: string }} a */
	const coords = (a) => (a.group ? `${a.group}/` : '') + a.name + (a.version ? `@${a.version}` : '');

	const facts = $derived(
		/** @type {[string, string][]} */ (
			[
				[$t('aibadge.supplier'), ml.supplier],
				[$t('aibadge.manufacturer'), ml.manufacturer],
				[$t('aibadge.publisher'), ml.publisher],
				[$t('aibadge.task'), ml.task],
				[$t('aibadge.approach'), ml.approach],
				[$t('aibadge.architectureFamily'), ml.architecture_family],
				[$t('aibadge.architecture'), ml.model_architecture],
				[$t('aibadge.inputs'), (ml.inputs ?? []).join(', ')],
				[$t('aibadge.outputs'), (ml.outputs ?? []).join(', ')],
				[$t('aibadge.license'), c?.license_expression || c?.license]
			].filter(([, v]) => v)
		)
	);
</script>

{#if labelKey}
	<button type="button" class="badge {styles[c.kind]} badge-xs whitespace-nowrap cursor-pointer" title={$t('aibadge.showCardTitle')} onclick={() => dialog?.showModal()}>{$t(labelKey)}</button>
	<dialog bind:this={dialog} class="modal" aria-labelledby="ml-card-{c.id}">
		<div class="modal-box max-w-2xl">
			<h3 id="ml-card-{c.id}" class="text-lg font-bold">
				{c.group ? `${c.group}/` : ''}{c.name}{#if c.version}<span class="text-base-content/50 text-sm font-normal"> @{c.version}</span>{/if}
				<span class="badge {styles[c.kind]} badge-sm ml-2 align-middle">{$t(labelKey)}</span>
			</h3>
			{#if ml.description}<p class="mt-2 text-sm text-base-content/70">{ml.description}</p>{/if}

			{#if facts.length}
				<table class="table table-sm mt-3">
					<tbody>
						{#each facts as [k, v] (k)}
							<tr><th class="w-44 text-base-content/60 font-normal">{k}</th><td class="break-all">{v}</td></tr>
						{/each}
					</tbody>
				</table>
			{:else}
				<p class="mt-3 text-sm text-base-content/50">{$t('aibadge.noFacts')}</p>
			{/if}

			{#if ml.datasets?.length || ml.data?.length}
				<h4 class="mt-4 mb-1 font-semibold text-sm">{c.kind === 'dataset' ? $t('aibadge.contents') : $t('aibadge.datasetsHeading')}</h4>
				<ul class="text-sm list-disc ml-5">
					{#each [...(ml.datasets ?? []), ...(ml.data ?? [])] as d, i (i)}
						<li>
							{d.name || d.ref || $t('aibadge.unnamed')}
							{#if d.type}<span class="text-base-content/50"> · {d.type}</span>{/if}
							{#if d.classification}<span class="badge badge-ghost badge-xs ml-1">{d.classification}</span>{/if}
							{#if d.ref}<span class="text-xs text-base-content/50"> (component {d.ref})</span>{/if}
							{#if d.url}
								{#if isWeb(d.url)}<a class="link link-primary text-xs ml-1 break-all" href={d.url} target="_blank" rel="noopener noreferrer">{d.url}</a>
								{:else}<span class="text-xs font-mono ml-1 break-all">{d.url}</span>{/if}
							{/if}
						</li>
					{/each}
				</ul>
			{/if}

			{#if ml.ancestors?.length}
				<h4 class="mt-4 mb-1 font-semibold text-sm">{$t('aibadge.derivedFrom')}</h4>
				<ul class="text-sm list-disc ml-5">
					{#each ml.ancestors as a, i (i)}<li>{coords(a)}</li>{/each}
				</ul>
			{/if}

			{#if ml.endpoints?.length}
				<h4 class="mt-4 mb-1 font-semibold text-sm">{$t('aibadge.endpoints')}</h4>
				<ul class="text-sm font-mono list-disc ml-5">
					{#each ml.endpoints as e (e)}<li class="break-all">{e}</li>{/each}
				</ul>
			{/if}

			{#if ml.external_references?.length}
				<h4 class="mt-4 mb-1 font-semibold text-sm">{$t('aibadge.links')}</h4>
				<ul class="text-sm list-disc ml-5">
					{#each ml.external_references as r, i (i)}
						<li>
							<span class="text-base-content/50">{r.type}:</span>
							{#if isWeb(r.url)}<a class="link link-primary break-all" href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a>
							{:else}<span class="font-mono break-all">{r.url}</span>{/if}
						</li>
					{/each}
				</ul>
			{/if}

			<div class="modal-action">
				<form method="dialog"><button class="btn btn-sm">{$t('aibadge.close')}</button></form>
			</div>
		</div>
		<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
	</dialog>
{/if}
