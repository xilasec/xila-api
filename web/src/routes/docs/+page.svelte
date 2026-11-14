<script>
	import { onMount } from 'svelte';
	import { errorMessage } from '#lib/api.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';

	let spec = $state(/** @type {any} */ (null));
	let loading = $state(true);
	let error = $state('');
	let query = $state('');
	let openOp = $state('');

	// The spec is served by the API itself, so these docs always describe the
	// version you are actually running — and they work offline.
	onMount(async () => {
		try {
			const res = await fetch('/api/v1/openapi.json');
			if (!res.ok) throw new Error(`spec unavailable (${res.status})`);
			spec = await res.json();
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	});

	/** @type {Record<string, string>} */
	const METHOD_STYLE = {
		get: 'badge-info',
		post: 'badge-success',
		put: 'badge-warning',
		patch: 'badge-warning',
		delete: 'badge-error'
	};

	/** Flatten paths → a list of operations, grouped by tag, in the spec's tag order. */
	const groups = $derived.by(() => {
		if (!spec) return [];
		/** @type {Map<string, { name: string, description?: string, ops: any[] }>} */
		const byTag = new Map();
		for (const tag of spec.tags ?? []) byTag.set(tag.name, { ...tag, ops: [] });

		for (const [path, methods] of Object.entries(spec.paths ?? {})) {
			for (const [method, op] of Object.entries(/** @type {Record<string, any>} */ (methods))) {
				const tag = op.tags?.[0] ?? 'Other';
				if (!byTag.has(tag)) byTag.set(tag, { name: tag, description: '', ops: [] });
				byTag.get(tag)?.ops.push({ ...op, path, method, id: `${method} ${path}` });
			}
		}
		const q = query.trim().toLowerCase();
		return [...byTag.values()]
			.map((g) => ({
				...g,
				ops: g.ops
					.filter(
						(o) =>
							!q ||
							o.path.toLowerCase().includes(q) ||
							o.summary?.toLowerCase().includes(q) ||
							o.method.includes(q)
					)
					.sort((a, b) => a.path.localeCompare(b.path))
			}))
			.filter((g) => g.ops.length > 0);
	});

	const opCount = $derived(groups.reduce((n, g) => n + g.ops.length, 0));

	/** @param {string} id */
	function toggle(id) {
		openOp = openOp === id ? '' : id;
	}

	/** Resolve a local $ref against the spec. @param {any} node @returns {any} */
	function deref(node) {
		if (!node || typeof node !== 'object') return node;
		if (node.$ref?.startsWith('#/')) {
			let cur = spec;
			for (const part of node.$ref.slice(2).split('/')) cur = cur?.[part];
			return deref(cur);
		}
		return node;
	}

	/** A one-line type label for a schema. @param {any} schema @returns {string} */
	function typeOf(schema) {
		const s = deref(schema);
		if (!s) return '';
		if (s.enum) return s.enum.map((/** @type {any} */ e) => (e === '' ? '""' : e)).join(' | ');
		if (Array.isArray(s.type)) return s.type.join(' | ');
		if (s.type === 'array') return `${typeOf(s.items)}[]`;
		return s.type ?? 'object';
	}

	/** The response body schema's properties, for the little response table. @param {any} op */
	function bodyProps(op) {
		const ok = op.responses?.['200'] ?? op.responses?.['201'];
		const schema = deref(ok?.content?.['application/json']?.schema);
		if (!schema) return [];
		return Object.entries(schema.properties ?? {}).map(([name, s]) => ({
			name,
			type: typeOf(s),
			description: deref(s)?.description ?? ''
		}));
	}

	/** @param {any} op */
	function requestProps(op) {
		const schema = deref(op.requestBody?.content?.['application/json']?.schema);
		if (!schema?.properties) return [];
		const required = new Set(schema.required ?? []);
		return Object.entries(schema.properties).map(([name, s]) => ({
			name,
			type: typeOf(s),
			required: required.has(name),
			description: deref(s)?.description ?? ''
		}));
	}

	/** @param {any} op @param {string} where @returns {any[]} */
	function params(op, where) {
		return /** @type {any[]} */ (op.parameters ?? [])
			.map(deref)
			.filter((p) => p?.in === where)
			.map((p) => ({
				name: p.name,
				type: typeOf(p.schema),
				required: !!p.required,
				description: p.description ?? ''
			}));
	}
</script>

<svelte:head><title>{$t('docs.pageTitle')}</title></svelte:head>

<div class="mb-6">
	<h1 class="text-2xl font-bold">{$t('docs.title')}</h1>
	<p class="mt-1 text-sm text-base-content/60">
		{$t('docs.intro')}
		<a class="link" href="/api/v1/openapi.json" target="_blank" rel="noreferrer">openapi.json</a>
		{$t('docs.introLinkSep')}
		<a class="link" href="/api/v1/openapi.yaml" target="_blank" rel="noreferrer">openapi.yaml</a>
		{$t('docs.introEnd')}
	</p>
</div>

<State {loading} {error} empty={false} />

{#if spec}
	<div class="mb-4 flex flex-wrap items-center gap-3">
		<input
			bind:value={query}
			placeholder={$t('docs.filterPlaceholder')}
			class="input input-bordered input-sm w-full max-w-sm"
		/>
		<span class="text-xs text-base-content/50">{$t('docs.endpointCount', { count: opCount })}</span>
	</div>

	<div class="mb-6 rounded-box bg-base-100 p-4 text-sm shadow-sm">
		<p class="mb-2">
			{$t('docs.authPre')} <code>/health</code>, <code>/ready</code> {$t('docs.authAnd')}
			<code>/api/v1/auth/*</code> {$t('docs.authPost', { jwt: $t('docs.jwt') })}
			<code>POST /auth/login</code>{$t('docs.authOr', { apiToken: $t('docs.apiToken'), prefix: 'xila_…' })}
			<code>POST /tokens</code> {$t('docs.authEnd')}
		</p>
		<pre class="rounded bg-base-200 p-2 text-xs"><code>Authorization: Bearer &lt;token&gt;</code></pre>
	</div>

	{#each groups as group (group.name)}
		<section class="mb-8">
			<h2 class="text-lg font-semibold">{group.name}</h2>
			{#if group.description}
				<p class="mb-2 text-sm text-base-content/60">{group.description}</p>
			{/if}

			<div class="divide-y divide-base-300 overflow-hidden rounded-box bg-base-100 shadow-sm">
				{#each group.ops as op (op.id)}
					<div>
						<button
							class="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-base-200"
							onclick={() => toggle(op.id)}
						>
							<span class="badge badge-sm w-16 justify-center font-mono uppercase {METHOD_STYLE[op.method] ?? 'badge-ghost'}">
								{op.method}
							</span>
							<code class="text-sm">{op.path}</code>
							<span class="ml-auto truncate pl-4 text-xs text-base-content/60">{op.summary}</span>
						</button>

						{#if openOp === op.id}
							<div class="space-y-4 border-t border-base-300 bg-base-200/40 px-4 py-4 text-sm">
								{#if op.description}
									<p class="whitespace-pre-line text-base-content/80">{op.description}</p>
								{/if}

								{#each [[$t('docs.pathParams'), params(op, 'path')], [$t('docs.queryParams'), params(op, 'query')]] as [label, rows]}
									{#if rows.length > 0}
										<div>
											<h3 class="mb-1 font-semibold">{label}</h3>
											<table class="table table-xs">
												<tbody>
													{#each rows as p (p.name)}
														<tr>
															<td class="w-40 font-mono">{p.name}{#if p.required}<span class="text-error"> *</span>{/if}</td>
															<td class="w-40 text-base-content/60">{p.type}</td>
															<td class="whitespace-pre-line">{p.description}</td>
														</tr>
													{/each}
												</tbody>
											</table>
										</div>
									{/if}
								{/each}

								{#if requestProps(op).length > 0}
									<div>
										<h3 class="mb-1 font-semibold">{$t('docs.requestBody')}</h3>
										<table class="table table-xs">
											<tbody>
												{#each requestProps(op) as p (p.name)}
													<tr>
														<td class="w-40 font-mono">{p.name}{#if p.required}<span class="text-error"> *</span>{/if}</td>
														<td class="w-40 text-base-content/60">{p.type}</td>
														<td class="whitespace-pre-line">{p.description}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{:else if op.requestBody}
									<div>
										<h3 class="mb-1 font-semibold">{$t('docs.requestBody')}</h3>
										<p class="text-base-content/70">
											{deref(op.requestBody.content?.['application/json']?.schema)?.description ??
												$t('docs.jsonDocument')}
										</p>
									</div>
								{/if}

								<div>
									<h3 class="mb-1 font-semibold">{$t('docs.responses')}</h3>
									<div class="flex flex-wrap gap-2">
										{#each Object.entries(op.responses ?? {}) as [code, res] (code)}
											<span
												class="badge badge-sm {code.startsWith('2')
													? 'badge-success'
													: code.startsWith('4') || code.startsWith('5')
														? 'badge-error'
														: 'badge-ghost'}"
												title={deref(res)?.description ?? ''}
											>
												{code}
											</span>
										{/each}
									</div>
									{#each Object.entries(op.responses ?? {}) as [code, res] (code)}
										{#if deref(res)?.description}
											<p class="mt-1 text-xs text-base-content/60">
												<code>{code}</code> — {deref(res).description}
											</p>
										{/if}
									{/each}

									{#if bodyProps(op).length > 0}
										<table class="table table-xs mt-2">
											<tbody>
												{#each bodyProps(op) as p (p.name)}
													<tr>
														<td class="w-40 font-mono">{p.name}</td>
														<td class="w-40 text-base-content/60">{p.type}</td>
														<td class="whitespace-pre-line">{p.description}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									{/if}
								</div>
							</div>
						{/if}
					</div>
				{/each}
			</div>
		</section>
	{/each}
{/if}
