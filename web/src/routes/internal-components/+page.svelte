<script>
	// Internal (first-party) components and private package registries
	// (M13 13.11, admin): which components never reach a public registry or
	// online advisory source, and the registries that may be asked instead.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';

	const ECOSYSTEMS = ['npm', 'pypi', 'maven', 'golang', 'cargo', 'nuget', 'gem', 'composer'];
	let loading = $state(true);
	let error = $state('');
	let patterns = $state(/** @type {any[]} */ ([]));
	let registries = $state(/** @type {any[]} */ ([]));
	let busy = $state(false);
	const blankPattern = () => ({ ecosystem: '', group_pattern: '', name_pattern: '', pattern_type: 'glob' });
	let pattern = $state(blankPattern());
	const blankRegistry = () => ({ ecosystem: 'npm', url: '', auth_type: 'none', username: '', password: '', token: '', internal: false, sort_order: 0 });
	let registry = $state(blankRegistry());

	async function load() {
		loading = true;
		error = '';
		try {
			[patterns, registries] = await Promise.all([api.listComponentPatterns(), api.listPrivateRegistries()]);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {() => Promise<any>} fn */
	async function run(fn) {
		busy = true;
		try {
			await fn();
			notify($t('intcomp.saved'), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	/** @param {SubmitEvent} e */
	function addPattern(e) {
		e.preventDefault();
		run(async () => {
			await api.createComponentPattern(pattern);
			pattern = blankPattern();
		});
	}

	/** @param {SubmitEvent} e */
	function addRegistry(e) {
		e.preventDefault();
		/** @type {Record<string, any>} */
		const body = { ecosystem: registry.ecosystem, url: registry.url, auth_type: registry.auth_type,
			internal: registry.internal, sort_order: Number(registry.sort_order) || 0 };
		if (registry.auth_type === 'basic') Object.assign(body, { username: registry.username, password: registry.password });
		if (registry.auth_type === 'bearer') body.token = registry.token;
		run(async () => {
			await api.createPrivateRegistry(body);
			registry = blankRegistry();
		});
	}
</script>

<h1 class="text-2xl font-bold">{$t('intcomp.title')}</h1>
<p class="mb-4 text-sm text-base-content/60">{$t('intcomp.intro')}</p>

<State {loading} {error} />
{#if !loading && !error}
	<h2 class="text-lg font-semibold mb-2">{$t('intcomp.patterns')}</h2>
	{#if patterns.length === 0}
		<p class="text-sm text-base-content/60 mb-3">{$t('intcomp.noPatterns')}</p>
	{:else}
		<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-3">
			<table class="table table-sm">
				<thead><tr><th>{$t('intcomp.ecosystem')}</th><th>{$t('intcomp.group')}</th><th>{$t('intcomp.name')}</th><th>{$t('intcomp.type')}</th><th></th></tr></thead>
				<tbody>
					{#each patterns as p (p.id)}
						<tr>
							<td>{p.ecosystem || $t('intcomp.anyEcosystem')}</td>
							<td class="font-mono text-xs">{p.group_pattern}</td>
							<td class="font-mono text-xs">{p.name_pattern}</td>
							<td class="text-xs">{p.pattern_type === 'regex' ? $t('intcomp.regex') : $t('intcomp.glob')}</td>
							<td class="text-right"><button class="btn btn-ghost btn-xs" disabled={busy} onclick={() => run(() => api.deleteComponentPattern(p.id))}>{$t('common.delete')}</button></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	<form onsubmit={addPattern} class="bg-base-100 rounded-box shadow-sm p-4 mb-8 flex flex-wrap items-end gap-3">
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.ecosystem')}</span>
			<select bind:value={pattern.ecosystem} class="select select-bordered select-sm">
				<option value="">{$t('intcomp.anyEcosystem')}</option>
				{#each ECOSYSTEMS as eco (eco)}<option value={eco}>{eco}</option>{/each}
			</select>
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.group')}</span>
			<input bind:value={pattern.group_pattern} placeholder="@acme" class="input input-bordered input-sm font-mono" />
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.name')}</span>
			<input bind:value={pattern.name_pattern} placeholder="acme-*" class="input input-bordered input-sm font-mono" />
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.type')}</span>
			<select bind:value={pattern.pattern_type} class="select select-bordered select-sm">
				<option value="glob">{$t('intcomp.glob')}</option>
				<option value="regex">{$t('intcomp.regex')}</option>
			</select>
		</label>
		<button class="btn btn-primary btn-sm" disabled={busy || (!pattern.group_pattern && !pattern.name_pattern)}>{$t('intcomp.addPattern')}</button>
	</form>

	<h2 class="text-lg font-semibold">{$t('intcomp.registries')}</h2>
	<p class="mb-2 text-sm text-base-content/60">{$t('intcomp.registriesIntro')}</p>
	{#if registries.length === 0}
		<p class="text-sm text-base-content/60 mb-3">{$t('intcomp.noRegistries')}</p>
	{:else}
		<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm mb-3">
			<table class="table table-sm">
				<thead><tr><th>{$t('intcomp.ecosystem')}</th><th>{$t('intcomp.url')}</th><th>{$t('intcomp.auth')}</th><th>{$t('intcomp.order')}</th><th></th></tr></thead>
				<tbody>
					{#each registries as r (r.id)}
						<tr>
							<td>{r.ecosystem}{#if r.internal} <span class="badge badge-sm badge-info">{$t('intcomp.internalBadge')}</span>{/if}</td>
							<td class="font-mono text-xs">{r.url}</td>
							<td class="text-xs">{r.auth_type === 'basic' ? `${$t('intcomp.authBasic')} (${r.username})` : r.auth_type === 'bearer' ? $t('intcomp.authBearer') : $t('intcomp.authNone')}{#if r.has_password || r.has_token}{' · '}{$t('intcomp.credentialSet')}{/if}</td>
							<td class="text-xs">{r.sort_order}</td>
							<td class="text-right"><button class="btn btn-ghost btn-xs" disabled={busy} onclick={() => run(() => api.deletePrivateRegistry(r.id))}>{$t('common.delete')}</button></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	<form onsubmit={addRegistry} class="bg-base-100 rounded-box shadow-sm p-4 grid gap-3 md:grid-cols-3">
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.ecosystem')}</span>
			<select bind:value={registry.ecosystem} class="select select-bordered select-sm">
				{#each ECOSYSTEMS as eco (eco)}<option value={eco}>{eco}</option>{/each}
			</select>
		</label>
		<label class="form-control md:col-span-2">
			<span class="label-text mb-1">{$t('intcomp.url')}</span>
			<input bind:value={registry.url} required type="url" placeholder="https://npm.acme.internal" class="input input-bordered input-sm font-mono" />
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.auth')}</span>
			<select bind:value={registry.auth_type} class="select select-bordered select-sm">
				<option value="none">{$t('intcomp.authNone')}</option>
				<option value="basic">{$t('intcomp.authBasic')}</option>
				<option value="bearer">{$t('intcomp.authBearer')}</option>
			</select>
		</label>
		{#if registry.auth_type === 'basic'}
			<label class="form-control">
				<span class="label-text mb-1">{$t('intcomp.username')}</span>
				<input bind:value={registry.username} required autocomplete="off" class="input input-bordered input-sm" />
			</label>
			<label class="form-control">
				<span class="label-text mb-1">{$t('intcomp.password')}</span>
				<input bind:value={registry.password} required type="password" autocomplete="new-password" class="input input-bordered input-sm" />
			</label>
		{:else if registry.auth_type === 'bearer'}
			<label class="form-control md:col-span-2">
				<span class="label-text mb-1">{$t('intcomp.token')}</span>
				<input bind:value={registry.token} required type="password" autocomplete="off" class="input input-bordered input-sm" />
			</label>
		{:else}
			<div class="md:col-span-2"></div>
		{/if}
		<label class="label cursor-pointer justify-start gap-2 md:col-span-2">
			<input type="checkbox" bind:checked={registry.internal} class="checkbox checkbox-sm" />
			<span class="label-text">{$t('intcomp.internal')}</span>
		</label>
		<label class="form-control">
			<span class="label-text mb-1">{$t('intcomp.order')}</span>
			<input bind:value={registry.sort_order} type="number" class="input input-bordered input-sm" />
		</label>
		<div class="md:col-span-3 flex justify-end">
			<button class="btn btn-primary btn-sm" disabled={busy}>{$t('intcomp.addRegistry')}</button>
		</div>
	</form>
{/if}
