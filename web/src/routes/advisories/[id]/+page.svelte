<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api, errorMessage } from '$lib/api.js';
	import { me, notify } from '$lib/stores.js';
	import { t } from '$lib/i18n.js';
	import State from '$lib/components/State.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import AdvisoryEditor from '$lib/components/AdvisoryEditor.svelte';
	import { fmtDate } from '$lib/format.js';

	const id = $derived($page.params.id ?? '');
	const isNew = $derived(id === 'new');

	let advisory = $state(/** @type {any} */ (null));
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);

	async function load() {
		if (isNew) {
			advisory = null;
			loading = false;
			return;
		}
		loading = true;
		try {
			advisory = await api.getAdvisory(id);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}
	onMount(load);

	/** @param {any} body */
	async function save(body) {
		saving = true;
		try {
			if (isNew) {
				const out = await api.createAdvisory(body);
				notify($t('adv.publishedToast', { id: out.id }), 'success');
				await goto(`/advisories/${encodeURIComponent(out.id)}`);
				advisory = out;
			} else {
				advisory = await api.updateAdvisory(id, { ...body, withdrawn: advisory.withdrawn });
				notify($t('adv.savedToast'), 'success');
			}
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {boolean} on */
	async function setWithdrawn(on) {
		if (on && !confirm($t('adv.confirmWithdraw', { id: advisory.id }))) return;
		try {
			advisory = await api.updateAdvisory(advisory.id, { ...advisory, withdrawn: on ? new Date().toISOString() : null });
			notify(on ? $t('adv.withdrawnToast') : $t('adv.restoredToast'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function remove() {
		if (!confirm($t('adv.confirmDelete', { id: advisory.id }))) return;
		try {
			await api.deleteAdvisory(advisory.id);
			await goto('/advisories');
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="text-sm breadcrumbs mb-2">
	<ul>
		<li><a href="/advisories">{$t('adv.title')}</a></li>
		<li>{isNew ? $t('adv.new') : id}</li>
	</ul>
</div>

<State {loading} {error} />
{#if !loading && !error}
	{#if isNew}
		<h1 class="text-2xl font-bold mb-3">{$t('adv.newHeading')}</h1>
		{#if $me?.is_admin}
			<AdvisoryEditor value={null} onsubmit={save} {saving} submitLabel={$t('adv.publish')} />
		{:else}
			<p class="text-base-content/60">{$t('adv.adminOnly')}</p>
		{/if}
	{:else if advisory}
		<div class="flex flex-wrap items-center justify-between gap-2 mb-3">
			<div>
				<h1 class="text-2xl font-bold flex items-center gap-2">
					<span class="font-mono">{advisory.id}</span>
					<Badge kind="severity" value={advisory.severity} />
					{#if advisory.withdrawn}<span class="badge badge-ghost">{$t('adv.withdrawn')} {fmtDate(advisory.withdrawn)}</span>{/if}
				</h1>
				<p class="text-sm text-base-content/60">
					{$t('adv.publishedMeta', { published: fmtDate(advisory.published), updated: fmtDate(advisory.updated_at) })}
				</p>
			</div>
			{#if $me?.is_admin}
				<div class="flex gap-2">
					<button class="btn btn-ghost btn-sm" onclick={() => setWithdrawn(!advisory.withdrawn)}>
						{advisory.withdrawn ? $t('adv.restore') : $t('adv.withdraw')}
					</button>
					<button class="btn btn-ghost btn-sm text-error" onclick={remove}>{$t('adv.delete')}</button>
				</div>
			{/if}
		</div>
		<a class="link link-hover text-sm mb-3 inline-block" href="/findings?scanner=osv&rule_id={encodeURIComponent(advisory.id)}">{$t('adv.findingsFor')}</a>
		<AdvisoryEditor value={advisory} readonly={!$me?.is_admin} onsubmit={save} {saving} />
	{/if}
{/if}
