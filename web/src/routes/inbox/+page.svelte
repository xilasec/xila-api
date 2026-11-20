<script>
	// The in-app notification inbox (13.8): assignments, @mentions, watched
	// project events, and (project-less) admin events. Each item is the
	// server's own filtered, access-checked list — never trimmed client-side.
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import { fmtDate } from '#lib/format.js';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';

	const LIMIT = 25;

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const FILTERS = {
		'': 'inbox.filterAll',
		unread: 'inbox.filterUnread',
		mentions: 'inbox.filterMentions',
		assigned: 'inbox.filterAssigned'
	};

	let loading = $state(true);
	let error = $state('');
	let filter = $state('');
	let items = $state(/** @type {any[]} */ ([]));
	let offset = $state(0);
	let hasMore = $state(false);
	let marking = $state('');

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.listInbox({ filter: filter || undefined, limit: LIMIT, offset });
			items = res.items ?? [];
			hasMore = res.pagination?.has_more ?? false;
		} catch (err) {
			error = err instanceof ApiError ? err.message : errorMessage(err);
		} finally {
			loading = false;
		}
	}

	/** @param {string} f */
	function setFilter(f) {
		filter = f;
		offset = 0;
		load();
	}

	async function markAllRead() {
		marking = 'all';
		try {
			await api.markInboxRead({ all: true });
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			marking = '';
		}
	}

	/** @param {any} item */
	async function open(item) {
		if (!item.read_at) {
			try {
				await api.markInboxRead({ ids: [item.id] });
			} catch {
				// best-effort — still navigate even if marking read failed
			}
		}
		if (item.link) goto(item.link);
	}

	onMount(load);
</script>

<div class="flex flex-wrap items-center justify-between gap-2 mb-5">
	<div>
		<h1 class="text-2xl font-bold">{$t('inbox.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('inbox.subtitle')}</p>
	</div>
	<button class="btn btn-sm" disabled={marking === 'all'} onclick={markAllRead}>{$t('inbox.markAllRead')}</button>
</div>

<div class="tabs tabs-boxed w-fit mb-4">
	{#each Object.entries(FILTERS) as [value, key] (value)}
		<button class="tab {filter === value ? 'tab-active' : ''}" onclick={() => setFilter(value)}>{$t(key)}</button>
	{/each}
</div>

<State {loading} {error} empty={!loading && !error && items.length === 0} emptyText={$t('inbox.empty')} />

{#if !loading && !error && items.length > 0}
	<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
		{#each items as item (item.id)}
			<li>
				<button
					class="w-full text-left p-3 flex gap-3 items-start hover:bg-base-200/60 {item.read_at ? 'opacity-60' : ''}"
					onclick={() => open(item)}
				>
					{#if !item.read_at}<span class="badge badge-primary badge-xs mt-1.5" aria-hidden="true"></span>{/if}
					<div class="flex-1 min-w-0">
						<p class="font-medium truncate">{item.title}</p>
						{#if item.body}<p class="text-sm text-base-content/60 truncate">{item.body}</p>{/if}
					</div>
					<span class="text-xs text-base-content/50 whitespace-nowrap">{fmtDate(item.created_at)}</span>
				</button>
			</li>
		{/each}
	</ul>
	<Pagination limit={LIMIT} {offset} count={items.length} {hasMore}
		onchange={(/** @type {number} */ o) => { offset = o; load(); }} />
{/if}
