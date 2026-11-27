<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { api } from '#lib/api.js';
	import { me, features, isOn } from '#lib/stores.js';
	import { locale, translate } from '#lib/i18n.js';
	import { MAIN_NAV, SETTINGS_NAV, visible } from '#lib/nav.js';

	// Part of the app shell: speaks the user's language on every page.
	/** @param {import('#lib/i18n.js').MessageKey} key @param {import('#lib/i18n.js').MessageParams} [params] */
	const ts = (key, params) => translate($locale, key, params);

	let open = $state(false);
	let query = $state('');
	let active = $state(0);
	let projects = $state(/** @type {any[]} */ ([]));
	let loaded = false;
	/** @type {HTMLInputElement | undefined} */
	let input = $state();
	/** @type {HTMLElement | undefined} */
	let listEl = $state();

	const pages = $derived([
		{ label: ts('nav.projects'), hint: ts('palette.hint.overview'), href: '/', keywords: 'dashboard home portfolio' },
		{ label: ts('palette.findingsInbox'), hint: ts('palette.hint.triage'), href: '/findings', keywords: 'vulnerabilities' },
		{ label: ts('palette.openFindings'), hint: ts('palette.hint.filter'), href: '/findings?status=open', keywords: 'triage' },
		{ label: ts('palette.exploitable'), hint: ts('palette.hint.filter'), href: '/findings?kev=true', keywords: 'epss exploit' },
		{ label: ts('palette.byPriority'), hint: ts('palette.hint.filter'), href: '/findings?sort=priority', keywords: 'rank' },
		{ label: ts('nav.components'), hint: ts('palette.hint.sbom'), href: '/components', keywords: 'packages dependencies sbom' },
		{ label: ts('nav.licenses'), hint: ts('palette.hint.spdx'), href: '/licenses', keywords: 'spdx license groups copyleft scancode' },
		{ label: ts('nav.policies'), hint: ts('palette.hint.components'), href: '/policies', keywords: 'policy violations license outdated compliance' },
		{ label: ts('nav.advisories'), hint: ts('palette.hint.private'), href: '/advisories', keywords: 'private vulnerability database internal osv mirror' },
		{ label: ts('palette.expiring'), hint: ts('palette.hint.exceptions'), href: '/exceptions', keywords: 'risk waiver' },
		{ label: ts('nav.approvals'), hint: ts('palette.hint.assessments'), href: '/approvals', keywords: 'four-eyes review pending assessment' },
		{ label: ts('nav.notifications'), hint: ts('palette.hint.alerts'), href: '/notifications', keywords: 'slack webhook' },
		{ label: ts('nav.apiKeys'), hint: ts('palette.hint.tokens'), href: '/tokens', keywords: 'ci token' },
		...($me?.is_admin
			? [
					{ label: ts('nav.triageRules'), hint: ts('palette.hint.admin'), href: '/triage-rules', keywords: 'suppress noise' },
					{ label: ts('nav.users'), hint: ts('palette.hint.admin'), href: '/users', keywords: 'members admin' },
					{ label: ts('palette.singleSignOn'), hint: ts('palette.hint.admin'), href: '/sso', keywords: 'sso saml oidc idp groups mappings login' },
					{ label: ts('nav.features'), hint: ts('palette.hint.admin'), href: '/features', keywords: 'feature flags switches toggle turn off disable' }
				]
			: [])
	]);

	// Every other page the navigation knows, so nothing is unreachable by
	// keyboard; the curated entries above keep their keywords and shortcuts.
	const navPages = $derived.by(() => {
		const who = { admin: !!$me?.is_admin, on: (/** @type {string} */ f) => isOn($features, f) };
		const known = new Set(pages.map((p) => p.href));
		return visible([...MAIN_NAV, ...SETTINGS_NAV], who).flatMap((sec) =>
			sec.items
				.filter((i) => !known.has(i.href))
				.map((i) => ({ label: ts(i.key), hint: sec.key ? ts(sec.key) : '', href: i.href, keywords: '' }))
		);
	});

	const items = $derived([
		...pages,
		...navPages,
		{ label: ts('nav.settings'), hint: '', href: '/settings', keywords: 'admin configuration preferences' },
		...projects.map((p) => ({ label: p.name, hint: ts('palette.hint.project'), href: `/projects/${p.id}`, keywords: p.slug }))
	]);

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) return items;
		return items.filter((it) => (it.label + ' ' + it.hint + ' ' + (it.keywords ?? '')).toLowerCase().includes(q));
	});

	// Keep the highlighted row valid + in view.
	$effect(() => {
		if (active >= filtered.length) active = Math.max(0, filtered.length - 1);
	});
	$effect(() => {
		if (open) listEl?.querySelector(`[data-i="${active}"]`)?.scrollIntoView({ block: 'nearest' });
	});
	// Focus the input once the palette has rendered (effects run post-render).
	$effect(() => {
		if (open && input) input.focus();
	});

	async function show() {
		open = true;
		query = '';
		active = 0;
		if (!loaded) {
			loaded = true;
			try {
				projects = await api.listProjects();
			} catch {
				/* palette still works for pages */
			}
		}
	}
	function hide() {
		open = false;
	}
	/** @param {{ href: string } | undefined} it */
	function run(it) {
		if (!it) return;
		hide();
		goto(it.href);
	}

	/** @param {KeyboardEvent} e */
	function onKey(e) {
		const cmd = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
		if (cmd) {
			e.preventDefault();
			open ? hide() : show();
			return;
		}
		if (!open) return;
		if (e.key === 'Escape') hide();
		else if (e.key === 'ArrowDown') {
			e.preventDefault();
			active = Math.min(active + 1, filtered.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			active = Math.max(active - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			run(filtered[active]);
		}
	}

	onMount(() => {
		window.addEventListener('keydown', onKey);
		window.addEventListener('xila:command', show);
		return () => {
			window.removeEventListener('keydown', onKey);
			window.removeEventListener('xila:command', show);
		};
	});
</script>

{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
	<div class="fixed inset-0 z-[60] flex items-start justify-center bg-black/40 px-4 pt-[12vh]" onclick={hide}>
		<div class="w-full max-w-lg rounded-box bg-base-100 shadow-2xl ring-1 ring-base-content/10 overflow-hidden" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center gap-2 border-b border-base-200 px-4">
				<span class="text-base-content/40">⌕</span>
				<input
					bind:this={input}
					bind:value={query}
					placeholder={ts('palette.placeholder')}
					class="w-full bg-transparent py-3 outline-none placeholder:text-base-content/40"
				/>
				<kbd class="kbd kbd-sm hidden sm:inline">esc</kbd>
			</div>
			<div bind:this={listEl} class="max-h-80 overflow-y-auto p-2">
				{#each filtered as it, i (it.href)}
					<button
						data-i={i}
						class="flex w-full items-center gap-3 rounded-btn px-3 py-2 text-left text-sm {i === active ? 'bg-primary text-primary-content' : 'hover:bg-base-200'}"
						onmouseenter={() => (active = i)}
						onclick={() => run(it)}
					>
						<span class="flex-1 truncate">{it.label}</span>
						<span class="text-xs {i === active ? 'text-primary-content/70' : 'text-base-content/40'}">{it.hint}</span>
					</button>
				{:else}
					<div class="px-3 py-6 text-center text-sm text-base-content/40">{ts('palette.noMatches')}</div>
				{/each}
			</div>
			<div class="flex items-center justify-between border-t border-base-200 px-4 py-2 text-xs text-base-content/40">
				<span><kbd class="kbd kbd-xs">↑</kbd> <kbd class="kbd kbd-xs">↓</kbd> {ts('palette.navigate')} · <kbd class="kbd kbd-xs">↵</kbd> {ts('palette.open')}</span>
				<span>{ts('palette.results', { count: filtered.length })}</span>
			</div>
		</div>
	</div>
{/if}
