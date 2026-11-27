<script>
	import '../app.css';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { token, toast, me, loadMe, features, loadFeatures, isOn } from '#lib/stores.js';
	import { api } from '#lib/api.js';
	import CommandPalette from '#lib/components/CommandPalette.svelte';
	import { locale, contentLocale, routeLocale, translate, LOCALES } from '#lib/i18n.js';
	import Icon from '#lib/components/Icon.svelte';
	import InboxBell from '#lib/components/InboxBell.svelte';
	import { MAIN_NAV, PAGE_FEATURE, visible, settingsItemFor, isCurrent } from '#lib/nav.js';

	let { children } = $props();

	const openCommand = () => window.dispatchEvent(new Event('xila:command'));

	// The shell speaks the user's language; the page does too unless it is one
	// of the pages still English-only (then all of it is English).
	/** @param {import('#lib/i18n.js').MessageKey} key */
	const ts = (key) => translate($locale, key);
	let pageLocale = $derived(routeLocale(page.route.id, $locale));
	$effect.pre(() => {
		contentLocale.set(pageLocale);
		document.documentElement.lang = pageLocale;
	});

	let theme = $state('winter');

	// Keep the current-user store in sync with auth state (drives role-aware UI).
	$effect(() => {
		if ($token) {
			loadMe();
			loadFeatures();
		} else me.set(null);
	});

	// Xila is AGPL-3.0: every page offers its users this instance's source
	// (section 13). The server's SOURCE_URL decides where; upstream until it answers.
	let sourceURL = $state('https://github.com/xilasec/xila-api');

	onMount(() => {
		theme = localStorage.getItem('xila_theme') ?? 'winter';
		document.documentElement.setAttribute('data-theme', theme);
		api.authConfig().then((c) => {
			if (typeof c?.source_url === 'string' && /^https?:\/\//.test(c.source_url)) sourceURL = c.source_url;
		}, () => {});
	});

	function toggleTheme() {
		theme = theme === 'winter' ? 'night' : 'winter';
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('xila_theme', theme);
	}

	// Sign-out is local (other devices stay signed in). When the session came
	// from a SAML IdP that supports Single Logout, the browser goes on to the
	// IdP so it ends its session too; any failure is still a local sign-out.
	async function logout() {
		/** @type {string} */
		let redirect = '';
		try {
			redirect = (await api.logout()).redirect ?? '';
		} catch {
			// the token is dropped below either way
		}
		token.set(null);
		if (redirect.startsWith('https://') || redirect.startsWith('http://')) window.location.assign(redirect);
		else goto('/login');
	}

	// Redirect to login when unauthenticated. The reset page is public: it
	// carries its own credential (the link's token).
	$effect(() => {
		const path = page.url.pathname;
		if (!$token && path !== '/login' && path !== '/reset-password') goto('/login');
		if ($token && path === '/login') goto('/');
	});

	// Pages that belong to a switchable feature: hidden from the menus while it
	// is off, and replaced by a notice if opened directly.
	let offFeature = $derived.by(() => {
		const f = PAGE_FEATURE[page.url.pathname];
		return f && !isOn($features, f) ? f : '';
	});

	let who = $derived({ admin: !!$me?.is_admin, on: (/** @type {string} */ f) => isOn($features, f) });
	let mainNav = $derived(visible(MAIN_NAV, who));
	let settingsCrumb = $derived(page.url.pathname === '/settings' ? undefined : settingsItemFor(page.url.pathname));
	let onSettings = $derived(page.url.pathname === '/settings' || !!settingsCrumb);

	// The sidebar is a drawer below lg: close it whenever the page changes.
	let drawerOpen = $state(false);
	$effect(() => {
		page.url.pathname;
		drawerOpen = false;
	});
	let initial = $derived(($me?.email || '?').trim().charAt(0).toUpperCase());
</script>

{#snippet content()}
	<main class="mx-auto w-full max-w-7xl flex-1 px-4 py-6 lg:px-8">
		{#if settingsCrumb}
			<div class="breadcrumbs mb-1 py-0 text-sm text-base-content/60">
				<ul><li><a href="/settings">{ts('nav.settings')}</a></li><li>{ts(settingsCrumb.key)}</li></ul>
			</div>
		{/if}
		<!-- A locale change remounts the page so dates and numbers re-format. -->
		{#key pageLocale}
			{#if offFeature}
				<div class="card bg-base-100 shadow-sm max-w-xl mx-auto mt-10">
					<div class="card-body">
						<h1 class="card-title">{ts('feat.offTitle')}</h1>
						<p class="text-sm text-base-content/70">{ts('feat.offText')}</p>
						{#if $me?.is_admin}<a href="/features" class="link link-primary text-sm">{ts('feat.manage')}</a>{/if}
					</div>
				</div>
			{:else}
				{@render children()}
			{/if}
		{/key}
	</main>
	<footer class="mx-auto w-full max-w-7xl px-4 pb-6 lg:px-8 text-xs text-base-content/50">
		Xila · <a class="link link-hover" href="https://www.gnu.org/licenses/agpl-3.0.html" rel="license noopener" target="_blank">AGPL-3.0</a>
		· <a class="link link-hover" href={sourceURL} rel="noopener" target="_blank">{ts('nav.sourceCode')}</a>
	</footer>
{/snippet}

{#if $token}
	<div class="drawer lg:drawer-open">
		<input id="nav-drawer" type="checkbox" class="drawer-toggle" bind:checked={drawerOpen} />
		<div class="drawer-content flex min-h-screen flex-col bg-base-200">
			<header class="navbar sticky top-0 z-30 min-h-14 gap-1 border-b border-base-300 bg-base-100/90 px-3 backdrop-blur">
				<label for="nav-drawer" class="btn btn-ghost btn-square btn-sm lg:hidden" aria-label={ts('nav.menu')}><Icon name="menu" class="h-5 w-5" /></label>
				<a href="/" class="btn btn-ghost btn-sm gap-1.5 px-2 text-lg lg:hidden"><span class="text-primary">◈</span> Xila</a>
				<div class="flex-1"></div>
				<button class="btn btn-ghost btn-sm gap-2 text-base-content/60" onclick={openCommand} aria-label={ts('nav.search')}>
					<Icon name="search" />
					<span class="hidden md:inline">{ts('nav.search')}</span>
					<kbd class="kbd kbd-xs hidden md:inline">⌘K</kbd>
				</button>
				<InboxBell />
				{#if $me}
					<div class="dropdown dropdown-end">
						<button tabindex="0" class="btn btn-ghost btn-sm gap-2 px-1.5" aria-label={ts('nav.userMenu')}>
							<span class="flex h-7 w-7 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-content">{initial}</span>
							<span class="hidden max-w-48 truncate text-sm font-normal xl:inline">{$me.email}</span>
						</button>
						<ul class="dropdown-content menu z-40 mt-2 w-64 rounded-box border border-base-300 bg-base-100 p-2 shadow-lg">
							<li class="menu-title flex-row items-center gap-2 normal-case">
								<span class="truncate">{$me.email}</span>
								{#if $me.is_admin}<span class="badge badge-primary badge-xs">{ts('nav.adminBadge')}</span>{/if}
							</li>
							<li><a href="/account" onclick={(e) => e.currentTarget.blur()}><Icon name="user" />{ts('nav.account')}</a></li>
							<li><a href="/tokens" onclick={(e) => e.currentTarget.blur()}><Icon name="key" />{ts('nav.apiKeys')}</a></li>
							<li><a href="/docs" onclick={(e) => e.currentTarget.blur()}><Icon name="doc" />{ts('nav.apiDocs')}</a></li>
							<li class="mt-1 border-t border-base-300 pt-1">
								<label class="flex items-center gap-2">
									<Icon name="globe" />
									<span class="flex-1">{ts('nav.language')}</span>
									<select class="select select-ghost select-xs w-auto" bind:value={$locale} aria-label={ts('nav.language')}>
										{#each LOCALES as l (l.id)}<option value={l.id}>{l.id.toUpperCase()}</option>{/each}
									</select>
								</label>
							</li>
							<li>
								<button onclick={toggleTheme}>
									<Icon name={theme === 'winter' ? 'moon' : 'sun'} />{ts(theme === 'winter' ? 'nav.themeDark' : 'nav.themeLight')}
								</button>
							</li>
							<li class="mt-1 border-t border-base-300 pt-1"><button onclick={logout}><Icon name="logout" />{ts('nav.signOut')}</button></li>
						</ul>
					</div>
				{/if}
			</header>
			{@render content()}
		</div>
		<div class="drawer-side z-40">
			<label for="nav-drawer" class="drawer-overlay" aria-label={ts('nav.closeMenu')}></label>
			<aside class="flex min-h-full w-60 flex-col border-r border-base-300 bg-base-100">
				<a href="/" class="flex h-14 items-center gap-2 px-5 text-xl font-bold"><span class="text-primary">◈</span> Xila</a>
				<nav class="flex-1 overflow-y-auto px-2 pb-4" aria-label={ts('nav.main')}>
					{#each mainNav as section}
						<ul class="menu menu-sm w-full gap-0.5 py-1">
							{#if section.key}<li class="menu-title pt-3 text-xs uppercase tracking-wide">{ts(section.key)}</li>{/if}
							{#each section.items as item (item.href)}
								<li>
									<a href={item.href} class:menu-active={isCurrent(item.href, page.url.pathname)} aria-current={isCurrent(item.href, page.url.pathname) ? 'page' : undefined}>
										<Icon name={item.icon ?? 'list'} />{ts(item.key)}
									</a>
								</li>
							{/each}
						</ul>
					{/each}
				</nav>
				<div class="border-t border-base-300 px-2 py-1">
					<ul class="menu menu-sm w-full">
						<li>
							<a href="/settings" class:menu-active={onSettings} aria-current={onSettings ? 'page' : undefined}><Icon name="settings" />{ts('nav.settings')}</a>
						</li>
					</ul>
				</div>
			</aside>
		</div>
	</div>
	<CommandPalette />
{:else}
	<div class="flex min-h-screen flex-col bg-base-200">{@render content()}</div>
{/if}

{#if $toast}
	<div class="toast toast-end z-50">
		<div class="alert alert-{$toast.type} shadow-lg">
			<span>{$toast.text}</span>
		</div>
	</div>
{/if}
