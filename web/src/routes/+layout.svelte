<script>
	import '../app.css';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { token, toast, me, loadMe, features, loadFeatures, isOn } from '#lib/stores.js';
	import { api } from '#lib/api.js';
	import CommandPalette from '#lib/components/CommandPalette.svelte';
	import { locale, contentLocale, routeLocale, translate, LOCALES } from '#lib/i18n.js';

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
	/** @type {Record<string, string>} */
	const pageFeature = { '/remediation': 'remediation', '/root-causes': 'remediation', '/cra': 'cra', '/custom-fields': 'custom_fields', '/psirt': 'psirt' };
	let offFeature = $derived.by(() => {
		const f = pageFeature[page.url.pathname];
		return f && !isOn($features, f) ? f : '';
	});

	/** @type {{ href: string, key: import('#lib/i18n.js').MessageKey }[]} */
	const baseNav = [
		{ href: '/', key: 'nav.projects' },
		{ href: '/my-work', key: 'nav.myWork' },
		{ href: '/findings', key: 'nav.findings' },
		{ href: '/fix-plan', key: 'nav.fixPlan' },
		{ href: '/remediation', key: 'nav.remediation' },
		{ href: '/root-causes', key: 'nav.rootCauses' },
		{ href: '/approvals', key: 'nav.approvals' },
		{ href: '/components', key: 'nav.components' },
		{ href: '/licenses', key: 'nav.licenses' },
		{ href: '/policies', key: 'nav.policies' },
		{ href: '/advisories', key: 'nav.advisories' },
		{ href: '/notifications', key: 'nav.notifications' },
		{ href: '/sla', key: 'nav.sla' },
		{ href: '/cra', key: 'nav.cra' },
		{ href: '/tokens', key: 'nav.apiKeys' },
		{ href: '/docs', key: 'nav.apiDocs' }
	];
	// Instance admins get the triage-rule policy, user management and SSO pages:
	// flat in the mobile menu, grouped under one "Admin" menu on wider screens
	// so the bar fits.
	/** @type {{ href: string, key: import('#lib/i18n.js').MessageKey }[]} */
	const adminNav = [
		{ href: '/triage-rules', key: 'nav.triageRules' },
		{ href: '/custom-fields', key: 'nav.customFields' },
		{ href: '/psirt', key: 'nav.psirt' },
		{ href: '/feed-rules', key: 'nav.feedRules' },
		{ href: '/finding-templates', key: 'nav.findingTemplates' },
		{ href: '/report-templates', key: 'nav.reportTemplates' },
		{ href: '/users', key: 'nav.users' },
		{ href: '/service-accounts', key: 'nav.serviceAccounts' },
		{ href: '/audit-log', key: 'nav.auditLog' },
		{ href: '/permissions', key: 'nav.permissions' },
		{ href: '/sso', key: 'nav.sso' },
		{ href: '/features', key: 'nav.features' }
	];
	/** @param {{ href: string }} i */
	const shown = (i) => !pageFeature[i.href] || isOn($features, pageFeature[i.href]);
	let navItems = $derived(($me?.is_admin ? [...baseNav, ...adminNav] : baseNav).filter(shown));
	let onAdminPage = $derived(adminNav.some((i) => page.url.pathname === i.href));
</script>

<div class="min-h-screen bg-base-200">
	{#if $token}
		<div class="navbar bg-base-100/90 backdrop-blur shadow-sm sticky top-0 z-30">
			<!-- min-w-0 lets the nav strip shrink instead of pushing search /
			     theme / sign-out off-screen on narrow windows. -->
			<div class="flex-1 items-center min-w-0">
				<!-- Mobile menu -->
				<div class="dropdown sm:hidden">
					<button tabindex="0" class="btn btn-ghost btn-circle btn-sm" aria-label={ts('nav.menu')}>
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" /></svg>
					</button>
					<ul class="dropdown-content menu menu-sm mt-2 w-52 rounded-box bg-base-100 p-2 shadow-lg z-40">
						{#each navItems as item}
							<li><a href={item.href} class:active={page.url.pathname === item.href} onclick={(e) => e.currentTarget.blur()}>{ts(item.key)}</a></li>
						{/each}
						<li><a href="/account" class:active={page.url.pathname === '/account'} onclick={(e) => e.currentTarget.blur()}>{ts('nav.account')}</a></li>
					</ul>
				</div>
				<a href="/" class="btn btn-ghost text-xl gap-2">
					<span class="text-primary">◈</span> Xila
				</a>
				<nav class="hidden sm:flex ml-1 gap-0.5 min-w-0 flex-wrap">
					{#each baseNav.filter(shown) as item}
						<a
							href={item.href}
							class="btn btn-ghost btn-sm font-normal"
							class:btn-active={page.url.pathname === item.href}>{ts(item.key)}</a
						>
					{/each}
					{#if $me?.is_admin}
						<div class="dropdown">
							<button tabindex="0" class="btn btn-ghost btn-sm font-normal" class:btn-active={onAdminPage}>{ts('nav.admin')} ▾</button>
							<ul class="dropdown-content menu menu-sm mt-1 w-44 rounded-box bg-base-100 p-2 shadow-lg z-40">
								{#each adminNav.filter(shown) as item}
									<li><a href={item.href} class:active={page.url.pathname === item.href} onclick={(e) => e.currentTarget.blur()}>{ts(item.key)}</a></li>
								{/each}
							</ul>
						</div>
					{/if}
				</nav>
			</div>
			<div class="flex-none gap-1 items-center">
				<a href="/account" class="btn btn-ghost btn-circle btn-sm xl:hidden" aria-label={ts('nav.account')} title={ts('nav.account')}>⚙</a>
				<button class="btn btn-ghost btn-sm hidden gap-2 sm:inline-flex text-base-content/60" onclick={openCommand} aria-label={ts('nav.search')}>
					<span>⌕</span><span class="hidden md:inline">{ts('nav.search')}</span>
					<kbd class="kbd kbd-xs hidden md:inline">⌘K</kbd>
				</button>
				<button class="btn btn-ghost btn-circle btn-sm sm:hidden" onclick={openCommand} aria-label={ts('nav.search')}>⌕</button>
				{#if $me}
					<a href="/account" class="btn btn-ghost btn-sm font-normal hidden xl:inline-flex text-xs text-base-content/60" title={ts('nav.accountTitle')}>
						{$me.email}
						{#if $me.is_admin}<span class="badge badge-primary badge-xs ml-1">{ts('nav.adminBadge')}</span>{/if}
					</a>
				{/if}
				<select class="select select-ghost select-xs w-auto" bind:value={$locale} aria-label={ts('nav.language')} title={ts('nav.language')}>
					{#each LOCALES as l (l.id)}<option value={l.id}>{l.id.toUpperCase()}</option>{/each}
				</select>
				<button class="btn btn-ghost btn-circle btn-sm" onclick={toggleTheme} aria-label={ts('nav.toggleTheme')}>
					{theme === 'winter' ? '🌙' : '☀️'}
				</button>
				<button class="btn btn-ghost btn-sm" onclick={logout}>{ts('nav.signOut')}</button>
			</div>
		</div>
		<CommandPalette />
	{/if}

	<main class="mx-auto max-w-6xl px-4 py-6">
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
	<footer class="mx-auto max-w-6xl px-4 pb-6 text-xs text-base-content/50">
		Xila · <a class="link link-hover" href="https://www.gnu.org/licenses/agpl-3.0.html" rel="license noopener" target="_blank">AGPL-3.0</a>
		· <a class="link link-hover" href={sourceURL} rel="noopener" target="_blank">{ts('nav.sourceCode')}</a>
	</footer>
</div>

{#if $toast}
	<div class="toast toast-end z-50">
		<div class="alert alert-{$toast.type} shadow-lg">
			<span>{$toast.text}</span>
		</div>
	</div>
{/if}
