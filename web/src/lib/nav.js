// The app's navigation, in one place: the sidebar, the Settings hub and the
// command palette all read it, so a new page is added here once.
//
// Main sections are the daily work and show in the sidebar. Settings groups
// are configuration: they live on the Settings hub (/settings), one click
// from the sidebar, and every page in them shows a "Settings" breadcrumb.

/** @typedef {import('#lib/i18n.js').MessageKey} MessageKey */
/**
 * @typedef {object} NavItem
 * @property {string} href
 * @property {MessageKey} key
 * @property {string} [icon]      sidebar icon name (Icon.svelte)
 * @property {MessageKey} [desc]  one line on the Settings hub
 * @property {string} [feature]   hidden while this switchable feature is off
 * @property {boolean} [admin]    instance admins only
 */
/** @typedef {{ key?: MessageKey, items: NavItem[] }} NavSection */

/** @type {NavSection[]} */
export const MAIN_NAV = [
	{
		items: [
			{ href: '/', key: 'nav.projects', icon: 'home' },
			{ href: '/my-work', key: 'nav.myWork', icon: 'inbox' },
			{ href: '/inbox', key: 'nav.inbox', icon: 'bell' }
		]
	},
	{
		key: 'nav.group.triage',
		items: [
			{ href: '/findings', key: 'nav.findings', icon: 'list' },
			{ href: '/approvals', key: 'nav.approvals', icon: 'check' },
			{ href: '/exceptions', key: 'nav.exceptions', icon: 'hourglass' }
		]
	},
	{
		key: 'nav.group.fix',
		items: [
			{ href: '/fix-plan', key: 'nav.fixPlan', icon: 'wrench' },
			{ href: '/remediation', key: 'nav.remediation', icon: 'clipboard', feature: 'remediation' },
			{ href: '/root-causes', key: 'nav.rootCauses', icon: 'branch', feature: 'remediation' }
		]
	},
	{
		key: 'nav.group.supplyChain',
		items: [
			{ href: '/components', key: 'nav.components', icon: 'package' },
			{ href: '/licenses', key: 'nav.licenses', icon: 'scale' },
			{ href: '/policies', key: 'nav.policies', icon: 'shield' },
			{ href: '/advisories', key: 'nav.advisories', icon: 'book' }
		]
	},
	{
		key: 'nav.group.compliance',
		items: [
			{ href: '/sla', key: 'nav.sla', icon: 'clock' },
			{ href: '/cra', key: 'nav.cra', icon: 'flag', feature: 'cra' },
			{ href: '/vex-documents', key: 'nav.vexDocuments', icon: 'doc' }
		]
	}
];

/** @type {NavSection[]} */
export const SETTINGS_NAV = [
	{
		key: 'nav.group.personal',
		items: [
			{ href: '/account', key: 'nav.account', desc: 'settings.desc.account' },
			{ href: '/tokens', key: 'nav.apiKeys', desc: 'settings.desc.apiKeys' },
			{ href: '/report-schedules', key: 'nav.reportSchedules', desc: 'settings.desc.reportSchedules' },
			{ href: '/docs', key: 'nav.apiDocs', desc: 'settings.desc.apiDocs' }
		]
	},
	{
		key: 'nav.group.automation',
		items: [
			{ href: '/triage-rules', key: 'nav.triageRules', desc: 'settings.desc.triageRules', admin: true },
			{ href: '/vuln-policies', key: 'nav.vulnPolicies', desc: 'settings.desc.vulnPolicies', admin: true },
			{ href: '/custom-fields', key: 'nav.customFields', desc: 'settings.desc.customFields', admin: true, feature: 'custom_fields' },
			{ href: '/custom-parsers', key: 'nav.customParsers', desc: 'settings.desc.customParsers', admin: true },
			{ href: '/feed-rules', key: 'nav.feedRules', desc: 'settings.desc.feedRules', admin: true },
			{ href: '/internal-components', key: 'nav.internalComponents', desc: 'settings.desc.internalComponents', admin: true },
			{ href: '/finding-templates', key: 'nav.findingTemplates', desc: 'settings.desc.findingTemplates', admin: true },
			{ href: '/report-templates', key: 'nav.reportTemplates', desc: 'settings.desc.reportTemplates', admin: true }
		]
	},
	{
		key: 'nav.group.access',
		items: [
			{ href: '/users', key: 'nav.users', desc: 'settings.desc.users', admin: true },
			{ href: '/groups', key: 'nav.groups', desc: 'settings.desc.groups', admin: true },
			{ href: '/service-accounts', key: 'nav.serviceAccounts', desc: 'settings.desc.serviceAccounts', admin: true },
			{ href: '/sso', key: 'nav.sso', desc: 'settings.desc.sso', admin: true },
			{ href: '/permissions', key: 'nav.permissions', desc: 'settings.desc.permissions', admin: true }
		]
	},
	{
		key: 'nav.group.platform',
		items: [
			{ href: '/notifications', key: 'nav.notifications', desc: 'settings.desc.notifications', admin: true },
			{ href: '/features', key: 'nav.features', desc: 'settings.desc.features', admin: true },
			{ href: '/psirt', key: 'nav.psirt', desc: 'settings.desc.psirt', admin: true, feature: 'psirt' },
			{ href: '/audit-log', key: 'nav.auditLog', desc: 'settings.desc.auditLog', admin: true }
		]
	}
];

/**
 * Sections with only the items this user may see.
 * @param {NavSection[]} sections
 * @param {{ admin: boolean, on: (feature: string) => boolean }} who
 * @returns {NavSection[]}
 */
export function visible(sections, who) {
	return sections
		.map((s) => ({ ...s, items: s.items.filter((i) => (!i.admin || who.admin) && (!i.feature || who.on(i.feature))) }))
		.filter((s) => s.items.length > 0);
}

/** Every navigable page, flat. */
export const ALL_ITEMS = [...MAIN_NAV, ...SETTINGS_NAV].flatMap((s) => s.items);

/** The feature a page belongs to, if it is switchable. */
/** @type {Record<string, string>} */
export const PAGE_FEATURE = Object.fromEntries(ALL_ITEMS.filter((i) => i.feature).map((i) => [i.href, /** @type {string} */ (i.feature)]));

/**
 * The settings item for a path (also for its sub-pages), for the breadcrumb.
 * @param {string} path
 */
export function settingsItemFor(path) {
	return SETTINGS_NAV.flatMap((s) => s.items).find((i) => path === i.href || path.startsWith(i.href + '/'));
}

/**
 * Whether a sidebar item is the current page (a section's sub-pages count:
 * a finding's page highlights Findings).
 * @param {string} href
 * @param {string} path
 */
export function isCurrent(href, path) {
	if (href === '/') return path === '/' || path.startsWith('/projects/') || path.startsWith('/sboms/');
	return path === href || path.startsWith(href + '/');
}
