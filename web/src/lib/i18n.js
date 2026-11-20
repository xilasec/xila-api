// A small i18n layer: message catalogues per locale, a persisted `locale`
// preference, and a `t` store whose value translates a key.
//
//   $t('nav.projects')
//   $t('findings.count', { count: 3 })   // "3 findings" — "one|other" plurals
//
// Catalogues live in ./i18n/<locale>.js. English is the source of truth: its
// keys are the MessageKey type, and every other catalogue is typed against
// it, so a missing or extra key is a svelte-check error (and
// scripts/check-i18n.mjs also compares the {param} placeholders).
//
// Only some pages are translated (TRANSLATED_ROUTES); the rest render in
// English whatever the preference, so no page is ever half-translated. The
// layout sets `contentLocale` from the route and the preference.
import { writable, derived } from 'svelte/store';
import en from './i18n/en.js';
import de from './i18n/de.js';

/** @typedef {keyof typeof en} MessageKey */
/** @typedef {Record<string, string | number>} MessageParams */
/** @typedef {(key: MessageKey, params?: MessageParams) => string} Translate */

/** @type {Record<string, Record<string, string>>} */
const CATALOGUES = { en, de };

export const LOCALES = [
	{ id: 'en', label: 'English' },
	{ id: 'de', label: 'Deutsch' }
];

// Routes (SvelteKit route ids) whose UI — the page and every component it
// renders — is extracted into the catalogues. Any other page renders wholly in
// English, so no page is ever half-translated: add a route here only once all
// of it is translated.
export const TRANSLATED_ROUTES = new Set([
	'/',
	'/features',
	'/login',
	'/reset-password',
	'/account',
	'/findings',
	'/findings/[id]',
	'/notifications',
	'/users',
	'/service-accounts',
	'/sso',
	'/triage-rules',
	'/vuln-policies',
	'/custom-fields',
	'/custom-parsers',
	'/feed-rules',
	'/psirt',
	'/finding-templates',
	'/report-templates',
	'/docs',
	'/advisories',
	'/advisories/[id]',
	'/approvals',
	'/my-work',
	'/inbox',
	'/groups',
	'/components',
	'/cra',
	'/exceptions',
	'/licenses',
	'/policies',
	'/sla',
	'/tokens',
	'/permissions',
	'/audit-log',
	'/projects/[id]',
	'/fix-plan',
	'/remediation',
	'/root-causes',
	'/vulnerabilities/[id]',
	'/sboms/[id]'
]);

const STORAGE_KEY = 'xila_locale';

/** @param {string | null | undefined} tag a BCP 47 tag such as "de-AT" */
export function supported(tag) {
	const base = (tag ?? '').toLowerCase().split('-')[0];
	return base in CATALOGUES ? base : '';
}

function initialLocale() {
	if (typeof window === 'undefined') return 'en';
	return supported(localStorage.getItem(STORAGE_KEY)) || supported(navigator.language) || 'en';
}

/** The user's preferred locale, persisted to localStorage. */
export const locale = writable(initialLocale());
locale.subscribe((l) => {
	if (typeof window !== 'undefined') localStorage.setItem(STORAGE_KEY, l);
});

/** The locale the current page renders in (English on untranslated pages). */
export const contentLocale = writable('en');

let active = 'en';
contentLocale.subscribe((l) => (active = l));

/** The current content locale, for non-reactive formatting helpers. */
export const activeLocale = () => active;

/** @param {string | null | undefined} routeId */
export const routeLocale = (routeId, preferred = 'en') =>
	routeId && TRANSLATED_ROUTES.has(routeId) ? preferred : 'en';

/**
 * Translate `key` in locale `loc`. `{name}` placeholders take `params`; a
 * message "singular|plural" picks its form from the `count` param.
 * @param {string} loc
 * @param {MessageKey} key
 * @param {MessageParams} [params]
 */
export function translate(loc, key, params) {
	let msg = CATALOGUES[loc]?.[key] ?? en[key] ?? key;
	if (params && typeof params.count === 'number' && msg.includes('|')) {
		const [one, other] = msg.split('|');
		msg = new Intl.PluralRules(loc).select(params.count) === 'one' ? one : other;
	}
	if (!params) return msg;
	return msg.replace(/\{(\w+)\}/g, (m, name) => {
		const v = params[name];
		if (v === undefined) return m;
		return typeof v === 'number' ? fmtNum(loc, v) : v;
	});
}

/** @param {string} loc @param {number} n */
const fmtNum = (loc, n) => new Intl.NumberFormat(loc).format(n);

/** Reactive translator for the current page: `$t('key', params)`. */
export const t = derived(contentLocale, (loc) => /** @type {Translate} */ ((key, params) => translate(loc, key, params)));

/**
 * Translated label of an enum value (severity, status, category…), falling
 * back to the value with underscores spaced out when it has no message.
 * @param {string} loc
 * @param {string} group e.g. "severity"
 * @param {string | null | undefined} value
 */
export function enumLabel(loc, group, value) {
	if (!value) return '';
	const key = `enum.${group}.${value}`;
	const msg = CATALOGUES[loc]?.[key] ?? en[/** @type {MessageKey} */ (key)];
	return msg ?? value.replaceAll('_', ' ');
}

/** Reactive enum labels: `$labelOf('status', f.status)`. */
export const labelOf = derived(contentLocale, (loc) => (/** @type {string} */ group, /** @type {string | null | undefined} */ value) => enumLabel(loc, group, value));
