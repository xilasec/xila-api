import { idleSignedOut } from '#lib/session.js';
import { writable } from 'svelte/store';
import { api, ApiError, getToken, setToken } from './api.js';

// After an SSO login the server redirects to `/#sso_token=<jwt>`; capture it into
// storage before anything reads the token, then scrub it from the URL.
function captureSSOToken() {
	if (typeof window === 'undefined') return;
	const m = window.location.hash.match(/(?:^|#|&)sso_token=([^&]+)/);
	if (!m) return;
	setToken(decodeURIComponent(m[1]));
	history.replaceState(null, '', window.location.pathname + window.location.search);
}
captureSSOToken();

/** Auth token, persisted to localStorage. */
export const token = writable(getToken());
token.subscribe((v) => {
	setToken(v);
	if (v) idleSignedOut.set(false); // a new sign-in clears the inactivity notice
});

/**
 * @typedef {object} User
 * @property {string} id
 * @property {string} email
 * @property {boolean} is_admin
 * @property {boolean} is_owner
 * @property {string} admin_source
 * @property {boolean} has_password
 * @property {string | null} disabled_at
 * @property {string | null} password_changed_at
 * @property {boolean} mfa_enabled
 * @property {string} created_at
 */

/** The authenticated user, or null. */
export const me = writable(/** @type {User | null} */ (null));

/** Fetch /me into the store; clears it on failure. A 401 means the session
 * was revoked (password change, sign-out everywhere, deactivation): drop the
 * token so the layout sends the user to the login page. */
export async function loadMe() {
	try {
		me.set(await api.me());
	} catch (err) {
		me.set(null);
		if (err instanceof ApiError && err.status === 401) token.set(null);
	}
}

/**
 * Runtime feature switches (GET /features): key → on. A feature the map
 * doesn't know about counts as on, so nothing disappears while it loads or
 * on a server that predates a switch.
 * @type {import('svelte/store').Writable<Record<string, boolean>>}
 */
export const features = writable({});

/** Fetch the switches into the store; on failure keep what it had. */
export async function loadFeatures() {
	try {
		/** @type {{ features: { key: string, enabled: boolean }[] }} */
		const res = await api.features();
		features.set(Object.fromEntries(res.features.map((f) => [f.key, f.enabled])));
	} catch {
		// keep the last known switches
	}
}

/** Whether feature `key` is on in `map` (unknown = on).
 * @param {Record<string, boolean>} map @param {string} key */
export const isOn = (map, key) => map[key] !== false;

/** Transient toast/alert message: { type, text } | null */
export const toast = writable(/** @type {{ type: string, text: string } | null} */ (null));

/** @type {ReturnType<typeof setTimeout> | undefined} */
let toastTimer;
/** @param {string} text @param {string} [type] */
export function notify(text, type = 'error') {
	toast.set({ text, type });
	clearTimeout(toastTimer);
	toastTimer = setTimeout(() => toast.set(null), 4000);
}
