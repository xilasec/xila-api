// Browser-session idle tracking (M13 13.16). The server sends the idle
// timeout on every response to a tracked session (X-Session-Idle-Timeout);
// the last activity is kept in localStorage so every tab counts the same.
// No imports from api.js or stores.js: both import this.
import { writable } from 'svelte/store';

const KEY = 'xila.lastActivity';

/** The session's idle timeout in seconds; 0 = not tracked (no warning). */
export const idleTimeout = writable(0);

/** Set when the session ended for inactivity, until the next sign-in. */
export const idleSignedOut = writable(false);

/**
 * A tracked request succeeded; unless it was background polling, the idle
 * clock restarted.
 * @param {number} seconds @param {boolean} active
 */
export function noteActivity(seconds, active) {
	idleTimeout.set(seconds);
	if (!active) return;
	try {
		localStorage.setItem(KEY, String(Date.now()));
	} catch {
		// storage unavailable: the warning then counts from this tab only
	}
}

/** When any tab last made a tracked request (ms), 0 when unknown. */
export function lastActivity() {
	try {
		return Number(localStorage.getItem(KEY)) || 0;
	} catch {
		return 0;
	}
}
