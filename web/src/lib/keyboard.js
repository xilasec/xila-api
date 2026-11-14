// Keyboard-driven triage for the findings tables (portfolio + project tab).
// Pages own their data; this module owns the keymap, the "should a shortcut
// fire at all" rule and the row cursor, so both tables behave the same.

/**
 * @typedef {object} ListCursor
 * @property {number} index  the highlighted row, -1 = none
 * @property {number} anchor the last row toggled with `x`, -1 = none (start of a Shift+X range)
 * @property {(delta: number, length: number) => number} move  move by delta, clamped to [0, length)
 * @property {(i: number) => void} mark  record the anchor for a later range
 * @property {() => [number, number]} range  the inclusive [lo, hi] from the anchor (or cursor) to the cursor
 * @property {() => void} reset
 */

/**
 * @typedef {object} ListKeyHandlers
 * @property {(delta: number) => void} move     j/k, ↓/↑
 * @property {(range: boolean) => void} toggle  x (range = Shift+X)
 * @property {() => void} open                  Enter / o
 * @property {(status: string) => void} triage  c f a w r
 * @property {() => void} assignMe              m
 * @property {() => void} editStatus            s
 * @property {() => void} escape                Esc
 * @property {() => void} [focusSearch]         / (only where the page has a search box)
 */

/** Status each triage key sets. */
export const TRIAGE_KEYS = /** @type {Record<string, string>} */ ({
	c: 'confirmed',
	f: 'false_positive',
	a: 'risk_accepted',
	w: 'wont_fix',
	r: 'open'
});

/** Statuses that record an exception: they need a reason (and may expire). */
export const EXCEPTION_STATUSES = ['false_positive', 'risk_accepted', 'wont_fix'];
/** @param {string} status */
export const isExceptionStatus = (status) => EXCEPTION_STATUSES.includes(status);

/**
 * The keymap shown by KeyboardHelp; `search` rows only where a search box exists.
 * @type {{ keys: string[], label: import('./i18n.js').MessageKey, search?: boolean }[]}
 */
export const SHORTCUTS = [
	{ keys: ['j', '↓'], label: 'keys.next' },
	{ keys: ['k', '↑'], label: 'keys.prev' },
	{ keys: ['x'], label: 'keys.select' },
	{ keys: ['Shift', 'x'], label: 'keys.range' },
	{ keys: ['Enter', 'o'], label: 'keys.open' },
	{ keys: ['c'], label: 'keys.confirm' },
	{ keys: ['f'], label: 'keys.fp' },
	{ keys: ['a'], label: 'keys.accept' },
	{ keys: ['w'], label: 'keys.wont' },
	{ keys: ['r'], label: 'keys.reopen' },
	{ keys: ['m'], label: 'keys.assign' },
	{ keys: ['s'], label: 'keys.status' },
	{ keys: ['/'], label: 'keys.search', search: true },
	{ keys: ['?'], label: 'keys.help' },
	{ keys: ['Esc'], label: 'keys.esc' }
];

const NON_TEXT_INPUTS = new Set(['checkbox', 'radio', 'button', 'submit', 'reset', 'range', 'color', 'file', 'image']);

/**
 * True when a page shortcut must not fire: the user is typing, a dialog is
 * open, or a browser/OS modifier is held.
 * @param {KeyboardEvent} e
 */
export function ignoreKey(e) {
	if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.isComposing) return true;
	const t = e.target instanceof HTMLElement ? e.target : null;
	if (t && (t.isContentEditable || t.closest('textarea, select, [contenteditable=""], [contenteditable="true"]'))) return true;
	// A focused checkbox (e.g. a row just clicked) must not swallow the keymap.
	if (t instanceof HTMLInputElement && !NON_TEXT_INPUTS.has(t.type)) return true;
	return typeof document !== 'undefined' && document.querySelector('dialog[open]') !== null;
}

/**
 * A row cursor plus the range anchor. Plain object: wrap it in `$state(…)`
 * and its methods mutate the reactive proxy.
 * @returns {ListCursor}
 */
export function createListCursor() {
	return {
		index: -1,
		anchor: -1,
		move(delta, length) {
			if (length <= 0) return (this.index = -1);
			const from = this.index < 0 ? (delta > 0 ? -1 : length) : Math.min(this.index, length);
			return (this.index = Math.max(0, Math.min(length - 1, from + delta)));
		},
		mark(i) {
			this.anchor = i;
		},
		range() {
			const from = this.anchor < 0 ? this.index : this.anchor;
			return [Math.min(from, this.index), Math.max(from, this.index)];
		},
		reset() {
			this.index = -1;
			this.anchor = -1;
		}
	};
}

/**
 * After a dialog closes, drop focus left on one of its controls, so Enter
 * reaches the table again instead of a hidden button.
 * @param {HTMLDialogElement} dialog
 */
export function releaseFocus(dialog) {
	const active = document.activeElement;
	if (active instanceof HTMLElement && dialog.contains(active)) active.blur();
}

/** Bring the highlighted row (`aria-selected="true"`) into view. */
export function scrollCursorIntoView() {
	document.querySelector('tr[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
}

/**
 * Dispatch one keydown to the table's handlers. Returns whether it was handled
 * (and then prevents the browser default, e.g. Firefox's `/` quick find).
 * @param {KeyboardEvent} e
 * @param {ListKeyHandlers} h
 */
export function handleListKey(e, h) {
	if (ignoreKey(e)) return false;
	const key = e.key;
	// Enter on a focused button or link is that control's own activation.
	if (key === 'Enter' && e.target instanceof Element && e.target.closest('button, a, [role="button"]')) return false;
	if (key === 'j' || key === 'ArrowDown') h.move(1);
	else if (key === 'k' || key === 'ArrowUp') h.move(-1);
	else if (key === 'x' || key === 'X') h.toggle(e.shiftKey);
	else if (key === 'Enter' || key === 'o') h.open();
	else if (key in TRIAGE_KEYS && !e.shiftKey) h.triage(TRIAGE_KEYS[key]);
	else if (key === 'm') h.assignMe();
	else if (key === 's') h.editStatus();
	else if (key === '/' && h.focusSearch) h.focusSearch();
	else if (key === 'Escape') h.escape();
	else return false;
	e.preventDefault();
	return true;
}
