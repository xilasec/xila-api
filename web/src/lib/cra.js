// EU CRA Article 14 reporting: labels and timers shared by the project's
// Compliance tab and the /cra case list. Label text follows the page's
// content locale (#lib/i18n.js) through plain functions (not reactive
// stores): the layout remounts the page when the locale changes, same as
// #lib/format.js.
import { translate, activeLocale } from './i18n.js';

/** @param {string} stage */
export const stageLabel = (stage) => translate(activeLocale(), /** @type {any} */ (`cra.stage.${stage}`));

/** @type {Record<string, import('./i18n.js').MessageKey>} */
const STATE_KEY = {
	active: 'cra.state.active',
	open: 'cra.state.open',
	early_warning_sent: 'cra.state.early_warning_sent',
	notification_sent: 'cra.state.notification_sent',
	final_report_sent: 'cra.state.final_report_sent',
	closed: 'cra.state.closed',
	dismissed: 'cra.state.dismissed'
};
export const stateLabel = (/** @type {string} */ s) => (STATE_KEY[s] ? translate(activeLocale(), STATE_KEY[s]) : s);

/** @type {Record<string, string>} */
const STATE_CLASS = { open: 'badge-error', closed: 'badge-success', dismissed: 'badge-ghost' };
export const stateClass = (/** @type {string} */ s) => STATE_CLASS[s] ?? 'badge-warning';

/** @type {Record<string, import('./i18n.js').MessageKey>} */
const DEADLINE_KEY = {
	met: 'cra.deadline.met',
	late: 'cra.deadline.late',
	missed: 'cra.deadline.missed',
	due_soon: 'cra.deadline.due_soon',
	pending: 'cra.deadline.pending',
	not_started: 'cra.deadline.not_started',
	waived: 'cra.deadline.waived'
};
export const deadlineLabel = (/** @type {string} */ s) => (DEADLINE_KEY[s] ? translate(activeLocale(), DEADLINE_KEY[s]) : s.replaceAll('_', ' '));

/** @type {Record<string, string>} */
const DEADLINE_CLASS = {
	met: 'badge-success',
	late: 'badge-error',
	missed: 'badge-error',
	due_soon: 'badge-warning',
	pending: 'badge-info',
	not_started: 'badge-ghost',
	waived: 'badge-ghost'
};
export const deadlineClass = (/** @type {string} */ s) => DEADLINE_CLASS[s] ?? 'badge-ghost';

export const CRA_STATES = ['active', 'open', 'early_warning_sent', 'notification_sent', 'final_report_sent', 'closed', 'dismissed'];

/**
 * "in 5 h 12 m" / "overdue by 2 d 3 h" for a deadline, at now (ms).
 * @param {string | null | undefined} iso
 * @param {number} now
 */
export function countdown(iso, now) {
	if (!iso) return '';
	const loc = activeLocale();
	const ms = new Date(iso).getTime() - now;
	const abs = Math.abs(ms);
	const d = Math.floor(abs / 86_400_000);
	const h = Math.floor((abs % 86_400_000) / 3_600_000);
	const m = Math.floor((abs % 3_600_000) / 60_000);
	const span =
		d > 0
			? translate(loc, 'cra.countdown.dh', { d, h })
			: h > 0
				? translate(loc, 'cra.countdown.hm', { h, m })
				: translate(loc, 'cra.countdown.m', { m });
	return translate(loc, ms >= 0 ? 'cra.countdown.in' : 'cra.countdown.overdue', { span });
}

/** The deadline the case is working towards next, if any. @param {any} c */
export function nextDeadline(c) {
	return (c.deadlines ?? []).find((/** @type {any} */ d) => d.stage === c.next_stage) ?? null;
}
