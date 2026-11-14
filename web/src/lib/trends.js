// Series definitions and window rollups for the metric trend charts. Series
// labels are i18n message keys; values format in the page locale.
import { fmtNumber } from './format.js';

/** @typedef {{ label: import('./i18n.js').MessageKey, color: string, value: (p: any) => number }} Series */

// Stacked bottom-up: the most severe band sits on top.
/** @type {Series[]} */
export const OPEN_BY_SEVERITY = [
	{ label: 'trend.low', color: 'var(--color-neutral)', value: (/** @type {any} */ p) => p.open_by_severity?.low ?? 0 },
	{ label: 'trend.medium', color: 'var(--color-info)', value: (/** @type {any} */ p) => p.open_by_severity?.medium ?? 0 },
	{ label: 'trend.high', color: 'var(--color-warning)', value: (/** @type {any} */ p) => p.open_by_severity?.high ?? 0 },
	{ label: 'trend.critical', color: 'var(--color-error)', value: (/** @type {any} */ p) => p.open_by_severity?.critical ?? 0 }
];

/** @type {Series[]} */
export const RISK = [{ label: 'trend.risk', color: 'var(--color-primary)', value: (/** @type {any} */ p) => p.risk_score }];

/** @type {Series[]} */
export const FLOW = [
	{ label: 'trend.new', color: 'var(--color-error)', value: (/** @type {any} */ p) => p.new },
	{ label: 'trend.closed', color: 'var(--color-success)', value: (/** @type {any} */ p) => p.closed }
];

export const fmtCount = (/** @type {number} */ v) => fmtNumber(Math.round(v));
export const fmtRisk = (/** @type {number} */ v) => fmtNumber(Math.abs(v) >= 100 ? Math.round(v) : Math.round(v * 10) / 10);

// Window totals: MTTR and SLA compliance re-derived from the daily inputs
// (weighted by each day's fixes — averaging daily averages would not be).
/** @param {any[]} points metric snapshot points from the trends API */
export function windowStats(points) {
	let closed = 0;
	let days = 0;
	let met = 0;
	let missed = 0;
	let opened = 0;
	for (const p of points) {
		opened += p.new;
		closed += p.closed;
		if (p.mttr_days != null) days += p.mttr_days * p.closed;
		met += p.sla_met;
		missed += p.sla_missed;
	}
	return {
		opened,
		closed,
		mttr: closed ? Math.round((days / closed) * 10) / 10 : null,
		compliance: met + missed ? Math.round((met / (met + missed)) * 100) : null
	};
}
