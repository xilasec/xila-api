// Presentation helpers: badge colors and date/number formatting. Dates and
// numbers follow the page's locale (#lib/i18n.js); the layout remounts the
// page when it changes, so these plain functions need not be reactive.
import { activeLocale } from './i18n.js';

/** @type {Record<string, string>} */
const SEVERITY = {
	critical: 'badge-error',
	high: 'badge-warning',
	medium: 'badge-info',
	low: 'badge-ghost',
	info: 'badge-ghost'
};

/** @type {Record<string, string>} */
const STATUS = {
	open: 'badge-error',
	confirmed: 'badge-warning',
	remediated: 'badge-success',
	false_positive: 'badge-ghost',
	risk_accepted: 'badge-info',
	wont_fix: 'badge-neutral'
};

/** @type {Record<string, string>} */
const CRITICALITY = {
	critical: 'badge-error',
	high: 'badge-warning',
	medium: 'badge-info',
	low: 'badge-ghost'
};

// Left-edge accent color for a table row, by severity.
/** @type {Record<string, string>} */
const SEVERITY_ACCENT = {
	critical: 'border-error',
	high: 'border-warning',
	medium: 'border-info',
	low: 'border-base-300',
	info: 'border-base-300'
};
export const severityAccent = (/** @type {string} */ s) => SEVERITY_ACCENT[s] ?? 'border-base-300';

export const severityClass = (/** @type {string} */ s) => SEVERITY[s] ?? 'badge-ghost';
export const statusClass = (/** @type {string} */ s) => STATUS[s] ?? 'badge-ghost';
export const criticalityClass = (/** @type {string} */ s) => CRITICALITY[s] ?? 'badge-ghost';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const STATUSES = [
	'open',
	'confirmed',
	'false_positive',
	'risk_accepted',
	'remediated',
	'wont_fix'
];
export const CATEGORIES = [
	'sast',
	'dast',
	'sca',
	'secret',
	'container',
	'iac',
	'license',
	'cloud',
	'kubernetes'
];

// SLA states a finding can be filtered by (mirrors domain.SLAStatus); their
// labels are the enum.sla.* messages.
export const SLA_STATUSES = ['breached', 'due_soon', 'on_track', 'paused', 'met', 'missed', 'none'];

export const prettyStatus = (/** @type {string | null | undefined} */ s) => (s ? s.replaceAll('_', ' ') : '');

/** @param {string | number | Date | null | undefined} iso */
export function fmtDate(iso) {
	if (!iso) return '—';
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return '—';
	return d.toLocaleString(activeLocale(), {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit'
	});
}

/** A timestamp's date in the page locale ("15 Dec 2026" / "15.12.2026").
 * @param {string | number | Date | null | undefined} iso */
export function fmtDateOnly(iso) {
	if (!iso) return '—';
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString(activeLocale());
}

/** A number in the page locale ("12,345" / "12.345").
 * @param {number | null | undefined} n @param {Intl.NumberFormatOptions} [opts] */
export function fmtNumber(n, opts) {
	return n == null ? '—' : new Intl.NumberFormat(activeLocale(), opts).format(n);
}

/**
 * A calendar date ("2026-12-15" or a timestamp of one): the day itself, never
 * shifted by the viewer's timezone.
 * @param {string | null | undefined} d
 */
export function fmtDay(d) {
	if (!d) return '';
	const day = String(d).slice(0, 10);
	const t = new Date(day + 'T00:00:00Z');
	return isNaN(t.getTime()) ? day : t.toLocaleDateString(activeLocale(), { dateStyle: 'medium', timeZone: 'UTC' });
}

// slugify turns a display name into a URL-friendly slug.
/** @param {string | null | undefined} name */
export function slugify(name) {
	return (name || '')
		.toLowerCase()
		.trim()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '');
}

/** @param {number} score */
export function riskTone(score) {
	if (score >= 100) return 'text-error';
	if (score >= 40) return 'text-warning';
	if (score > 0) return 'text-info';
	return 'text-success';
}

/** @type {Record<string, string>} */
const KEV_CATALOG_NAMES = { cisa: 'CISA KEV', enisa: 'ENISA EUVD', vulncheck: 'VulnCheck KEV' };

/**
 * Names the KEV catalogs asserting a finding (its kev_sources), for tooltips;
 * empty when the finding doesn't say which.
 * @param {string[] | null | undefined} sources
 */
export function kevCatalogs(sources) {
	return sources?.length ? sources.map((s) => KEV_CATALOG_NAMES[s] ?? s).join(', ') : '';
}
