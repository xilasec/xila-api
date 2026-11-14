// Notification channel types: the `url` field is a webhook URL for every type
// except email, where it holds a comma-separated recipient list. Labels are
// i18n message keys ($lib/i18n.js).
/** @typedef {import('./i18n.js').MessageKey} MessageKey */
/** @typedef {import('./i18n.js').Translate} Translate */

/** @type {{ id: string, label: string, long: MessageKey }[]} */
export const CHANNEL_TYPES = [
	{ id: 'slack', label: 'Slack', long: 'channel.slackLong' },
	{ id: 'teams', label: 'Teams', long: 'channel.teamsLong' },
	{ id: 'mattermost', label: 'Mattermost', long: 'channel.mattermostLong' },
	{ id: 'email', label: 'Email', long: 'channel.emailLong' },
	{ id: 'webhook', label: 'Webhook', long: 'channel.webhookLong' }
];

/** @type {Record<string, string | MessageKey>} */
const HINTS = {
	slack: 'https://hooks.slack.com/services/…',
	teams: 'channel.hint.teams',
	mattermost: 'https://mattermost.example.com/hooks/…',
	email: 'channel.hint.email',
	webhook: 'https://your-endpoint/…'
};

/** @param {string} type @param {Translate} t */
export const channelHint = (type, t) => {
	const h = HINTS[type] ?? HINTS.webhook;
	return h.startsWith('channel.') ? t(/** @type {MessageKey} */ (h)) : h;
};
export const channelPlaceholder = (/** @type {string} */ type) =>
	type === 'email' ? 'alice@example.com, bob@example.com' : 'https://…';
export const channelInputType = (/** @type {string} */ type) => (type === 'email' ? 'text' : 'url');

// Event types a channel can subscribe to. Scheduled summaries aren't one: a
// channel's `summary` setting sends them to that channel alone.
/** @type {{ id: string, key: MessageKey }[]} */
export const EVENT_TYPES = [
	{ id: '*', key: 'event.all' },
	{ id: 'finding.critical', key: 'event.findingCritical' },
	{ id: 'finding.exploitable', key: 'event.findingExploitable' },
	{ id: 'finding.assigned', key: 'event.findingAssigned' },
	{ id: 'risk_acceptance.requested', key: 'event.raRequested' },
	{ id: 'risk_acceptance.approved', key: 'event.raApproved' },
	{ id: 'risk_acceptance.expiring', key: 'event.raExpiring' },
	{ id: 'risk_acceptance.expired', key: 'event.raExpired' },
	{ id: 'finding.sla_breach', key: 'event.slaBreach' },
	{ id: 'finding.sla_due_soon', key: 'event.slaDueSoon' },
	{ id: 'cra.case_opened', key: 'event.craOpened' },
	{ id: 'cra.deadline_due_soon', key: 'event.craDueSoon' },
	{ id: 'cra.deadline_missed', key: 'event.craMissed' },
	{ id: 'policy.violation', key: 'event.policyViolation' },
	{ id: 'exception.expired', key: 'event.exceptionExpired' },
	{ id: 'ingestion.anomaly', key: 'event.ingestionAnomaly' }
];

/**
 * Weekday name in a locale; 0 = Sunday, as the API's summary_weekday.
 * @param {number} day @param {string} loc @param {'long' | 'short'} [width]
 */
export const weekday = (day, loc, width = 'long') =>
	new Intl.DateTimeFormat(loc, { weekday: width, timeZone: 'UTC' }).format(new Date(Date.UTC(2023, 0, 1 + day)));

/** Default delivery rules for a new channel. */
export const defaultRules = () => ({ min_severity: '', filter: '', summary: 'none', summary_hour: 8, summary_weekday: 1 });

/**
 * One line describing a channel's filter and schedule, e.g. "high and above · weekly summary Fri 07:00 UTC".
 * @param {{ min_severity?: string, filter?: string, summary?: string, summary_hour?: number, summary_weekday?: number }} ch
 * @param {Translate} t
 * @param {(group: string, value: string) => string} label enum labels
 * @param {string} loc
 */
export function describeRules(ch, t, label, loc) {
	const parts = [];
	if (ch.min_severity) parts.push(t('rules.andAbove', { severity: label('severity', ch.min_severity) }));
	if (ch.filter) parts.push(t('rules.when', { filter: ch.filter }));
	const time = `${String(ch.summary_hour ?? 8).padStart(2, '0')}:00 UTC`;
	if (ch.summary === 'daily') parts.push(t('rules.daily', { time }));
	if (ch.summary === 'weekly') parts.push(t('rules.weekly', { day: weekday(ch.summary_weekday ?? 1, loc, 'short'), time }));
	return parts.join(' · ') || t('rules.everyEvent');
}
