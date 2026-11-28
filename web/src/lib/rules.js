// Shared by the admin triage-rules page and a project's Rules tab: a rule's
// side-action fields (M13 13.5) between the form and the API.

/** The side-action fields of a blank rule form. */
export const blankSide = () => ({
	assign_user_id: /** @type {string | null} */ (null),
	assign_owner_from: '',
	only_if_unassigned: true,
	add_tags: '',
	comment: '',
	notify: false,
	schedule: '',
	age_days_gt: /** @type {string | number} */ ('')
});

/**
 * The API shape of the form's side fields: tags as a list, an empty age as null.
 * @param {ReturnType<typeof blankSide>} f
 */
export function sideBody(f) {
	return {
		assign_user_id: f.assign_user_id || null,
		assign_owner_from: f.assign_owner_from,
		only_if_unassigned: f.only_if_unassigned,
		add_tags: String(f.add_tags)
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean),
		comment: f.comment.trim(),
		notify: f.notify,
		schedule: f.schedule,
		age_days_gt: f.age_days_gt === '' || f.age_days_gt === null ? null : Number(f.age_days_gt)
	};
}

/**
 * Short labels for what a stored rule does besides its action.
 * @param {any} r
 * @param {(key: any, params?: Record<string, any>) => string} t
 */
export function sideChips(r, t) {
	const out = [];
	if (r.assign_user_id || r.assign_owner_from) out.push(t('rules.side.chipAssign'));
	if (r.add_tags?.length) out.push(t('rules.side.chipTags', { tags: r.add_tags.join(', ') }));
	if (r.comment) out.push(t('rules.side.chipComment'));
	if (r.notify) out.push(t('rules.side.chipNotify'));
	if (r.schedule === 'daily') out.push(t('rules.side.chipDaily'));
	return out;
}
