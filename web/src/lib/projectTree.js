// Project hierarchy helpers: projects carry an optional parent_id (same
// organization, at most MAX_DEPTH levels; the server enforces both).

export const MAX_DEPTH = 5;

/**
 * Orders projects as a tree: each root (no parent, or a parent the caller
 * can't see) by name, followed by its descendants depth-first.
 * @param {any[]} projects
 * @returns {{ project: any, depth: number }[]}
 */
export function flattenTree(projects) {
	const ids = new Set(projects.map((p) => p.id));
	/** @type {Map<string, any[]>} */
	const children = new Map();
	for (const p of projects) {
		const key = p.parent_id && ids.has(p.parent_id) ? p.parent_id : '';
		if (!children.has(key)) children.set(key, []);
		children.get(key)?.push(p);
	}
	for (const list of children.values()) list.sort((a, b) => a.name.localeCompare(b.name));
	/** @type {{ project: any, depth: number }[]} */
	const out = [];
	/** @param {string} key @param {number} depth */
	const walk = (key, depth) => {
		for (const p of children.get(key) ?? []) {
			out.push({ project: p, depth });
			walk(p.id, depth + 1);
		}
	};
	walk('', 0);
	return out;
}

/**
 * The projects that may become the parent of `self` (null for a new
 * project): same organization, not `self` or one of its descendants.
 * @param {any[]} projects
 * @param {any[]} teams
 * @param {string} teamId the (new) project's team
 * @param {string | null} selfId
 */
export function parentChoices(projects, teams, teamId, selfId) {
	const orgOf = (/** @type {string} */ tid) => teams.find((t) => t.id === tid)?.org_id;
	const org = orgOf(teamId);
	/** @type {Set<string>} */
	const excluded = new Set();
	if (selfId) {
		excluded.add(selfId);
		let grew = true;
		while (grew) {
			grew = false;
			for (const p of projects) {
				if (p.parent_id && excluded.has(p.parent_id) && !excluded.has(p.id)) {
					excluded.add(p.id);
					grew = true;
				}
			}
		}
	}
	return flattenTree(projects.filter((p) => !excluded.has(p.id) && orgOf(p.team_id) === org));
}
