// Thin client for the Xila API. Handles the Bearer token, JSON encoding,
// the {items, pagination} envelope, and raw uploads (scans / SBOMs).

// Same-origin by default (works when the API serves the bundled UI). Override
// with VITE_API_URL for the standalone dev server (see .env.example).
const BASE = import.meta.env.VITE_API_URL ?? '/api/v1';
const TOKEN_KEY = 'xila_token';

export function getToken() {
	if (typeof localStorage === 'undefined') return null;
	return localStorage.getItem(TOKEN_KEY);
}

/** @param {string | null | undefined} t */
export function setToken(t) {
	if (typeof localStorage === 'undefined') return;
	if (t) localStorage.setItem(TOKEN_KEY, t);
	else localStorage.removeItem(TOKEN_KEY);
}

/** The message of anything thrown (an ApiError, an Error, or a value). @param {unknown} err */
export function errorMessage(err) {
	return err instanceof Error ? err.message : String(err);
}

export class ApiError extends Error {
	/** @param {number} status @param {string} message */
	constructor(status, message) {
		super(message);
		this.status = status;
		// Set when the server wants a fresh sign-in first (X-Reauth-Required):
		// confirm the password with api.reauth and retry.
		this.reauth = false;
		// The parsed error body, when the server sent one beyond `error`
		// (e.g. a strict SBOM upload's `fields: [{path, message}]`).
		this.data = /** @type {any} */ (null);
	}
}

/** Base64url, no padding — matches the API's path-segment decoding for a root
 * cause's key (which may hold "/" or "@"). @param {string} s */
function b64url(s) {
	return btoa(unescape(encodeURIComponent(s)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

/** @typedef {Record<string, string | number | boolean | null | undefined>} Query */

/** @param {string} path @param {Query} [query] */
function buildURL(path, query) {
	// BASE may be relative ("/api/v1") for same-origin/proxy use, so resolve it
	// against the current origin — new URL() throws on a bare relative string.
	const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
	const url = new URL(BASE + path, origin);
	if (query) {
		for (const [k, v] of Object.entries(query)) {
			if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
		}
	}
	return url;
}

/** @param {Response} res @returns {Promise<any>} */
async function parse(res) {
	if (res.status === 204) return null;
	const text = await res.text();
	let data = null;
	if (text) {
		try {
			data = JSON.parse(text);
		} catch {
			data = text;
		}
	}
	if (!res.ok) {
		const msg = (data && data.error) || res.statusText || 'request failed';
		const err = new ApiError(res.status, msg);
		err.reauth = res.headers.get('X-Reauth-Required') === 'true';
		err.data = data;
		throw err;
	}
	return data;
}

/**
 * @param {string} method
 * @param {string} path
 * @param {{ body?: unknown, query?: Query, auth?: boolean, ifMatch?: string }} [opts]
 * @returns {Promise<any>}
 */
async function request(method, path, { body, query, auth = true, ifMatch = '' } = {}) {
	/** @type {Record<string, string>} */
	const headers = {};
	// Conflict detection: the version the edit is based on (a 412 means it changed).
	if (ifMatch) headers['If-Match'] = `"${ifMatch}"`;
	if (body !== undefined) headers['Content-Type'] = 'application/json';
	if (auth) {
		const t = getToken();
		if (t) headers['Authorization'] = 'Bearer ' + t;
	}
	const res = await fetch(buildURL(path, query), {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});
	return parse(res);
}

// upload sends a raw text body (scanner / SBOM output) as-is.
/** @param {string} path @param {string} rawText @param {Query} [query] @returns {Promise<any>} */
async function upload(path, rawText, query) {
	/** @type {Record<string, string>} */
	const headers = { 'Content-Type': 'application/json' };
	const t = getToken();
	if (t) headers['Authorization'] = 'Bearer ' + t;
	const res = await fetch(buildURL(path, query), { method: 'POST', headers, body: rawText });
	return parse(res);
}

// rawPut sends a raw text body (a YAML/JSON GitOps bundle) with PUT.
/** @param {string} path @param {string} rawText @param {Query} [query] @returns {Promise<any>} */
async function rawPut(path, rawText, query) {
	/** @type {Record<string, string>} */
	const headers = { 'Content-Type': 'application/yaml' };
	const t = getToken();
	if (t) headers['Authorization'] = 'Bearer ' + t;
	const res = await fetch(buildURL(path, query), { method: 'PUT', headers, body: rawText });
	return parse(res);
}

// sendFile posts one file as multipart field "file".
/** @param {string} path @param {Blob} file @returns {Promise<any>} */
async function sendFile(path, file) {
	/** @type {Record<string, string>} */
	const headers = {};
	const t = getToken();
	if (t) headers['Authorization'] = 'Bearer ' + t;
	const form = new FormData();
	form.append('file', file);
	const res = await fetch(buildURL(path), { method: 'POST', headers, body: form });
	return parse(res);
}

// download fetches an authenticated file and hands it to the browser to save.
// Resolves to true when the server flagged the file as truncated (X-Truncated).
/** @param {string} path @param {string} filename @returns {Promise<boolean>} */
async function download(path, filename) {
	/** @type {Record<string, string>} */
	const headers = {};
	const t = getToken();
	if (t) headers['Authorization'] = 'Bearer ' + t;
	const res = await fetch(buildURL(path), { headers });
	if (!res.ok) await parse(res); // throws ApiError
	const href = URL.createObjectURL(await res.blob());
	const a = document.createElement('a');
	a.href = href;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(href);
	return res.headers.get('X-Truncated') === 'true';
}

// exportTable downloads a listing's CSV / XLSX export for the given filters
// (pagination keys dropped — an export is the whole filter). Resolves to true
// when the server truncated it at its row cap.
/** @param {string} path @param {string} name @param {Record<string, any>} [filters] @param {string} [format] */
async function exportTable(path, name, filters = {}, format = 'csv') {
	const { limit, offset, ...rest } = filters;
	const q = new URLSearchParams({ format });
	for (const [k, v] of Object.entries(rest)) {
		if (v !== undefined && v !== null && v !== '' && v !== false) q.set(k, String(v));
	}
	const day = new Date().toISOString().slice(0, 10);
	return download(`${path}?${q}`, `${name}-${day}.${format}`);
}

// openReport shows an authenticated HTML report in a new tab — fetched with the
// Bearer token, which a plain link couldn't carry. With print, the browser's
// print dialog opens on it: that's how a report becomes a PDF ("Save as PDF").
// The tab is opened synchronously, inside the click, so it isn't popup-blocked.
// template / engagement_id pick a report template and an engagement's findings.
/** @param {string} path @param {{ print?: boolean, template?: string, engagement_id?: string }} [opts] */
async function openReport(path, { print = false, template = '', engagement_id = '' } = {}) {
	const query = new URLSearchParams(Object.entries({ template, engagement_id }).filter(([, v]) => v));
	if (query.size) path += '?' + query;
	const w = window.open('', '_blank');
	if (!w) throw new ApiError(0, 'Allow pop-ups for this site to open the report');
	try {
		/** @type {Record<string, string>} */
		const headers = {};
		const t = getToken();
		if (t) headers['Authorization'] = 'Bearer ' + t;
		const res = await fetch(buildURL(path), { headers });
		if (!res.ok) await parse(res); // throws ApiError
		// The server escapes every value and the document carries no scripts.
		const html = await res.text();
		w.document.open();
		w.document.write(html);
		w.document.close();
		if (print) {
			w.focus();
			w.print();
		}
	} catch (err) {
		w.close();
		throw err;
	}
}

export const api = {
	// --- auth ---
	/** @param {string} email @param {string} password */
	async register(email, password) {
		return request('POST', '/auth/register', { body: { email, password }, auth: false });
	},
	// Resolves to { token, user } — or { mfa_required, mfa_token } when two-factor is on.
	/** @param {string} email @param {string} password */
	login: (email, password) => request('POST', '/auth/login', { body: { email, password }, auth: false }),
	// Second sign-in step: the challenge plus a TOTP or recovery code → { token, user }.
	/** @param {string} mfaToken @param {string} code */
	verifyMfa: (mfaToken, code) => request('POST', '/auth/mfa', { body: { mfa_token: mfaToken, code }, auth: false }),
	mfaStatus: () => request('GET', '/me/mfa'),
	// Runtime feature switches: everyone reads them; admins (the owner, for
	// owner-only ones like mfa) flip them.
	features: () => request('GET', '/features'),
	/** @param {string} key @param {boolean} enabled */
	setFeature: (key, enabled) => request('PUT', `/features/${encodeURIComponent(key)}`, { body: { enabled } }),
	mfaSetup: () => request('POST', '/me/mfa/setup'),
	/** @param {string} code */
	mfaEnable: (code) => request('POST', '/me/mfa/enable', { body: { code } }),
	/** @param {string} code */
	mfaDisable: (code) => request('POST', '/me/mfa/disable', { body: { code } }),
	/** @param {string} id */
	resetUserMfa: (id) => request('DELETE', `/users/${id}/mfa`),
	// Public: { password_login_enabled, password_reset_email, directory_login, development, providers: [{ kind, name, login_url }] }.
	authConfig: () => request('GET', '/auth/config', { auth: false }),
	// Always 202, whether or not the address has an account.
	/** @param {string} email */
	requestPasswordReset: (email) => request('POST', '/auth/password-reset/request', { body: { email }, auth: false }),
	// Resolves to { token, user }: the reset signs the user in.
	/** @param {string} token @param {string} password */
	confirmPasswordReset: (token, password) =>
		request('POST', '/auth/password-reset/confirm', { body: { token, password }, auth: false }),
	// Both revoke every other session and resolve to { token, user } for this one.
	/** @param {string} currentPassword @param {string} newPassword */
	changePassword: (currentPassword, newPassword) =>
		request('POST', '/me/password', { body: { current_password: currentPassword, new_password: newPassword } }),
	revokeSessions: () => request('POST', '/me/sessions/revoke'),
	// Sign out. `redirect` is the IdP's Single Logout URL when the session came
	// from a SAML provider that supports it; empty for a plain local sign-out.
	/** @returns {Promise<{ redirect: string }>} */
	logout: () => request('POST', '/me/logout'),

	// --- single sign-on (admin) ---
	ssoProviders: () => request('GET', '/sso/providers'),
	/** @param {Record<string, any>} data */
	createSsoProvider: (data) => request('POST', '/sso/providers', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateSsoProvider: (id, data) => request('PUT', `/sso/providers/${id}`, { body: data }),
	/** @param {string} id */
	deleteSsoProvider: (id) => request('DELETE', `/sso/providers/${id}`),
	// Dry runs: a draft (not saved; `id` = an edit of that provider) or a saved one.
	/** @param {Record<string, any>} data */
	testSsoDraft: (data) => request('POST', '/sso/providers/test', { body: data }),
	/** @param {string} id */
	testSsoProvider: (id) => request('POST', `/sso/providers/${id}/test`),
	listGroupMappings: () => request('GET', '/sso/group-mappings').then((d) => d.mappings ?? []),
	/** @param {Record<string, any>} data */
	createGroupMapping: (data) => request('POST', '/sso/group-mappings', { body: data }),
	/** @param {string} id */
	deleteGroupMapping: (id) => request('DELETE', `/sso/group-mappings/${id}`),

	// --- security gate ---
	/** @param {string} projectId */
	gatePolicy: (projectId) => request('GET', `/projects/${projectId}/gate/policy`),
	/** @param {string} projectId @param {Record<string, any>} policy */
	setGatePolicy: (projectId, policy) =>
		request('PUT', `/projects/${projectId}/gate/policy`, { body: policy }),
	/** @param {string} projectId */
	deleteGatePolicy: (projectId) => request('DELETE', `/projects/${projectId}/gate/policy`),
	// A gate result comes back 200 (pass) or 422 (fail); both carry the body.
	/** @param {string} projectId */
	runGate: async (projectId) => {
		/** @type {Record<string, string>} */
		const headers = {};
		const t = getToken();
		if (t) headers['Authorization'] = 'Bearer ' + t;
		const res = await fetch(buildURL(`/projects/${projectId}/gate`), { method: 'POST', headers });
		const data = await res.json().catch(() => null);
		if (res.status === 200 || res.status === 422) return data;
		throw new ApiError(res.status, (data && data.error) || 'gate evaluation failed');
	},

	// --- SLA policies: GET returns the policy in force + its scope ---
	/** @param {string} projectId */
	slaPolicy: (projectId) => request('GET', `/projects/${projectId}/sla/policy`),
	/** @param {string} projectId @param {Record<string, any>} days */
	setSlaPolicy: (projectId, days) =>
		request('PUT', `/projects/${projectId}/sla/policy`, { body: days }),
	/** @param {string} projectId */
	deleteSlaPolicy: (projectId) => request('DELETE', `/projects/${projectId}/sla/policy`),
	/** @param {string} orgId */
	orgSlaPolicy: (orgId) => request('GET', `/orgs/${orgId}/sla/policy`),
	/** @param {string} orgId @param {Record<string, any>} days */
	setOrgSlaPolicy: (orgId, days) => request('PUT', `/orgs/${orgId}/sla/policy`, { body: days }),
	/** @param {string} orgId */
	deleteOrgSlaPolicy: (orgId) => request('DELETE', `/orgs/${orgId}/sla/policy`),
	globalSlaPolicy: () => request('GET', '/sla/policy'),
	/** @param {Record<string, any>} days */
	setGlobalSlaPolicy: (days) => request('PUT', '/sla/policy', { body: days }),
	deleteGlobalSlaPolicy: () => request('DELETE', '/sla/policy'),
	slaSweep: () => request('POST', '/sla/sweep'),
	slaSettings: () => request('GET', '/sla/settings'),
	/** @param {Record<string, any>} settings */
	setSlaSettings: (settings) => request('PUT', '/sla/settings', { body: settings }),

	// --- issue trackers (one per project; token write-only) + finding links ---
	/** @param {string} projectId */
	issueTracker: (projectId) => request('GET', `/projects/${projectId}/issue-tracker`),
	/** @param {string} projectId @param {Record<string, any>} data */
	setIssueTracker: (projectId, data) =>
		request('PUT', `/projects/${projectId}/issue-tracker`, { body: data }),
	/** @param {string} projectId */
	deleteIssueTracker: (projectId) => request('DELETE', `/projects/${projectId}/issue-tracker`),
	/** @param {string} projectId */
	testIssueTracker: (projectId) => request('POST', `/projects/${projectId}/issue-tracker/test`),
	/** @param {string} findingId */
	findingIssue: (findingId) => request('GET', `/findings/${findingId}/issue`),
	/** @param {string} findingId */
	createFindingIssue: (findingId) => request('POST', `/findings/${findingId}/issue`),
	syncIssueTrackers: () => request('POST', '/issue-trackers/sync'),

	// --- pull connectors (Dependency-Track / DefectDojo; token write-only) ---
	/** @param {string} projectId */
	listConnectors: (projectId) =>
		request('GET', `/projects/${projectId}/connectors`).then((d) => d.connectors ?? []),
	/** @param {string} projectId @param {Record<string, any>} data */
	createConnector: (projectId, data) => request('POST', `/projects/${projectId}/connectors`, { body: data }),
	/** @param {string} projectId @param {string} id @param {Record<string, any>} data */
	updateConnector: (projectId, id, data) =>
		request('PUT', `/projects/${projectId}/connectors/${id}`, { body: data }),
	/** @param {string} projectId @param {string} id */
	deleteConnector: (projectId, id) => request('DELETE', `/projects/${projectId}/connectors/${id}`),
	/** @param {string} projectId @param {string} id */
	testConnector: (projectId, id) => request('POST', `/projects/${projectId}/connectors/${id}/test`),
	/** @param {string} projectId @param {string} id */
	pullConnector: (projectId, id) => request('POST', `/projects/${projectId}/connectors/${id}/pull`),

	// --- triage rules (admin) ---
	listRules: () => request('GET', '/triage-rules').then((d) => d.rules ?? []),
	/** @param {Record<string, any>} data */
	createRule: (data) => request('POST', '/triage-rules', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateRule: (id, data) => request('PATCH', `/triage-rules/${id}`, { body: data }),
	/** @param {string} id */
	deleteRule: (id) => request('DELETE', `/triage-rules/${id}`),
	/** @param {string} [projectId] */
	applyRules: (projectId) =>
		request('POST', '/triage-rules/apply', { query: { project_id: projectId } }),
	/** @param {Record<string, any>} data @param {string} [projectId] */
	previewRule: (data, projectId) =>
		request('POST', '/triage-rules/preview', { body: data, query: { project_id: projectId } }),
	/** @param {string} id @param {string} [projectId] */
	previewStoredRule: (id, projectId) =>
		request('POST', `/triage-rules/${id}/preview`, { query: { project_id: projectId } }),
	/** @param {string} id */
	approveRule: (id) => request('POST', `/triage-rules/${id}/approve`),
	/** @param {string} id */
	rejectRule: (id) => request('POST', `/triage-rules/${id}/reject`),

	// --- account / rbac ---
	me: () => request('GET', '/me'),
	listUsers: () => request('GET', '/users').then((d) => d.users ?? []),
	// A passwordless account an SSO login links to (SSO_AUTO_CREATE_USERS=false).
	/** @param {string} email */
	createUser: (email) => request('POST', '/users', { body: { email } }),
	/** @param {string} id @param {boolean} isAdmin */
	setUserAdmin: (id, isAdmin) => request('PATCH', `/users/${id}`, { body: { is_admin: isAdmin } }),
	/** @param {string} id */
	deactivateUser: (id) => request('POST', `/users/${id}/deactivate`),
	/** @param {string} id */
	reactivateUser: (id) => request('POST', `/users/${id}/reactivate`),
	/** @param {string} id */
	deleteUser: (id) => request('DELETE', `/users/${id}`),
	// { url, expires_at }; url is relative when PUBLIC_URL is unset.
	/** @param {string} id */
	passwordResetLink: (id) => request('POST', `/users/${id}/password-reset-link`),

	// --- organizations ---
	listOrgs: () => request('GET', '/orgs').then((d) => d.organizations ?? []),
	/** @param {Record<string, any>} data */
	createOrg: (data) => request('POST', '/orgs', { body: data }),
	/** @param {string} orgId */
	listOrgMembers: (orgId) =>
		request('GET', `/orgs/${orgId}/members`).then((d) => d.members ?? []),
	/** @param {string} orgId @param {string} email @param {string} role */
	addOrgMember: (orgId, email, role) =>
		request('POST', `/orgs/${orgId}/members`, { body: { email, role } }),
	/** @param {string} orgId @param {string} userId */
	removeOrgMember: (orgId, userId) => request('DELETE', `/orgs/${orgId}/members/${userId}`),

	// --- teams ---
	listTeams: () => request('GET', '/teams').then((d) => d.teams ?? []),
	/** @param {string} orgId @param {Record<string, any>} data */
	createTeam: (orgId, data) => request('POST', `/orgs/${orgId}/teams`, { body: data }),
	/** @param {string} teamId */
	listMembers: (teamId) =>
		request('GET', `/teams/${teamId}/members`).then((d) => d.members ?? []),
	// A grant: a user ({ email }) or a user group ({ group_id }) with a role,
	// optionally narrowed by a custom role (custom_role_id).
	/** @param {string} teamId @param {{ email?: string, group_id?: string, role: string, custom_role_id?: string }} grant */
	addMember: (teamId, grant) => request('POST', `/teams/${teamId}/members`, { body: grant }),
	/** @param {string} teamId @param {string} userId */
	removeMember: (teamId, userId) => request('DELETE', `/teams/${teamId}/members/${userId}`),
	/** @param {string} teamId @param {string} groupId */
	removeTeamGroup: (teamId, groupId) => request('DELETE', `/teams/${teamId}/groups/${groupId}`),

	// --- user groups and custom roles (org admin) ---
	/** @param {string} orgId */
	listGroups: (orgId) => request('GET', `/orgs/${orgId}/groups`).then((d) => d.groups ?? []),
	/** @param {string} orgId @param {string} name */
	createGroup: (orgId, name) => request('POST', `/orgs/${orgId}/groups`, { body: { name } }),
	/** @param {string} orgId @param {string} groupId */
	getGroup: (orgId, groupId) => request('GET', `/orgs/${orgId}/groups/${groupId}`),
	/** @param {string} orgId @param {string} groupId @param {string} name */
	renameGroup: (orgId, groupId, name) => request('PUT', `/orgs/${orgId}/groups/${groupId}`, { body: { name } }),
	/** @param {string} orgId @param {string} groupId */
	deleteGroup: (orgId, groupId) => request('DELETE', `/orgs/${orgId}/groups/${groupId}`),
	/** @param {string} orgId @param {string} groupId @param {string} email */
	addGroupMember: (orgId, groupId, email) =>
		request('POST', `/orgs/${orgId}/groups/${groupId}/members`, { body: { email } }),
	/** @param {string} orgId @param {string} groupId @param {string} userId */
	removeGroupMember: (orgId, groupId, userId) =>
		request('DELETE', `/orgs/${orgId}/groups/${groupId}/members/${userId}`),
	/** @param {string} orgId */
	listCustomRoles: (orgId) => request('GET', `/orgs/${orgId}/custom-roles`).then((d) => d.custom_roles ?? []),
	/** @param {string} orgId @param {{ name: string, base_role: string, denied_capabilities: string[] }} role */
	createCustomRole: (orgId, role) => request('POST', `/orgs/${orgId}/custom-roles`, { body: role }),
	/** @param {string} orgId @param {string} roleId @param {{ name: string, base_role: string, denied_capabilities: string[] }} role */
	updateCustomRole: (orgId, roleId, role) => request('PUT', `/orgs/${orgId}/custom-roles/${roleId}`, { body: role }),
	/** @param {string} orgId @param {string} roleId */
	deleteCustomRole: (orgId, roleId) => request('DELETE', `/orgs/${orgId}/custom-roles/${roleId}`),
	capabilities: () => request('GET', '/capabilities').then((d) => d.capabilities ?? []),
	// SCIM provisioning tokens (instance admin); the secret is returned once.
	listSCIMTokens: () => request('GET', '/scim-tokens').then((d) => d.tokens ?? []),
	/** @param {string} name @param {string} orgId */
	createSCIMToken: (name, orgId) => request('POST', '/scim-tokens', { body: { name, org_id: orgId } }),
	/** @param {string} id */
	revokeSCIMToken: (id) => request('DELETE', `/scim-tokens/${id}`),

	// --- project members (access to one project, without joining its team) ---
	/** @param {string} projectId */
	listProjectMembers: (projectId) =>
		request('GET', `/projects/${projectId}/members`).then((d) => d.members ?? []),
	/** @param {string} projectId @param {{ email?: string, group_id?: string, role: string, custom_role_id?: string }} grant */
	addProjectMember: (projectId, grant) => request('POST', `/projects/${projectId}/members`, { body: grant }),
	/** @param {string} projectId @param {string} groupId */
	removeProjectGroup: (projectId, groupId) => request('DELETE', `/projects/${projectId}/groups/${groupId}`),
	/** @param {string} projectId @param {string} userId */
	removeProjectMember: (projectId, userId) =>
		request('DELETE', `/projects/${projectId}/members/${userId}`),
	/** @param {string} userId */
	transferOwnership: (userId) => request('POST', `/users/${userId}/transfer-ownership`),
	// Instance audit log (admin). filters: actor, actor_id, actor_kind, action,
	// resource_type, resource_id, project_id, outcome, from, to, limit, offset.
	/** @param {Query} [filters] */
	listAuditLog: (filters) => request('GET', '/audit-log', { query: filters }),
	/** @param {Record<string, any>} [filters] @param {string} [format] */
	exportAuditLog: (filters, format) => exportTable('/audit-log/export', 'xila-audit-log', filters, format),
	// Personal notifications: the caller's own subscriptions and watches.
	myNotifications: () => request('GET', '/me/notifications'),
	/** @param {Record<string, any>} prefs */
	saveMyNotifications: (prefs) => request('PUT', '/me/notifications', { body: prefs }),
	myNotificationDeliveries: () =>
		request('GET', '/me/notifications/deliveries').then((d) => d.deliveries ?? []),
	/** @param {string} projectId */
	watchingProject: (projectId) => request('GET', `/projects/${projectId}/watch`).then((d) => !!d.watching),
	/** @param {string} projectId @param {boolean} on */
	watchProject: (projectId, on) =>
		request(on ? 'PUT' : 'DELETE', `/projects/${projectId}/watch`).then((d) => !!d.watching),
	// In-app notification inbox (13.8): assignments, @mentions, watched-project
	// events, and (project-less) admin events, re-checked for visibility on
	// every call. filters: unread / mentions / assigned, limit, offset.
	/** @param {Query} [filters] */
	listInbox: (filters) => request('GET', '/me/inbox', { query: filters }),
	inboxCount: () => request('GET', '/me/inbox/count').then((d) => d.unread ?? 0),
	/** @param {{ ids?: string[], all?: boolean }} body */
	markInboxRead: (body) => request('POST', '/me/inbox/read', { body }),
	// Permission audit (admin). filters: user, user_id, project_id, team_id,
	// org_id, role, source, principal_kind, limit, offset.
	/** @param {Query} [filters] */
	listPermissions: (filters) => request('GET', '/permissions', { query: filters }),
	/** @param {Record<string, any>} [filters] @param {string} [format] */
	exportPermissions: (filters, format) => exportTable('/permissions/export', 'xila-permissions', filters, format),
	/** Who can reach a project and why (project owner). @param {string} projectId @param {Query} [filters] */
	projectAccess: (projectId, filters) => request('GET', `/projects/${projectId}/access`, { query: filters }),

	// --- PSIRT: CSAF advisories about our own products (admin) ---
	listPSIRT: () => request('GET', '/psirt/advisories', { query: { limit: 200 } }).then((d) => d.advisories ?? []),
	/** @param {Record<string, any>} a */
	createPSIRT: (a) => request('POST', '/psirt/advisories', { body: a }),
	/** @param {string} id @param {Record<string, any>} a */
	updatePSIRT: (id, a) => request('PUT', `/psirt/advisories/${id}`, { body: a }),
	/** @param {string} id */
	deletePSIRT: (id) => request('DELETE', `/psirt/advisories/${id}`),
	/** @param {string} id */
	previewPSIRT: (id) => request('GET', `/psirt/advisories/${id}/preview`),
	/** @param {string} id @param {string} note */
	publishPSIRT: (id, note) => request('POST', `/psirt/advisories/${id}/publish`, { body: { note } }),
	/** @param {string} id @param {string} note */
	withdrawPSIRT: (id, note) => request('POST', `/psirt/advisories/${id}/withdraw`, { body: { note } }),
	/** @param {string} id @param {string} filename */
	downloadPSIRT: (id, filename) => download(`/psirt/advisories/${id}/csaf`, filename),
	// --- advisory feed rules (admin) ---
	listFeedRules: () => request('GET', '/feed-rules').then((d) => d.feed_rules ?? []),
	/** @param {Record<string, any>} r */
	createFeedRule: (r) => request('POST', '/feed-rules', { body: r }),
	/** @param {string} id @param {Record<string, any>} r */
	updateFeedRule: (id, r) => request('PUT', `/feed-rules/${id}`, { body: r }),
	/** @param {string} id */
	deleteFeedRule: (id) => request('DELETE', `/feed-rules/${id}`),

	// --- projects ---
	/** @param {string} [teamId] @param {boolean} [archived] */
	listProjects: (teamId, archived) =>
		request('GET', '/projects', { query: { team_id: teamId, archived: archived ? 'true' : undefined } }).then(
			(d) => d.projects ?? []
		),
	/** @param {string} id */
	getProject: (id) => request('GET', `/projects/${id}`),
	/** @param {string} teamId @param {Record<string, any>} data */
	createProject: (teamId, data) => request('POST', `/teams/${teamId}/projects`, { body: data }),
	// Partial update; `parent_id: null` makes the project a root.
	/** @param {string} id @param {Record<string, any>} data */
	updateProject: (id, data) => request('PATCH', `/projects/${id}`, { body: data }),
	// Archive instead of delete: DELETE archives; restore within ARCHIVE_RETENTION.
	/** @param {'projects' | 'engagements' | 'scans' | 'findings'} kind @param {string} id */
	archive: (kind, id) => request('DELETE', `/${kind}/${id}`),
	/** @param {'projects' | 'engagements' | 'scans' | 'findings'} kind @param {string} id */
	restore: (kind, id) => request('POST', `/${kind}/${id}/restore`),
	/** @param {string} id */
	projectChildren: (id) => request('GET', `/projects/${id}/children`).then((d) => d.projects ?? []),
	// Rollups take `include_children` (default: true for a collection).
	/** @param {string} id @param {Record<string, any>} [query] */
	projectSummary: (id, query = {}) => request('GET', `/projects/${id}/summary`, { query }),
	// Branches / releases: every scan, SBOM and finding belongs to one.
	/** @param {string} projectId */
	listVersions: (projectId) =>
		request('GET', `/projects/${projectId}/versions`).then((d) => d.versions ?? []),
	/** @param {string} projectId @param {string} versionId */
	setDefaultVersion: (projectId, versionId) =>
		request('PATCH', `/projects/${projectId}/versions/${versionId}`, { body: { is_default: true } }),
	/** @param {string} projectId @param {string} versionId */
	deleteVersion: (projectId, versionId) =>
		request('DELETE', `/projects/${projectId}/versions/${versionId}`),

	// --- scans ---
	/** @param {string} projectId @param {boolean} [archived] */
	listScans: (projectId, archived) =>
		request('GET', `/projects/${projectId}/scans`, { query: { archived: archived ? 'true' : undefined } }).then(
			(d) => d.scans ?? []
		),
	/** @param {string} projectId @param {string} scanner @param {string} raw @param {Record<string, any>} [opts] */
	uploadScan: (projectId, scanner, raw, opts = {}) =>
		upload(`/projects/${projectId}/scans`, raw, { scanner, ...opts }),

	// --- engagements (DefectDojo-style): time-boxed work; its scans are its tests ---
	/** @param {string} projectId @param {boolean} [archived] */
	listEngagements: (projectId, archived) =>
		request('GET', `/projects/${projectId}/engagements`, { query: { archived: archived ? 'true' : undefined } }).then(
			(d) => d.engagements ?? []
		),
	/** @param {string} id */
	getEngagement: (id) => request('GET', `/engagements/${id}`),
	/** @param {string} projectId @param {object} data */
	createEngagement: (projectId, data) => request('POST', `/projects/${projectId}/engagements`, { body: data }),
	/** @param {string} id @param {object} data */
	updateEngagement: (id, data) => request('PATCH', `/engagements/${id}`, { body: data }),
	// A finding a person found (pentest, review); optional template_id prefills it.
	/** @param {string} projectId @param {object} data */
	createManualFinding: (projectId, data) => request('POST', `/projects/${projectId}/findings`, { body: data }),
	// Manual findings only: edit the write-up (scanner findings belong to their scanner).
	/** @param {string} id @param {object} data */
	updateFindingDetails: (id, data) => request('PATCH', `/findings/${id}/details`, { body: data }),
	// Override title / severity (sticky across scans), set or clear the planned
	// remediation date. ifMatch = the finding's updated_at as loaded (412 if stale).
	/** @param {string} id @param {Record<string, any>} data @param {string} ifMatch */
	editFindingFields: (id, data, ifMatch) => request('PATCH', `/findings/${id}/fields`, { body: data, ifMatch }),

	// --- custom fields (definitions: read everyone, write admin; values: editor) ---
	/** @param {{ entity?: string, project_id?: string }} [query] */
	listCustomFields: (query = {}) =>
		request('GET', '/custom-fields', { query }).then((d) => d.custom_fields ?? []),
	/** @param {object} data */
	createCustomField: (data) => request('POST', '/custom-fields', { body: data }),
	/** @param {string} id @param {object} data */
	updateCustomField: (id, data) => request('PATCH', `/custom-fields/${id}`, { body: data }),
	/** @param {string} id */
	deleteCustomField: (id) => request('DELETE', `/custom-fields/${id}`),
	// Merge values into a project's / asset's / finding's custom fields (null clears).
	/** @param {'projects' | 'assets' | 'findings'} kind @param {string} id @param {Record<string, any>} values */
	setCustomValues: (kind, id, values) =>
		request('PATCH', `/${kind}/${id}/custom`, { body: values }).then((d) => d.custom ?? {}),

	// --- custom parsers (no-code: map a CSV/JSON/XML report's fields to findings; admin) ---
	listCustomParsers: () => request('GET', '/custom-parsers').then((d) => d.custom_parsers ?? []),
	/** @param {object} def */
	createCustomParser: (def) => request('POST', '/custom-parsers', { body: def }),
	/** @param {string} id @param {object} def */
	updateCustomParser: (id, def) => request('PUT', `/custom-parsers/${id}`, { body: def }),
	/** @param {string} id */
	deleteCustomParser: (id) => request('DELETE', `/custom-parsers/${id}`),
	/** @param {object} def @param {string} sample */
	dryRunCustomParser: (def, sample) => request('POST', '/custom-parsers/dry-run', { body: { ...def, sample } }),

	// --- finding templates (read: everyone; write: admin) ---
	listFindingTemplates: () => request('GET', '/finding-templates').then((d) => d.templates ?? []),
	/** @param {object} data */
	createFindingTemplate: (data) => request('POST', '/finding-templates', { body: data }),
	/** @param {string} id @param {object} data */
	updateFindingTemplate: (id, data) => request('PUT', `/finding-templates/${id}`, { body: data }),
	/** @param {string} id */
	deleteFindingTemplate: (id) => request('DELETE', `/finding-templates/${id}`),

	// --- report templates (read: everyone; write: admin) ---
	listReportTemplates: () => request('GET', '/report-templates'), // { templates, sections }
	/** @param {object} data */
	createReportTemplate: (data) => request('POST', '/report-templates', { body: data }),
	/** @param {string} id @param {object} data */
	updateReportTemplate: (id, data) => request('PUT', `/report-templates/${id}`, { body: data }),
	/** @param {string} id */
	deleteReportTemplate: (id) => request('DELETE', `/report-templates/${id}`),

	// --- report schedules (each user manages their own; admins see all) ---
	listReportSchedules: () => request('GET', '/report-schedules'), // { report_schedules }
	/** @param {object} data */
	createReportSchedule: (data) => request('POST', '/report-schedules', { body: data }),
	/** @param {string} id @param {object} data */
	updateReportSchedule: (id, data) => request('PUT', `/report-schedules/${id}`, { body: data }),
	/** @param {string} id */
	deleteReportSchedule: (id) => request('DELETE', `/report-schedules/${id}`),
	/** @param {string} id */
	listReportScheduleRuns: (id) => request('GET', `/report-schedules/${id}/runs`), // { runs }
	/** @param {string} id */
	sendReportScheduleNow: (id) => request('POST', `/report-schedules/${id}/send-now`),

	// --- README badges (token shown once; owner manages) ---
	/** @param {string} projectId */
	badgeStatus: (projectId) => request('GET', `/projects/${projectId}/badge-token`),
	/** @param {string} projectId */
	issueBadgeToken: (projectId) => request('POST', `/projects/${projectId}/badge-token`),
	/** @param {string} projectId */
	revokeBadgeToken: (projectId) => request('DELETE', `/projects/${projectId}/badge-token`),

	// Async ingest queue (admin): depth, and the live tuning every node applies
	// on its next sample (null = the env default).
	ingestQueue: () => request('GET', '/ingest/queue'),
	ingestSettings: () => request('GET', '/ingest/settings'),
	/** @param {{ max_queue_depth: number | null, workers: number | null }} body */
	setIngestSettings: (body) => request('PUT', '/ingest/settings', { body }),

	// --- findings ---
	// Per-project priority weights ({ weights, custom, defaults }); PUT takes
	// only the factors to override.
	/** @param {string} projectId */
	priorityWeights: (projectId) => request('GET', `/projects/${projectId}/priority-weights`),

	/** @param {string} projectId */
	getTriageCarry: (projectId) => request('GET', `/projects/${projectId}/triage-carry`),
	/** @param {string} projectId */
	getAssessmentApprovers: (projectId) =>
		request('GET', `/projects/${projectId}/assessment-approvers`).then((d) => d.approvers ?? []),
	/** @param {string} projectId @param {string[]} userIds @param {string[]} groupIds */
	setAssessmentApprovers: (projectId, userIds, groupIds) =>
		request('PUT', `/projects/${projectId}/assessment-approvers`, { body: { user_ids: userIds, group_ids: groupIds } })
			.then((d) => d.approvers ?? []),
	/** @param {string} projectId @param {{enabled: boolean, branch_regex: string}} data */
	setTriageCarry: (projectId, data) => request('PUT', `/projects/${projectId}/triage-carry`, { body: data }),
	/** @param {string} findingId @param {string} primaryId */
	markDuplicate: (findingId, primaryId) => request('POST', `/findings/${findingId}/duplicate-of`, { body: { primary_id: primaryId } }),
	/** @param {string} findingId */
	unmarkDuplicate: (findingId) => request('DELETE', `/findings/${findingId}/duplicate-of`),
	/** @param {string} projectId @param {Record<string, number>} weights */
	setPriorityWeights: (projectId, weights) => request('PUT', `/projects/${projectId}/priority-weights`, { body: weights }),
	/** @param {string} projectId */
	resetPriorityWeights: (projectId) => request('DELETE', `/projects/${projectId}/priority-weights`),
	/** @param {string} projectId @param {Record<string, any>} [filters] */
	listFindings: (projectId, filters = {}) =>
		request('GET', `/projects/${projectId}/findings`, { query: filters }),
	/** @param {Record<string, any>} [filters] */
	searchFindings: (filters = {}) => request('GET', '/findings', { query: filters }),
	// CSV / Excel of the same filter (format: 'csv' | 'xlsx'). Returns whether
	// the 100k-row cap cut it short.
	/** @param {Record<string, any>} [filters] @param {string} [format] */
	exportFindings: (filters, format) => exportTable('/findings/export', 'xila-findings', filters, format),
	/** @param {string} projectId @param {Record<string, any>} [filters] @param {string} [format] */
	exportProjectFindings: (projectId, filters, format) =>
		exportTable(`/projects/${projectId}/findings/export`, 'xila-findings', filters, format),
	/** @param {string} id */
	getFinding: (id) => request('GET', `/findings/${id}`),
	/** @param {string} id @param {string} status @param {Record<string, any>} [opts] */
	setFindingStatus: (id, status, opts = {}) =>
		request('PATCH', `/findings/${id}`, { body: { status, ...opts } }),
	/** @param {string} id */
	findingComponents: (id) => request('GET', `/findings/${id}/components`),
	/** Public exploits for the finding's CVEs. @param {string} id */
	findingExploits: (id) => request('GET', `/findings/${id}/exploits`),
	/** @param {string} id */
	findingDuplicates: (id) =>
		request('GET', `/findings/${id}/duplicates`).then((d) => d.duplicates ?? []),
	/** @param {string} id */
	findingExceptions: (id) =>
		request('GET', `/findings/${id}/exceptions`).then((d) => d.exceptions ?? []),
	// Analyst workflow: ownership, discussion, evidence, history, bulk edits.
	/** @param {string} id */
	findingHistory: (id) => request('GET', `/findings/${id}/history`).then((d) => d.events ?? []),
	// Tags: replace one finding's set; list the tags in use ({tag, count}).
	/** @param {string} id @param {string[]} tags @param {string} [ifMatch] */
	setFindingTags: (id, tags, ifMatch = '') => request('PUT', `/findings/${id}/tags`, { body: { tags }, ifMatch }),
	/** Fix-first plan; projectId '' = every visible project. @param {string} projectId @param {Record<string, any>} [query] */
	fixPlan: (projectId, query = {}) => request('GET', projectId ? `/projects/${projectId}/fix-plan` : '/fix-plan', { query }),
	// Remediation actions: findings grouped by the change that fixes them.
	/** Actions; projectId '' = every visible project. @param {string} projectId @param {Record<string, any>} [query] */
	remediationActions: (projectId, query = {}) =>
		request('GET', projectId ? `/projects/${projectId}/remediation` : '/remediation', { query }),
	/** @param {string} projectId */
	remediationProposals: (projectId) =>
		request('GET', `/projects/${projectId}/remediation/proposals`).then((d) => d.proposals ?? []),
	/** @param {string} projectId @param {string} kind @param {string} key */
	acceptRemediation: (projectId, kind, key) =>
		request('POST', `/projects/${projectId}/remediation`, { body: { kind, key } }),
	/** @param {string} id @param {Record<string, any>} patch */
	updateRemediation: (id, patch) => request('PATCH', `/remediation/${id}`, { body: patch }),
	/** @param {string} id */
	remediationFindings: (id) => request('GET', `/remediation/${id}/findings`).then((d) => d.findings ?? []),
	/** @param {string} id */
	fileRemediationIssue: (id) => request('POST', `/remediation/${id}/issue`),
	// Root causes: the same change merged across every project you can see.
	/** @param {Record<string, any>} [query] */
	rootCauses: (query = {}) => request('GET', '/root-causes', { query }),
	/** @param {string} kind @param {string} key */
	rootCause: (kind, key) => request('GET', `/root-causes/${kind}/${b64url(key)}`),
	/** @param {string} kind @param {string} key */
	createRootCauseRemediation: (kind, key) => request('POST', `/root-causes/${kind}/${b64url(key)}/remediation`),
	/** @param {string} [projectId] */
	findingTags: (projectId) =>
		request('GET', '/findings/tags', { query: { project_id: projectId } }).then((d) => d.tags ?? []),
	// ifMatch: the finding's updated_at as loaded; a 412 means someone changed it.
	/** @param {string} id @param {string} assigneeId @param {string} [ifMatch] */
	assignFinding: (id, assigneeId, ifMatch = '') =>
		request('PUT', `/findings/${id}/assignee`, { body: { assignee_id: assigneeId || null }, ifMatch }),
	/** @param {string} projectId */
	projectAssignees: (projectId) =>
		request('GET', `/projects/${projectId}/assignees`).then((d) => d.assignees ?? []),
	/** @param {string} id */
	findingComments: (id) => request('GET', `/findings/${id}/comments`).then((d) => d.comments ?? []),
	/** @param {string} id @param {string} body */
	addFindingComment: (id, body) => request('POST', `/findings/${id}/comments`, { body: { body } }),
	/** @param {string} id @param {string} commentId */
	deleteFindingComment: (id, commentId) =>
		request('DELETE', `/findings/${id}/comments/${commentId}`),
	/** @param {string} id */
	findingAttachments: (id) =>
		request('GET', `/findings/${id}/attachments`).then((d) => d.attachments ?? []),
	/** @param {string} id @param {Blob} file */
	addFindingAttachment: (id, file) => sendFile(`/findings/${id}/attachments`, file),
	/** @param {string} id @param {{ id: string, filename: string }} att */
	downloadFindingAttachment: (id, att) =>
		download(`/findings/${id}/attachments/${att.id}`, att.filename),
	/** @param {string} id @param {string} attId */
	deleteFindingAttachment: (id, attId) => request('DELETE', `/findings/${id}/attachments/${attId}`),
	// target: { ids } or { filter } (GET /findings keys, as strings);
	// change: { status, reason, expires_at, severity, assignee_id } — omit what stays.
	// Returns { updated, failed, pending }; `pending` holds the assessments
	// created instead of applying (ASSESSMENT_REQUIRES_APPROVAL).
	/** @param {Record<string, any>} target @param {Record<string, any>} change */
	bulkUpdateFindings: (target, change) =>
		request('POST', '/findings/bulk', { body: { ...target, ...change } }),
	// Manual-assessment approval (four-eyes). setFindingStatus returns an
	// assessment ({ state: 'pending', … }) instead of the finding when held.
	/** @param {string} id */
	findingAssessments: (id) =>
		request('GET', `/findings/${id}/assessments`).then((d) => d.assessments ?? []),
	// Risk acceptances: setFindingStatus / bulk with status risk_accepted return
	// requested acceptances ({ state: 'requested', … }) instead of findings.
	/** @param {Record<string, any>} [filters] */
	listRiskAcceptances: (filters = {}) => request('GET', '/risk-acceptances', { query: filters }),
	/** @param {string} projectId @param {Record<string, any>} [filters] */
	projectRiskAcceptances: (projectId, filters = {}) =>
		request('GET', `/projects/${projectId}/risk-acceptances`, { query: filters }),
	/** @param {string} projectId @param {string} id */
	getRiskAcceptance: (projectId, id) => request('GET', `/projects/${projectId}/risk-acceptances/${id}`),
	/** @param {string} projectId @param {string} id @param {'approve' | 'reject' | 'revoke'} action @param {string} note */
	decideRiskAcceptance: (projectId, id, action, note) =>
		request('POST', `/projects/${projectId}/risk-acceptances/${id}/${action}`, { body: { note } }),
	/** @param {string} projectId @param {string} id @param {string} findingId */
	removeRiskAcceptanceFinding: (projectId, id, findingId) =>
		request('DELETE', `/projects/${projectId}/risk-acceptances/${id}/findings/${findingId}`),
	/** @param {string} id */
	findingRiskAcceptances: (id) =>
		request('GET', `/findings/${id}/risk-acceptances`).then((d) => d.risk_acceptances ?? []),
	/** @param {Record<string, any>} [filters] */
	listAssessments: (filters = {}) => request('GET', '/assessments', { query: filters }),
	/** @param {string} id @param {string} note */
	approveAssessment: (id, note) => request('POST', `/assessments/${id}/approve`, { body: { note } }),
	/** @param {string} id @param {string} note */
	rejectAssessment: (id, note) => request('POST', `/assessments/${id}/reject`, { body: { note } }),
	// AI-assisted triage (AI_TRIAGE_ENABLED; 404 while off). Proposals are
	// model output: render as text only. Nothing applies until accepted.
	/** @param {string} id */
	aiProposals: (id) => request('GET', `/findings/${id}/ai-proposals`),
	// Open proposals across visible projects (mine: asked by / assigned to me).
	/** @param {Record<string, any>} [filters] */
	listAIProposals: (filters = {}) => request('GET', '/ai-proposals', { query: filters }),
	/** @param {string} id @param {string} kind */
	aiPrompt: (id, kind) => request('GET', `/findings/${id}/ai-proposals/prompt`, { query: { kind } }),
	/** @param {string} id @param {string} kind */
	askAI: (id, kind) => request('POST', `/findings/${id}/ai-proposals`, { body: { kind } }),
	/** @param {string} id @param {string} proposalId @param {'accept' | 'reject'} action @param {string} note */
	decideAIProposal: (id, proposalId, action, note) =>
		request('POST', `/findings/${id}/ai-proposals/${proposalId}/${action}`, { body: { note } }),
	/** @param {string} projectId @param {boolean} optOut */
	setProjectAIOptOut: (projectId, optOut) =>
		request('PATCH', `/projects/${projectId}`, { body: { ai_triage_opt_out: optOut } }),

	// --- sboms ---
	/** @param {string} projectId */
	listSboms: (projectId) =>
		request('GET', `/projects/${projectId}/sboms`).then((d) => d.sboms ?? []),
	/** @param {string} projectId @param {string} raw @param {Record<string, any>} [opts] */
	uploadSbom: (projectId, raw, opts = {}) =>
		upload(`/projects/${projectId}/sboms`, raw, opts),
	/** @param {string} projectId @param {Record<string, any>} [filters] */
	projectComponents: (projectId, filters = {}) =>
		request('GET', `/projects/${projectId}/components`, { query: filters }),
	/** @param {string} id */
	getSbom: (id) => request('GET', `/sboms/${id}`),
	/** @param {string} id @param {Record<string, any>} [filters] */
	sbomComponents: (id, filters = {}) => request('GET', `/sboms/${id}/components`, { query: filters }),
	/** @param {string} projectId @param {Record<string, any>} [filters] @param {string} [format] */
	exportProjectComponents: (projectId, filters, format) =>
		exportTable(`/projects/${projectId}/components/export`, 'xila-components', filters, format),
	/** @param {string} projectId */
	listLicenseOverrides: (projectId) => request('GET', `/projects/${projectId}/license-overrides`),
	/** @param {string} projectId @param {string} id */
	getLicenseOverride: (projectId, id) => request('GET', `/projects/${projectId}/license-overrides/${id}`),
	/** @param {string} projectId @param {any} data */
	createLicenseOverride: (projectId, data) => request('POST', `/projects/${projectId}/license-overrides`, { body: data }),
	/** @param {string} projectId @param {string} id @param {any} data */
	updateLicenseOverride: (projectId, id, data) => request('PUT', `/projects/${projectId}/license-overrides/${id}`, { body: data }),
	/** @param {string} projectId @param {string} id */
	deleteLicenseOverride: (projectId, id) => request('DELETE', `/projects/${projectId}/license-overrides/${id}`),
	/** @param {string} id @param {Record<string, any>} [filters] @param {string} [format] */
	exportSbomComponents: (id, filters, format) =>
		exportTable(`/sboms/${id}/components/export`, 'xila-components', filters, format),
	/** @param {string} id */
	sbomVulnerabilities: (id) => request('GET', `/sboms/${id}/vulnerabilities`),
	// Components counted by freshness: { total, outdated, up_to_date, unknown }.
	/** @param {string} id */
	sbomFreshness: (id) => request('GET', `/sboms/${id}/freshness`),
	// Declared services (CycloneDX): { services, summary }.
	/** @param {string} id */
	sbomServices: (id) => request('GET', `/sboms/${id}/services`),
	/** @param {string} projectId @param {Record<string, any>} [query] */
	projectServices: (projectId, query = {}) => request('GET', `/projects/${projectId}/services`, { query }),
	// base omitted: compare with the previous snapshot of the same artifact.
	/** @param {string} id @param {string} [base] */
	sbomDiff: (id, base) => request('GET', `/sboms/${id}/diff`, { query: { base } }),
	/** @param {string} id */
	sbomGraph: (id) => request('GET', `/sboms/${id}/graph`),
	/** @param {string} id @param {Record<string, any>} target */
	sbomPaths: (id, target) => request('GET', `/sboms/${id}/graph/paths`, { query: target }),
	// The snapshot as a CycloneDX BOM (with vulnerabilities + analysis); spec 1.6 or 1.7.
	/** @param {string} id @param {string} filename @param {string} [spec] */
	exportSbom: (id, filename, spec = '1.6') => download(`/sboms/${id}/export?format=cyclonedx&spec=${spec}`, filename),
	/** @param {string} vulnId */
	vulnerabilityTimeline: (vulnId) =>
		request('GET', `/vulnerabilities/${encodeURIComponent(vulnId)}/sboms`),

	// --- vex ---
	/** @param {string} projectId */
	listVex: (projectId) =>
		request('GET', `/projects/${projectId}/vex`).then((d) => d.statements ?? []),
	/** @param {string} projectId @param {string} raw */
	uploadVex: (projectId, raw) => upload(`/projects/${projectId}/vex`, raw),
	/** @param {string} id */
	deleteVex: (id) => request('DELETE', `/vex/${id}`),
	// format: openvex | cyclonedx | csaf; versionId '' = the default branch;
	// spec: the CycloneDX version (1.6 or 1.7).
	/** @param {string} projectId @param {string} format @param {string} versionId @param {string} filename @param {string} [spec] */
	exportVex: (projectId, format, versionId, filename, spec = '') => {
		const q = new URLSearchParams({ format });
		if (spec) q.set('spec', spec);
		if (versionId) q.set('version_id', versionId);
		return download(`/projects/${projectId}/vex/export?${q}`, filename);
	},

	// --- vex-documents: stored, versioned VEX documents ---
	/** @param {{ limit?: number, offset?: number }} [page] */
	listVexDocuments: (page = {}) =>
		request('GET', '/vex-documents', { query: { limit: 200, ...page } }).then((d) => d.documents ?? []),
	/** @param {string} id */
	getVexDocument: (id) => request('GET', `/vex-documents/${id}`),
	/** @param {any} d */
	createVexDocument: (d) => request('POST', '/vex-documents', { body: d }),
	/** @param {string} id @param {any} d */
	updateVexDocument: (id, d) => request('PUT', `/vex-documents/${id}`, { body: d }),
	/** @param {string} id */
	deleteVexDocument: (id) => request('DELETE', `/vex-documents/${id}`),
	/** @param {string} id */
	publishVexDocument: (id) => request('POST', `/vex-documents/${id}/publish`),
	/** @param {string} id */
	listVexDocumentRevisions: (id) =>
		request('GET', `/vex-documents/${id}/revisions`).then((d) => d.revisions ?? []),
	/** @param {string} id @param {number} number @param {string} filename */
	downloadVexDocumentRevision: (id, number, filename) => download(`/vex-documents/${id}/revisions/${number}/download`, filename),

	// --- global component search ---
	/** @param {Record<string, any>} [filters] */
	searchComponents: (filters = {}) => request('GET', '/components', { query: filters }),
	/** @param {Record<string, any>} [filters] @param {string} [format] */
	exportComponents: (filters, format) => exportTable('/components/export', 'xila-components', filters, format),

	// --- licenses (SPDX catalog + ScanCode categories) and license groups ---
	// filters: { q, category, osi, deprecated, limit, offset } →
	// { licenses, total, list_version, categories, pagination }.
	/** @param {Record<string, any>} [filters] */
	listLicenses: (filters = {}) => request('GET', '/licenses', { query: filters }),
	/** @param {string} id */
	getLicense: (id) => request('GET', `/licenses/${encodeURIComponent(id)}`),
	// { groups, builtin, pagination }
	listLicenseGroups: () => request('GET', '/license-groups', { query: { limit: 200 } }),
	/** @param {string} ref */
	getLicenseGroup: (ref) => request('GET', `/license-groups/${encodeURIComponent(ref)}`),
	/** @param {Record<string, any>} data */
	createLicenseGroup: (data) => request('POST', '/license-groups', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateLicenseGroup: (id, data) => request('PUT', `/license-groups/${id}`, { body: data }),
	/** @param {string} id */
	deleteLicenseGroup: (id) => request('DELETE', `/license-groups/${id}`),

	// --- component policies (mutations admin) ---
	listPolicies: () => request('GET', '/policies').then((d) => d.policies ?? []),
	/** @param {string} id */
	getPolicy: (id) => request('GET', `/policies/${id}`),
	/** @param {Record<string, any>} data */
	createPolicy: (data) => request('POST', '/policies', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updatePolicy: (id, data) => request('PUT', `/policies/${id}`, { body: data }),
	/** @param {string} id */
	deletePolicy: (id) => request('DELETE', `/policies/${id}`),
	// { components, total, truncated, violations }
	/** @param {Record<string, any>} data @param {string} [projectId] */
	previewPolicy: (data, projectId) =>
		request('POST', '/policies/preview', { body: data, query: { project_id: projectId } }),
	/** @param {string} [projectId] */
	evaluatePolicies: (projectId) => request('POST', '/policies/evaluate', { query: { project_id: projectId } }),
	// { findings, pagination }
	/** @param {string} id @param {Record<string, any>} [filters] */
	policyViolations: (id, filters = {}) => request('GET', `/policies/${id}/violations`, { query: filters }),
	/** @param {string} projectId @param {Record<string, any>} [query] */
	projectPolicies: (projectId, query = {}) =>
		request('GET', `/projects/${projectId}/policies`, { query }).then((d) => d.policies ?? []),

	// --- vulnerability policies (admin) ---
	listVulnPolicies: () => request('GET', '/vuln-policies').then((d) => d.policies ?? []),
	/** @param {string} id */
	getVulnPolicy: (id) => request('GET', `/vuln-policies/${id}`),
	/** @param {Record<string, any>} data */
	createVulnPolicy: (data) => request('POST', '/vuln-policies', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateVulnPolicy: (id, data) => request('PATCH', `/vuln-policies/${id}`, { body: data }),
	/** @param {string} id */
	deleteVulnPolicy: (id) => request('DELETE', `/vuln-policies/${id}`),
	// { total, findings }
	/** @param {Record<string, any>} data @param {string} [projectId] */
	previewVulnPolicy: (data, projectId) =>
		request('POST', '/vuln-policies/preview', { body: data, query: { project_id: projectId } }),
	/** @param {string} id @param {string} [projectId] */
	previewStoredVulnPolicy: (id, projectId) =>
		request('POST', `/vuln-policies/${id}/preview`, { query: { project_id: projectId } }),
	/** @param {string} [projectId] */
	evaluateVulnPolicies: (projectId) =>
		request('POST', '/vuln-policies/evaluate', { query: { project_id: projectId } }),
	/** @param {string} [filename] */
	exportVulnPolicyBundle: (filename = 'vuln-policies.yaml') => download('/vuln-policies/bundle?format=yaml', filename),
	// { policies, dry_run }
	/** @param {string} rawText @param {boolean} [dryRun] */
	importVulnPolicyBundle: (rawText, dryRun = false) => rawPut('/vuln-policies/bundle', rawText, { dry_run: dryRun }),

	// --- assets ---
	/** @param {string} projectId */
	listAssets: (projectId) =>
		request('GET', `/projects/${projectId}/assets`).then((d) => d.assets ?? []),
	/** @param {string} projectId @param {Record<string, any>} data */
	createAsset: (projectId, data) => request('POST', `/projects/${projectId}/assets`, { body: data }),
	/** @param {string} assetId @param {Record<string, any>} [filters] */
	assetFindings: (assetId, filters = {}) =>
		request('GET', `/assets/${assetId}/findings`, { query: filters }),
	// Every asset the caller can see (relation targets may be in other projects).
	listAllAssets: () => request('GET', '/assets').then((d) => d.assets ?? []),
	/** @param {string} assetId @param {{ exposure: string, reason?: string }} data */
	setAssetExposure: (assetId, data) => request('PUT', `/assets/${assetId}/exposure`, { body: data }),
	/** @param {string} assetId */
	assetRelations: (assetId) =>
		request('GET', `/assets/${assetId}/relations`).then((d) => d.relations ?? []),
	/** @param {string} assetId @param {{ from_asset_id: string, to_asset_id: string, kind: string }} data */
	createAssetRelation: (assetId, data) => request('POST', `/assets/${assetId}/relations`, { body: data }),
	/** @param {string} assetId @param {string} relationId */
	deleteAssetRelation: (assetId, relationId) => request('DELETE', `/assets/${assetId}/relations/${relationId}`),
	/** @param {string} assetId */
	assetRelationSuggestions: (assetId) => request('GET', `/assets/${assetId}/relations/suggestions`),
	// { asset, affected: [{ asset, depth, via, shared_count, shared_findings }], shared_findings }
	/** @param {string} assetId */
	assetBlastRadius: (assetId) => request('GET', `/assets/${assetId}/blast-radius`),

	// --- compliance ---
	listFrameworks: () => request('GET', '/frameworks').then((d) => d.frameworks ?? []),
	/** @param {string} projectId */
	projectCompliance: (projectId) =>
		request('GET', `/projects/${projectId}/compliance`).then((d) => d.compliance ?? []),

	// --- portfolio ---
	portfolio: () => request('GET', '/portfolio'),
	// Printable HTML report (print → Save as PDF), scoped to what you can see.
	/** @param {{ print?: boolean, template?: string, engagement_id?: string }} [opts] */
	openPortfolioReport: (opts) => openReport('/portfolio/report', opts),
	/** @param {string} projectId @param {{ print?: boolean, template?: string, engagement_id?: string }} [opts] */
	openProjectReport: (projectId, opts) => openReport(`/projects/${projectId}/report`, opts),
	/** A framework's evidence report (printable HTML). @param {string} projectId @param {string} framework @param {{ print?: boolean }} [opts] */
	openEvidenceReport: (projectId, framework, opts) =>
		openReport(`/projects/${projectId}/compliance/${encodeURIComponent(framework)}/report`, opts),
	/** @param {string} projectId @param {string} framework @param {string} code @param {Record<string, any>} a */
	attestControl: (projectId, framework, code, a) =>
		request('PUT', `/projects/${projectId}/compliance/${encodeURIComponent(framework)}/attestations/${encodeURIComponent(code)}`, { body: a }),
	/** @param {string} projectId @param {string} framework @param {string} code */
	removeAttestation: (projectId, framework, code) =>
		request('DELETE', `/projects/${projectId}/compliance/${encodeURIComponent(framework)}/attestations/${encodeURIComponent(code)}`),
	// --- EU CRA Article 14 reporting cases ---
	/** Product declaration, manufacturer and cases. @param {string} projectId */
	projectCRA: (projectId) => request('GET', `/projects/${projectId}/cra`),
	/** @param {string} projectId @param {{ cra_in_scope: boolean, product_name: string, product_version: string, member_states: string[] }} product */
	setProjectCRA: (projectId, product) => request('PUT', `/projects/${projectId}/cra`, { body: product }),
	/** @param {string} projectId @param {{ finding_id: string, aware_at?: string, note?: string }} body */
	openCRACase: (projectId, body) => request('POST', `/projects/${projectId}/cra/cases`, { body }),
	/** @param {{ state?: string, project_id?: string, limit?: number, offset?: number }} [query] */
	listCRACases: (query = {}) => request('GET', '/cra/cases', { query }),
	/** @param {string} id */
	craCase: (id) => request('GET', `/cra/cases/${id}`),
	/** @param {string} id @param {Record<string, string | null>} edit */
	updateCRACase: (id, edit) => request('PATCH', `/cra/cases/${id}`, { body: edit }),
	/** @param {string} id @param {{ stage: string, reference?: string, note?: string }} body */
	submitCRACase: (id, body) => request('POST', `/cra/cases/${id}/submit`, { body }),
	/** @param {string} id @param {string} reason */
	dismissCRACase: (id, reason) => request('POST', `/cra/cases/${id}/dismiss`, { body: { reason } }),
	/** @param {string} id @param {string} [note] */
	closeCRACase: (id, note = '') => request('POST', `/cra/cases/${id}/close`, { body: { note } }),
	/** Download a stage's draft ENISA payload (JSON). @param {string} id @param {string} stage @param {string} vulnId */
	downloadCRAReport: (id, stage, vulnId) =>
		download(`/cra/cases/${id}/report?stage=${encodeURIComponent(stage)}`, `cra-${vulnId}-${stage}.json`),
	craSweep: () => request('POST', '/cra/sweep'),

	// --- metric trends (daily snapshots, oldest first; gaps = days not measured) ---
	/** @param {number} [days] */
	metricsTrends: (days = 90) =>
		request('GET', '/metrics/trends', { query: { days } }).then((d) => d.points ?? []),
	/** @param {string} projectId @param {number} [days] @param {Record<string, any>} [query] */
	projectTrends: (projectId, days = 90, query = {}) =>
		request('GET', `/projects/${projectId}/metrics/trends`, { query: { ...query, days } }).then((d) => d.points ?? []),

	// --- expiring exceptions ---
	/** @param {number} [days] */
	expiringFindings: (days = 30) =>
		request('GET', '/findings/expiring', { query: { days } }).then((d) => d.findings ?? []),

	// --- notifications ---
	/** @param {string} [projectId] */
	listChannels: (projectId) =>
		request('GET', '/notifications/channels', { query: { project_id: projectId } }).then(
			(d) => d.channels ?? []
		),
	/** @param {Record<string, any>} data */
	createChannel: (data) => request('POST', '/notifications/channels', { body: data }),
	// Edit name / events / enabled / min_severity / summary schedule.
	// Ingestion problems: silent scanners, collapsed uploads, failing connectors.
	ingestionHealth: () => request('GET', '/ingestion-health').then((d) => d.anomalies ?? []),
	/** @param {string} projectId */
	scanExpectations: (projectId) =>
		request('GET', `/projects/${projectId}/scan-expectations`).then((d) => d.expectations ?? []),
	/** @param {string} projectId @param {Record<string, any>} data */
	createScanExpectation: (projectId, data) =>
		request('POST', `/projects/${projectId}/scan-expectations`, { body: data }),
	/** @param {string} projectId @param {string} expectationId */
	deleteScanExpectation: (projectId, expectationId) =>
		request('DELETE', `/projects/${projectId}/scan-expectations/${expectationId}`),
	/** @param {string} id @param {Record<string, any>} data */
	updateChannel: (id, data) => request('PATCH', `/notifications/channels/${id}`, { body: data }),
	/** @param {string} id */
	deleteChannel: (id) => request('DELETE', `/notifications/channels/${id}`),
	/** @param {string} id */
	testChannel: (id) => request('POST', `/notifications/channels/${id}/test`),
	listDeliveries: () => request('GET', '/notifications/deliveries').then((d) => d.deliveries ?? []),
	// Queued deliveries not yet sent (new, or failed and waiting for a retry).
	listPendingDeliveries: () => request('GET', '/notifications/pending').then((d) => d.pending ?? []),

	// --- api tokens ---
	listTokens: () => request('GET', '/tokens').then((d) => d.tokens ?? []),
	/** @param {Record<string, any>} data */
	createToken: (data) => request('POST', '/tokens', { body: data }),
	// Confirms the password (+ two-factor code) and returns a freshly
	// authenticated session ({ token, user }); store the token before retrying.
	/** @param {string} password @param {string} [code] */
	reauth: (password, code = '') => request('POST', '/me/reauth', { body: { password, code } }),
	/** @param {string} tokenId */
	deleteToken: (tokenId) => request('DELETE', `/tokens/${tokenId}`),

	// --- service accounts + workload identity federation (admin) ---
	listServiceAccounts: () => request('GET', '/service-accounts').then((d) => d.service_accounts ?? []),
	/** @param {{name: string, description: string}} data */
	createServiceAccount: (data) => request('POST', '/service-accounts', { body: data }),
	/** @param {string} id @param {string} description */
	updateServiceAccount: (id, description) => request('PATCH', `/service-accounts/${id}`, { body: { description } }),
	/** @param {string} id */
	deleteServiceAccount: (id) => request('DELETE', `/service-accounts/${id}`),
	/** @param {string} id */
	suspendServiceAccount: (id) => request('POST', `/service-accounts/${id}/suspend`),
	/** @param {string} id */
	resumeServiceAccount: (id) => request('POST', `/service-accounts/${id}/resume`),
	/** @param {string} id */
	listServiceAccountKeys: (id) => request('GET', `/service-accounts/${id}/keys`).then((d) => d.keys ?? []),
	/** @param {string} id @param {{name: string, project_id: string | null, expires_in_days: number}} data */
	createServiceAccountKey: (id, data) => request('POST', `/service-accounts/${id}/keys`, { body: data }),
	/** @param {string} id @param {string} keyId */
	deleteServiceAccountKey: (id, keyId) => request('DELETE', `/service-accounts/${id}/keys/${keyId}`),
	listFederationIssuers: () => request('GET', '/federation/issuers').then((d) => d.issuers ?? []),
	/** @param {Record<string, any>} data */
	createFederationIssuer: (data) => request('POST', '/federation/issuers', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateFederationIssuer: (id, data) => request('PUT', `/federation/issuers/${id}`, { body: data }),
	/** @param {string} id */
	deleteFederationIssuer: (id) => request('DELETE', `/federation/issuers/${id}`),
	// { ok, error? }: runs OIDC discovery now.
	/** @param {string} id */
	testFederationIssuer: (id) => request('POST', `/federation/issuers/${id}/test`),
	listFederationBindings: () => request('GET', '/federation/bindings').then((d) => d.bindings ?? []),
	/** @param {Record<string, any>} data */
	createFederationBinding: (data) => request('POST', '/federation/bindings', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateFederationBinding: (id, data) => request('PUT', `/federation/bindings/${id}`, { body: data }),
	/** @param {string} id */
	deleteFederationBinding: (id) => request('DELETE', `/federation/bindings/${id}`),

	// --- enrichment ---
	enrich: () => request('POST', '/enrich'),

	// --- private advisories (mutations admin) + vulnerability sources (admin) ---
	/** @param {Record<string, any>} [filters] */
	listAdvisories: (filters = {}) => request('GET', '/advisories', { query: filters }),
	/** @param {string} id */
	getAdvisory: (id) => request('GET', `/advisories/${encodeURIComponent(id)}`),
	/** @param {Record<string, any>} data */
	createAdvisory: (data) => request('POST', '/advisories', { body: data }),
	/** @param {string} id @param {Record<string, any>} data */
	updateAdvisory: (id, data) => request('PUT', `/advisories/${encodeURIComponent(id)}`, { body: data }),
	/** @param {string} id */
	deleteAdvisory: (id) => request('DELETE', `/advisories/${encodeURIComponent(id)}`),
	// OSV JSON text: one document or an array.
	/** @param {string} osvJSON */
	importAdvisories: (osvJSON) => upload('/advisories/import', osvJSON),
	vulnSources: () => request('GET', '/vulnmatch/sources'),
	runVulnMatch: () => request('POST', '/vulnmatch'),
	/** @param {Blob} file */
	importOSVExport: (file) => sendFile('/vulnmatch/osv-import', file)
};
