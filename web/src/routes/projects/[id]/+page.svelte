<script>
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify, me, features, isOn } from '#lib/stores.js';
	import { handleListKey, createListCursor, isExceptionStatus, scrollCursorIntoView } from '#lib/keyboard.js';
	import TriageDialog from '#lib/components/TriageDialog.svelte';
	import KeyboardHelp from '#lib/components/KeyboardHelp.svelte';
	import StatusCell from '#lib/components/StatusCell.svelte';
	import { criticalityClass, severityClass, riskTone, fmtDate, fmtNumber, SEVERITIES, STATUSES, CATEGORIES, SLA_STATUSES } from '#lib/format.js';
	import { t, labelOf, contentLocale } from '#lib/i18n.js';
	import { SCAN_PRESETS } from '#lib/scanners.js';
	import { CHANNEL_TYPES, EVENT_TYPES, channelHint, channelPlaceholder, channelInputType, describeRules } from '#lib/channels.js';
	import Badge from '#lib/components/Badge.svelte';
	import SlaBadge from '#lib/components/SlaBadge.svelte';
	import SlaPolicyEditor from '#lib/components/SlaPolicyEditor.svelte';
	import IssueTrackerEditor from '#lib/components/IssueTrackerEditor.svelte';
	import ConnectorsEditor from '#lib/components/ConnectorsEditor.svelte';
	import VulnBadge from '#lib/components/VulnBadge.svelte';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import TrendChart from '#lib/components/TrendChart.svelte';
	import ExportMenu from '#lib/components/ExportMenu.svelte';
	import LicenseBadge from '#lib/components/LicenseBadge.svelte';
	import OutdatedBadge from '#lib/components/OutdatedBadge.svelte';
	import IntegrityBadge from '#lib/components/IntegrityBadge.svelte';
	import AIBadge from '#lib/components/AIBadge.svelte';
	import ReportMenu from '#lib/components/ReportMenu.svelte';
	import EngagementsEditor from '#lib/components/EngagementsEditor.svelte';
	import RiskAcceptances from '#lib/components/RiskAcceptances.svelte';
	import ManualFindingDialog from '#lib/components/ManualFindingDialog.svelte';
	import BadgesCard from '#lib/components/BadgesCard.svelte';
	import FixPlan from '#lib/components/FixPlan.svelte';
	import Remediation from '#lib/components/Remediation.svelte';
	import ExploitBadge from '#lib/components/ExploitBadge.svelte';
	import ExposureBadge from '#lib/components/ExposureBadge.svelte';
	import AssetDetail from '#lib/components/AssetDetail.svelte';
	import CraCases from '#lib/components/CraCases.svelte';
	import AccessTable from '#lib/components/AccessTable.svelte';
	import CustomFieldsEditor from '#lib/components/CustomFieldsEditor.svelte';
	import ManualControls from '#lib/components/ManualControls.svelte';
	import { OPEN_BY_SEVERITY, RISK, FLOW, fmtCount, fmtRisk, windowStats } from '#lib/trends.js';
	import { parentChoices } from '#lib/projectTree.js';

	const id = $derived(/** @type {string} */ (page.params.id)); // the [id] route always has it

	let project = $state(/** @type {any} */ (null));
	// Hierarchy: the visible ancestors (root first) for the breadcrumb, the
	// direct children, and whether rollups include the descendants (null =
	// the server default: a collection includes them).
	let ancestors = $state(/** @type {any[]} */ ([]));
	let children = $state(/** @type {any[]} */ ([]));
	let includeChildren = $state(/** @type {boolean | null} */ (null));
	const rollingUp = $derived(includeChildren ?? !!project?.is_collection);
	/** The include_children query of every rollup on this page. @returns {Record<string, boolean>} */
	const rollupQuery = () => (includeChildren === null ? {} : { include_children: includeChildren });
	/** @param {Event} e */
	async function toggleChildren(e) {
		includeChildren = /** @type {HTMLInputElement} */ (e.target).checked;
		for (const t of ['components', 'policies', 'trends']) loaded[t] = false;
		await Promise.all([loadHeader(), reloadFindings()]);
		if (['components', 'policies', 'trends'].includes(tab)) await switchTab(tab);
	}
	// Edit dialog: details, parent and collection.
	/** @type {HTMLDialogElement} */
	let editDialog;
	let editForm = $state({ name: '', repo_url: '', business_criticality: 'medium', parent_id: '', is_collection: false });
	let editProjects = $state(/** @type {any[]} */ ([]));
	let editTeams = $state(/** @type {any[]} */ ([]));
	const editParents = $derived(project ? parentChoices(editProjects, editTeams, project.team_id, project.id) : []);
	async function openEdit() {
		editForm = {
			name: project.name, repo_url: project.repo_url ?? '', business_criticality: project.business_criticality,
			parent_id: project.parent_id ?? '', is_collection: !!project.is_collection
		};
		editDialog.showModal();
		try {
			[editProjects, editTeams] = await Promise.all([api.listProjects(), api.listTeams()]);
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	/** @param {SubmitEvent} e */
	async function saveEdit(e) {
		e.preventDefault();
		/** @type {Record<string, any>} */
		const body = { name: editForm.name, repo_url: editForm.repo_url, business_criticality: editForm.business_criticality };
		if ((editForm.parent_id || null) !== (project.parent_id ?? null)) body.parent_id = editForm.parent_id || null;
		if (editForm.is_collection !== !!project.is_collection) body.is_collection = editForm.is_collection;
		try {
			await api.updateProject(id, body);
			editDialog.close();
			notify($t('proj.saved'), 'success');
			await loadHeader();
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.moveForbidden') : errorMessage(err));
		}
	}
	let summary = $state(/** @type {any} */ (null));
	let serviceSummary = $state(/** @type {any} */ (null)); // declared services of the current SBOMs (default version)
	let error = $state('');

	const TABS = ['findings', 'fix-plan', 'remediation', 'trends', 'branches', 'scans', 'engagements', 'acceptances', 'sboms', 'components', 'policies', 'vex', 'assets', 'compliance', 'gate', 'sla', 'issues', 'connectors', 'alerts', 'members'];
	// Tabs that belong to a switchable feature (hidden while it is off).
	/** @type {Record<string, string>} */
	const TAB_FEATURE = { remediation: 'remediation', engagements: 'engagements' };
	const visibleTabs = $derived(TABS.filter((tb) => !TAB_FEATURE[tb] || isOn($features, TAB_FEATURE[tb])));
	let manualDialog = $state();
	const urlTab = page.url.searchParams.get('tab');
	let tab = $state(urlTab && TABS.includes(urlTab) ? urlTab : 'findings');

	// per-tab state
	let findings = $state(/** @type {any[]} */ ([]));
	let fMeta = $state(/** @type {any} */ (null));
	let trend = $state(/** @type {any[]} */ ([])); // 90-day daily metric points (default branch)
	const trendStats = $derived(windowStats(trend));
	let fOffset = $state(0);
	// version: '' = the default branch; 'all' = every branch; else a version id.
	let fFilters = $state({ severity: '', status: '', category: '', sla: '', version: '' });
	// Branches / releases. Loaded with the header: the findings filter, scan and
	// SBOM tables and the Branches tab all label versions from it.
	let versions = $state(/** @type {any[]} */ ([]));
	/** @param {string} vid */
	const versionName = (vid) => versions.find((v) => v.id === vid)?.name ?? '';
	const defaultVersion = $derived(versions.find((v) => v.is_default));
	/** @param {any} v */
	async function makeDefault(v) {
		try {
			await api.setDefaultVersion(id, v.id);
			notify($t('proj.defaultChanged', { name: v.name }), 'success');
			await Promise.all([loadHeader(), loadFindings()]);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.ownerDefault') : errorMessage(err));
		}
	}
	/** @param {any} v */
	async function removeVersion(v) {
		if (!confirm($t('proj.confirmDeleteVersion', { kind: v.kind === 'release' ? $t('proj.kind.release') : $t('proj.kind.branch'), name: v.name, scans: v.scans, sboms: v.sboms }))) return;
		try {
			await api.deleteVersion(id, v.id);
			notify($t('proj.deleted', { name: v.name }), 'success');
			versions = await api.listVersions(id);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.ownerDeleteBranch') : errorMessage(err));
		}
	}
	let fLoading = $state(false);

	// Filter change resets to the first page; pagination just moves the offset.
	function reloadFindings() {
		fOffset = 0;
		loadFindings();
	}
	/** @param {number} offset */
	function goFindings(offset) {
		fOffset = offset;
		loadFindings();
	}

	let scans = $state(/** @type {any[]} */ ([]));
	let sboms = $state(/** @type {any[]} */ ([]));
	let components = $state(/** @type {any[]} */ ([]));
	let compSearch = $state('');
	let compExact = $state(false);
	let compVulnerable = $state('');
	let compOutdated = $state('');
	let compKind = $state('');
	let assets = $state(/** @type {any[]} */ ([]));
	let projectPolicies = $state(/** @type {any[]} */ ([]));
	/** @type {Record<string, string>} */
	const POLICY_TONE = { fail: 'badge-error', warn: 'badge-warning', info: 'badge-info' };
	let compliance = $state(/** @type {any[]} */ ([]));
	let alertChannels = $state(/** @type {any[]} */ ([]));
	let alertForm = $state({ name: '', type: 'slack', url: '', events: '*', min_severity: '', filter: '', summary: 'none' });
	let alertTesting = $state('');
	let slaPolicy = $state(/** @type {any} */ (null));
	async function loadSla() {
		slaPolicy = await api.slaPolicy(id);
	}
	// Saving or resetting re-dates the project's findings server-side, so the
	// header stats and the findings list are refreshed with it.
	/** @param {any} days */
	async function saveSla(days) {
		try {
			slaPolicy = await api.setSlaPolicy(id, days);
			notify($t('proj.slaSaved'), 'success');
			await Promise.all([loadHeader(), loadFindings()]);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.ownerSla') : errorMessage(err));
		}
	}
	async function resetSla() {
		try {
			await api.deleteSlaPolicy(id);
			await loadSla();
			notify($t('proj.slaRemoved'), 'success');
			await Promise.all([loadHeader(), loadFindings()]);
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.ownerSla') : errorMessage(err));
		}
	}
	let gatePolicy = $state(/** @type {any} */ (null));
	let gateScope = $state('none');
	let gateResult = $state(/** @type {any} */ (null));
	let gateRunning = $state(false);
	let tabLoading = $state(false);
	let loaded = $state(/** @type {Record<string, boolean>} */ ({}));

	// Project members: access to THIS project, without joining its team.
	let members = $state(/** @type {any[]} */ ([]));
	// Who can reach the project at all, and why (owners only; loaded on demand).
	let access = $state(/** @type {any[] | null} */ (null));
	// Whether I watch this project (personal notifications).
	let watching = $state(false);
	let watchBusy = $state(false);
	$effect(() => {
		if (id && isOn($features, 'personal_notifications')) api.watchingProject(id).then((w) => (watching = w)).catch(() => {});
	});
	async function toggleWatch() {
		watchBusy = true;
		try {
			watching = await api.watchProject(id, !watching);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			watchBusy = false;
		}
	}
	// Archive instead of delete: the project leaves every view until restored.
	let archiveBusy = $state(false);
	async function setArchived(/** @type {boolean} */ archived) {
		if (archived && !confirm($t('proj.archiveConfirm', { name: project.name }))) return;
		archiveBusy = true;
		try {
			if (archived) await api.archive('projects', id);
			else await api.restore('projects', id);
			project = await api.getProject(id);
			summary = await api.projectSummary(id);
			notify(archived ? $t('proj.archivedToast') : $t('proj.restoredToast'), 'success');
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('proj.archiveForbidden') : errorMessage(err));
		} finally {
			archiveBusy = false;
		}
	}
	let accessError = $state('');
	let accessLoading = $state(false);
	async function loadAccess() {
		accessLoading = true;
		accessError = '';
		try {
			access = (await api.projectAccess(id, { limit: 200 })).entries ?? [];
		} catch (err) {
			accessError = err instanceof ApiError && err.status === 403
				? $t('proj.ownersAccess')
				: errorMessage(err);
		} finally {
			accessLoading = false;
		}
	}
	let memberForm = $state({ kind: 'user', email: '', group_id: '', role: 'viewer', custom_role_id: '' });
	let memberBusy = $state(false);
	// The project's org's groups and custom roles, for the grant form (empty
	// when the caller can't list them).
	let orgGroups = $state(/** @type {any[]} */ ([]));
	let orgRoles = $state(/** @type {any[]} */ ([]));
	async function loadGrantOptions() {
		try {
			const team = (await api.listTeams()).find((/** @type {any} */ tm) => tm.id === project?.team_id);
			if (!team) return;
			[orgGroups, orgRoles] = await Promise.all([
				api.listGroups(team.org_id).catch(() => []),
				api.listCustomRoles(team.org_id).catch(() => [])
			]);
		} catch {
			/* the form still grants users */
		}
	}

	/** @param {SubmitEvent} e */
	async function addMember(e) {
		e.preventDefault();
		memberBusy = true;
		try {
			/** @type {{ email?: string, group_id?: string, role: string, custom_role_id?: string }} */
			const grant = { role: memberForm.role };
			if (memberForm.kind === 'group') grant.group_id = memberForm.group_id;
			else grant.email = memberForm.email.trim().toLowerCase();
			if (memberForm.custom_role_id) grant.custom_role_id = memberForm.custom_role_id;
			await api.addProjectMember(id, grant);
			memberForm = { kind: memberForm.kind, email: '', group_id: '', role: 'viewer', custom_role_id: '' };
			members = await api.listProjectMembers(id);
			notify($t('proj.accessGranted'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			memberBusy = false;
		}
	}

	/** @param {any} m */
	async function removeMember(m) {
		try {
			if (m.group_id) {
				await api.removeProjectGroup(id, m.group_id);
				notify($t('proj.accessRevoked'), 'success');
				members = await api.listProjectMembers(id);
				return;
			}
			const res = await api.removeProjectMember(id, m.user_id);
			// The API tells us honestly when the user still reaches the project
			// through its team — the grant is gone, the access isn't.
			if (res?.still_has_access) {
				notify(
					$t('proj.stillReaches', { email: m.email, role: $labelOf('role', res.effective_role) }),
					'warning'
				);
			} else {
				notify($t('proj.accessRevoked'), 'success');
			}
			members = await api.listProjectMembers(id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// VEX: the team's analysis of which vulnerabilities actually apply.
	let vexStatements = $state(/** @type {any[]} */ ([]));
	/** @type {HTMLDialogElement} */
	let vexDialog;
	let vexForm = $state({ raw: '' });

	/** @param {SubmitEvent} e */
	async function submitVex(e) {
		e.preventDefault();
		saving = true;
		try {
			const res = await api.uploadVex(id, vexForm.raw);
			vexDialog.close();
			vexForm = { raw: '' };
			const n = res.findings_resolved ?? 0;
			notify($t('proj.vexApplied', { count: n }), 'success');
			loaded.vex = false;
			await Promise.all([switchTab('vex'), loadHeader(), loadFindings()]);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {string} sid */
	async function removeVex(sid) {
		try {
			await api.deleteVex(sid);
			vexStatements = vexStatements.filter((v) => v.id !== sid);
			notify($t('proj.statementRemoved'), 'success');
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// Export: the project's analysis (triage + statements) as a VEX document.
	const VEX_FORMATS = [
		{ value: 'openvex', label: 'OpenVEX', ext: 'openvex.json' },
		{ value: 'cyclonedx', label: 'CycloneDX 1.6 VEX', ext: 'vex.cdx.json' },
		{ value: 'cyclonedx@1.7', label: 'CycloneDX 1.7 VEX', ext: 'vex.cdx.json' },
		{ value: 'csaf', label: 'CSAF 2.0 VEX', ext: 'csaf.json' },
	];
	let vexExport = $state({ format: 'openvex', version: '' });
	let exportingVex = $state(false);

	async function exportVex() {
		exportingVex = true;
		try {
			const fmt = /** @type {(typeof VEX_FORMATS)[number]} */ (VEX_FORMATS.find((f) => f.value === vexExport.format));
			const branch = (vexExport.version ? versionName(vexExport.version) : defaultVersion?.name) || 'main';
			const filename = `${project?.slug ?? 'project'}-${branch.replaceAll('/', '_')}.${fmt.ext}`;
			const [format, spec] = vexExport.format.split('@');
			await api.exportVex(id, format, vexExport.version, filename, spec ?? '');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			exportingVex = false;
		}
	}

	async function loadGate() {
		const { policy, scope } = await api.gatePolicy(id);
		gateScope = scope;
		gatePolicy = {
			max_critical: policy.max_critical ?? null,
			max_high: policy.max_high ?? null,
			block_kev: policy.block_kev ?? false,
			max_epss: policy.max_epss ?? null,
			block_license: policy.block_license ?? false,
			block_sla_breach: policy.block_sla_breach ?? false,
			new_only: policy.new_only ?? false,
			baseline_branch: policy.baseline_branch ?? '',
			max_risk_score: policy.max_risk_score ?? null
		};
		await runGate();
	}
	async function runGate() {
		gateRunning = true;
		try {
			gateResult = await api.runGate(id);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			gateRunning = false;
		}
	}
	async function saveGate() {
		saving = true;
		try {
			/** @type {Record<string, any>} */
			const body = {};
			for (const k of ['max_critical', 'max_high', 'max_epss', 'max_risk_score']) {
				body[k] = gatePolicy[k] === '' || gatePolicy[k] === null ? null : Number(gatePolicy[k]);
			}
			body.block_kev = gatePolicy.block_kev;
			body.block_license = gatePolicy.block_license;
			body.block_sla_breach = gatePolicy.block_sla_breach;
			body.new_only = gatePolicy.new_only;
			body.baseline_branch = gatePolicy.baseline_branch.trim() === '' ? null : gatePolicy.baseline_branch.trim();
			await api.setGatePolicy(id, body);
			notify($t('proj.gateSaved'), 'success');
			await loadGate();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @type {HTMLDialogElement} */
	let assetDialog;
	let newAsset = $state({ type: 'container_image', name: '', identifier: '' });
	const ASSET_TYPES = ['repository', 'container_image', 'cloud_resource', 'host', 'kubernetes', 'serverless'];
	/** @type {HTMLDialogElement} */
	let assetDetailDialog;
	let detailAsset = $state(/** @type {any} */ (null));
	/** @param {any} a */
	function openAsset(a) {
		detailAsset = a;
		assetDetailDialog.showModal();
	}
	/** @param {any} updated */
	function assetChanged(updated) {
		assets = assets.map((a) => (a.id === updated.id ? updated : a));
		detailAsset = updated;
	}

	/** @type {HTMLDialogElement} */
	let scanDialog;
	/** @type {HTMLDialogElement} */
	let sbomDialog;
	let saving = $state(false);
	let scanForm = $state({ preset: 'trivy', scanner: '', format: '', branch: '', commit: '', asset_id: '', raw: '' });
	let sbomForm = $state({ artifact: '', version: '', raw: '' });

	const selectedPreset = $derived(SCAN_PRESETS.find((p) => p.id === scanForm.preset));

	let enriching = $state(false);
	async function enrichNow() {
		enriching = true;
		try {
			const res = await api.enrich();
			notify($t('proj.enriched', { count: res.enriched }), 'success');
			await loadFindings();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			enriching = false;
		}
	}

	/** @param {Event} e */
	async function readScanFile(e) {
		const file = /** @type {HTMLInputElement} */ (e.target).files?.[0];
		if (file) scanForm.raw = await file.text();
	}
	/** @param {Event} e */
	async function readSbomFile(e) {
		const file = /** @type {HTMLInputElement} */ (e.target).files?.[0];
		if (file) sbomForm.raw = await file.text();
	}

	/** @param {Event} e */
	async function readVexFile(e) {
		const file = /** @type {HTMLInputElement} */ (e.target).files?.[0];
		if (file) vexForm.raw = await file.text();
	}

	async function loadHeader() {
		try {
			[project, summary, versions, children] = await Promise.all([
				api.getProject(id), api.projectSummary(id, rollupQuery()), api.listVersions(id), api.projectChildren(id)
			]);
			// Walk up for the breadcrumb, stopping at an ancestor the caller can't read.
			/** @type {any[]} */
			const up = [];
			for (let pid = project.parent_id; pid && up.length < 5; ) {
				const a = await api.getProject(pid).catch(() => null);
				if (!a) break;
				up.unshift(a);
				pid = a.parent_id;
			}
			ancestors = up;
			// Best-effort: a project without SBOMs simply has no services.
			api.projectServices(id).then((r) => (serviceSummary = r.summary)).catch(() => (serviceSummary = null));
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('proj.loadFailed');
		}
	}

	// The findings tab's filter — what's listed, and what Export downloads.
	function findingQuery() {
		/** @type {Record<string, string | boolean>} */
		const filters = { sort: 'priority', ...rollupQuery() };
		for (const [k, v] of Object.entries(fFilters)) if (v && k !== 'version') filters[k] = v;
		if (fFilters.version === 'all') filters.all_versions = true;
		else if (fFilters.version) filters.version_id = fFilters.version;
		return filters;
	}

	async function loadFindings() {
		fLoading = true;
		fSelected = {};
		fCursor.reset();
		fEditing = '';
		try {
			const res = await api.listFindings(id, { ...findingQuery(), limit: 50, offset: fOffset });
			findings = res.findings ?? [];
			fMeta = res.pagination;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			fLoading = false;
		}
	}

	// Findings-table triage: row selection, keyboard cursor, inline status
	// edits. Keys are in #lib/keyboard.js; exception statuses always go through
	// the reason / expiry dialog.
	let fSelected = $state(/** @type {Record<string, boolean>} */ ({}));
	let fBusy = $state(''); // id of a finding being triaged
	let fBulkBusy = $state(false);
	let fCursor = $state(createListCursor());
	let fEditing = $state(''); // row whose status cell shows the <select>
	/** @type {TriageDialog} */
	let triageDialog;
	/** @type {KeyboardHelp} */
	let help;
	/** @type {HTMLInputElement | undefined} */
	let fSelectAllEl = $state();
	const fSelectedIds = $derived(findings.filter((f) => fSelected[f.id]).map((f) => f.id));
	const fAllSelected = $derived(findings.length > 0 && findings.every((f) => fSelected[f.id]));
	const fCursorRow = $derived(fCursor.index >= 0 ? findings[fCursor.index] : undefined);
	$effect(() => {
		if (fSelectAllEl) fSelectAllEl.indeterminate = fSelectedIds.length > 0 && !fAllSelected;
	});
	$effect(() => {
		if (fCursor.index >= 0) scrollCursorIntoView();
	});
	/** @param {string} status */
	const fMatches = (status) => !fFilters.status || fFilters.status === status;

	function fToggleAll() {
		const val = !fAllSelected;
		/** @type {Record<string, boolean>} */
		const next = {};
		if (val) for (const f of findings) next[f.id] = true;
		fSelected = next;
	}

	/** @param {string} status @returns {Promise<Record<string, unknown> | null>} reason/expiry, {} or null = cancelled */
	async function triageOptions(status, count = 1) {
		return isExceptionStatus(status) ? triageDialog.open(status, count) : {};
	}

	/** @param {any} f @param {number} at */
	function restoreFinding(f, at) {
		findings = findings.some((x) => x.id === f.id)
			? findings.map((x) => (x.id === f.id ? f : x))
			: [...findings.slice(0, at), f, ...findings.slice(at)];
	}

	// One row: optimistic, rolled back if the server refuses or holds it for approval.
	/** @param {any} f @param {string} status */
	async function triageFinding(f, status) {
		fEditing = '';
		if (f.status === status || fBusy === f.id) return;
		const opts = await triageOptions(status);
		if (!opts) return;
		const at = findings.findIndex((x) => x.id === f.id);
		if (at < 0) return;
		fBusy = f.id;
		findings = fMatches(status)
			? findings.map((x) => (x.id === f.id ? { ...x, status } : x))
			: findings.filter((x) => x.id !== f.id);
		try {
			const updated = await api.setFindingStatus(f.id, status, opts);
			if (updated?.state === 'pending' || updated?.state === 'requested') {
				// Held for approval (an assessment, or a risk acceptance request).
				restoreFinding(f, at);
				notify(updated.state === 'requested' ? $t('findings.raRequested') : $t('findings.forApproval'), 'success');
				return;
			}
			findings = findings.map((x) => (x.id === f.id ? { ...x, ...updated } : x));
			notify($t('findings.setTo', { status: $labelOf('status', status) }), 'success');
		} catch (err) {
			restoreFinding(f, at);
			notify(errorMessage(err));
		} finally {
			fBusy = '';
		}
	}

	// The selection: one bulk call, each finding authorized and logged server-side.
	/** @param {string} status */
	async function triageSelected(status) {
		const ids = fSelectedIds;
		if (ids.length === 0 || fBulkBusy) return;
		const opts = await triageOptions(status, ids.length);
		if (!opts) return;
		fBulkBusy = true;
		try {
			const res = await api.bulkUpdateFindings({ ids }, { status, ...opts });
			const ok = res.updated?.length ?? 0;
			const failed = res.failed?.length ?? 0;
			const held = (res.pending?.length ?? 0) + (res.acceptances?.length ?? 0);
			if (held > 0) notify($t('findings.submitted', { count: held }), failed ? 'error' : 'success');
			else if (failed === 0) notify($t('proj.bulkSet', { count: ok, status: $labelOf('status', status) }), 'success');
			else notify($t('findings.bulkPartial', { ok, failed }));
			const updated = Object.fromEntries((res.updated ?? []).map((/** @type {any} */ f) => [f.id, f]));
			findings = findings
				.filter((f) => !updated[f.id] || fMatches(updated[f.id].status))
				.map((f) => (updated[f.id] ? { ...f, ...updated[f.id] } : f));
			fSelected = {};
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			fBulkBusy = false;
		}
	}

	// `m`: the selection, else the cursor row — optimistic per finding.
	async function assignToMe() {
		const user = $me;
		if (!user) return notify($t('findings.whoAreYou'));
		const targets = (fSelectedIds.length ? findings.filter((f) => fSelected[f.id]) : fCursorRow ? [fCursorRow] : [])
			.filter((f) => f.assignee_id !== user.id);
		if (targets.length === 0) return;
		const before = new Map(targets.map((f) => [f.id, f]));
		findings = findings.map((x) => (before.has(x.id) ? { ...x, assignee_id: user.id, assignee_email: user.email } : x));
		const results = await Promise.allSettled(targets.map((f) => api.assignFinding(f.id, user.id)));
		const failed = targets.filter((_, i) => results[i].status === 'rejected');
		if (failed.length) {
			findings = findings.map((x) => (failed.some((f) => f.id === x.id) ? /** @type {any} */ (before.get(x.id)) : x));
			const first = /** @type {PromiseRejectedResult} */ (results.find((r) => r.status === 'rejected'));
			notify(errorMessage(first.reason));
		} else notify($t('proj.assignedMany', { count: targets.length }), 'success');
	}

	/** @param {KeyboardEvent} e */
	function onFindingsKey(e) {
		if (tab !== 'findings' || fLoading) return;
		handleListKey(e, {
			move: (d) => fCursor.move(d, findings.length),
			toggle: (range) => {
				if (!fCursorRow) return;
				if (range) {
					const [lo, hi] = fCursor.range();
					const next = { ...fSelected };
					for (const f of findings.slice(lo, hi + 1)) next[f.id] = true;
					fSelected = next;
				} else fSelected[fCursorRow.id] = !fSelected[fCursorRow.id];
				fCursor.mark(fCursor.index);
			},
			open: () => fCursorRow && goto(`/findings/${fCursorRow.id}`),
			triage: (status) => {
				if (fSelectedIds.length > 0) triageSelected(status);
				else if (fCursorRow) triageFinding(fCursorRow, status);
			},
			assignMe: assignToMe,
			editStatus: () => fCursorRow && (fEditing = fCursorRow.id),
			escape: () => {
				fSelected = {};
				fEditing = '';
			}
		});
	}

	/** @param {string} name */
	async function switchTab(name) {
		tab = name;
		goto('?tab=' + name, { shallow: true, replace: true }); // deep-link + survive reload
		if (loaded[name]) return;
		tabLoading = true;
		try {
			if (name === 'scans') scans = await api.listScans(id);
			else if (name === 'sboms') sboms = await api.listSboms(id);
			else if (name === 'vex') vexStatements = await api.listVex(id);
			else if (name === 'members') {
				members = await api.listProjectMembers(id);
				loadGrantOptions();
			}
			else if (name === 'components') {
				const res = await api.projectComponents(id, { ...componentQuery(), limit: 200 });
				components = res.components ?? [];
			} else if (name === 'assets') assets = await api.listAssets(id);
			else if (name === 'policies') projectPolicies = await api.projectPolicies(id, rollupQuery());
			else if (name === 'compliance') compliance = await api.projectCompliance(id);
			else if (name === 'alerts') alertChannels = await api.listChannels(id);
			else if (name === 'gate') await loadGate();
			else if (name === 'sla') await loadSla();
			else if (name === 'branches') versions = await api.listVersions(id);
			else if (name === 'trends') trend = await api.projectTrends(id, 90, rollupQuery());
			loaded[name] = true;
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			tabLoading = false;
		}
	}

	// The components tab's filter — what's listed, and what Export downloads.
	function componentQuery() {
		/** @type {Record<string, string | boolean>} */
		const filters = { latest: true, ...rollupQuery() };
		if (compSearch) filters[compExact ? 'name' : 'search'] = compSearch;
		if (compVulnerable) filters.vulnerable = compVulnerable;
		if (compOutdated) filters.outdated = compOutdated;
		if (compKind) filters.kind = compKind;
		return filters;
	}

	async function searchComponents() {
		tabLoading = true;
		try {
			const res = await api.projectComponents(id, { ...componentQuery(), limit: 200 });
			components = res.components ?? [];
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			tabLoading = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function createAsset(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.createAsset(id, { ...newAsset });
			assetDialog.close();
			newAsset = { type: 'container_image', name: '', identifier: '' };
			notify($t('proj.assetRegistered'), 'success');
			loaded.assets = false;
			await switchTab('assets');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function createAlert(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.createChannel({
				name: alertForm.name,
				type: alertForm.type,
				url: alertForm.url,
				events: alertForm.events === '*' ? ['*'] : [alertForm.events],
				project_id: id,
				min_severity: alertForm.min_severity,
				filter: alertForm.filter,
				summary: alertForm.summary
			});
			alertForm = { name: '', type: 'slack', url: '', events: '*', min_severity: '', filter: '', summary: 'none' };
			notify($t('proj.alertAdded'), 'success');
			alertChannels = await api.listChannels(id);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}
	/** @param {any} ch */
	async function testAlert(ch) {
		alertTesting = ch.id;
		try {
			await api.testChannel(ch.id);
			notify($t('notif.testSent', { name: ch.name }), 'success');
		} catch (err) {
			notify($t('notif.testFailed', { error: errorMessage(err) }));
		} finally {
			alertTesting = '';
		}
	}
	/** @param {any} ch */
	async function deleteAlert(ch) {
		if (!confirm($t('notif.confirmDelete', { name: ch.name }))) return;
		try {
			await api.deleteChannel(ch.id);
			alertChannels = await api.listChannels(id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// Load assets so the scan modal can offer them for attribution.
	async function openScan() {
		if (!loaded.assets) assets = await api.listAssets(id).catch(() => []);
		scanDialog.showModal();
	}

	/** @param {SubmitEvent} e */
	async function submitScan(e) {
		e.preventDefault();
		const custom = scanForm.preset === 'custom';
		const scanner = custom ? scanForm.scanner.trim() : selectedPreset?.scanner;
		const format = custom ? scanForm.format.trim() : selectedPreset?.format;
		if (!scanner) {
			notify($t('proj.pickScanner'));
			return;
		}
		saving = true;
		try {
			const sc = await api.uploadScan(id, scanner, scanForm.raw, {
				branch: scanForm.branch,
				commit: scanForm.commit,
				asset_id: scanForm.asset_id,
				format
			});
			scanDialog.close();
			scanForm = { preset: 'trivy', scanner: '', format: '', branch: '', commit: '', asset_id: '', raw: '' };
			loaded.assets = false;
			notify($t('proj.scanIngested', { status: sc.status }), 'success');
			loaded.scans = false;
			await Promise.all([loadFindings(), switchTab('scans'), loadHeader()]);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function submitSbom(e) {
		e.preventDefault();
		saving = true;
		try {
			const { artifact, version, raw } = sbomForm;
			await api.uploadSbom(id, raw, { artifact, version });
			sbomDialog.close();
			sbomForm = { artifact: '', version: '', raw: '' };
			notify($t('proj.sbomUploaded'), 'success');
			loaded.sboms = false;
			loaded.components = false;
			await Promise.all([switchTab('sboms'), loadHeader(), loadFindings()]);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	// Keyed on the route id, not just on mount: navigating from one project to
	// another reuses this component, and an onMount-only fetch would keep showing
	// the project you came from.
	$effect(() => {
		const projectID = id;
		loaded = {}; // per-tab caches belong to the project we came from
		(async () => {
			await loadHeader();
			await loadFindings();
			if (id !== projectID) return; // superseded by a newer navigation
			loaded.findings = true;
			if (tab !== 'findings') await switchTab(tab); // load a deep-linked tab
		})();
	});
	async function reloadCompliance() {
		try {
			compliance = await api.projectCompliance(id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<svelte:window onkeydown={onFindingsKey} />

<div class="breadcrumbs text-sm text-base-content/60 py-0">
	<ul>
		<li><a href="/" class="hover:text-base-content">{$t('home.title')}</a></li>
		{#each ancestors as a (a.id)}<li><a href={`/projects/${a.id}`} class="hover:text-base-content">{a.name}</a></li>{/each}
		{#if project}<li>{project.name}</li>{/if}
	</ul>
</div>

{#if error}
	<div class="alert alert-error mt-4"><span>{error}</span></div>
{:else if project}
	{#if project.archived_at}
		<div class="alert alert-warning mt-2">
			<span>{$t('proj.archivedBanner', { date: fmtDate(project.archived_at) })}</span>
			<button class="btn btn-sm" onclick={() => setArchived(false)} disabled={archiveBusy}>{$t('common.restore')}</button>
		</div>
	{/if}
	<div class="flex flex-wrap items-center justify-between gap-3 mt-2 mb-5">
		<div>
			<h1 class="text-2xl font-bold flex items-center gap-2">
				{project.name}
				<span class="badge {criticalityClass(project.business_criticality)} capitalize"
					>{$labelOf('criticality', project.business_criticality)}</span
				>
				{#if project.is_collection}<span class="badge badge-ghost" title={$t('proj.collectionBadgeTitle')}>{$t('proj.collection')}</span>{/if}
			</h1>
			<p class="text-sm text-base-content/60">
				{project.slug}{#if project.repo_url} · <a class="link" href={project.repo_url}>{project.repo_url}</a>{/if}
			</p>
		</div>
		<div class="flex gap-2">
			{#if isOn($features, 'personal_notifications')}
				<button class="btn btn-sm" class:btn-active={watching} onclick={toggleWatch} disabled={watchBusy}
					title={watching ? $t('proj.watchingTitle') : $t('proj.watchTitle')}>
					{watching ? $t('proj.watching') : $t('proj.watch')}
				</button>
			{/if}
			<ReportMenu open={(opts) => api.openProjectReport(id, opts)} />
			<button class="btn btn-sm btn-ghost" onclick={openEdit}>{$t('common.edit')}</button>
			{#if !project.is_collection}
				<button class="btn btn-sm btn-outline" onclick={() => sbomDialog.showModal()}>{$t('proj.uploadSbom')}</button>
				<button class="btn btn-sm btn-primary" onclick={openScan}>{$t('proj.uploadScan')}</button>
			{/if}
			{#if !project.archived_at}
				<button class="btn btn-sm btn-ghost text-error" onclick={() => setArchived(true)} disabled={archiveBusy}>{$t('common.archive')}</button>
			{/if}
		</div>
	</div>

	{#if children.length > 0}
		<div class="flex flex-wrap items-center gap-2 mb-3 text-sm">
		<label class="label cursor-pointer gap-2 py-0" title={$t('proj.rollupTitle')}>
			<input type="checkbox" class="toggle toggle-sm" checked={rollingUp} onchange={toggleChildren} />
			<span>{$t('proj.includeChildren')}</span>
			</label>
			<span class="text-base-content/50">·</span>
			{#each children as ch (ch.id)}<a class="badge badge-outline hover:badge-primary" href={`/projects/${ch.id}`}>{ch.name}</a>{/each}
		</div>
	{/if}

	{#if summary}
		<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100 w-full mb-6">
			<div class="stat">
				<div class="stat-title">{$t('home.statRisk')}</div>
				<div class="stat-value {riskTone(summary.risk_score)}">{fmtNumber(Math.round(summary.risk_score))}</div>
				<div class="stat-desc">{$t('proj.weighted')}</div>
			</div>
			<div class="stat">
				<div class="stat-title">{$t('home.statOpen')}</div>
				<div class="stat-value">{fmtNumber(summary.total_open)}</div>
				<div class="stat-desc">{$t('proj.total', { count: summary.total })}</div>
			</div>
			<div class="stat">
				<div class="stat-title">{$t('proj.bySeverity')}</div>
				<div class="stat-desc pt-2 flex flex-wrap gap-1">
					{#each SEVERITIES as sev}
						{#if summary.open_by_severity?.[sev]}
							<span class="badge badge-sm whitespace-nowrap capitalize {severityClass(sev)}">{$labelOf('severity', sev)}: {fmtNumber(summary.open_by_severity[sev])}</span>
						{/if}
					{/each}
					{#if !summary.total_open}<span class="text-success">{$t('home.allClear')}</span>{/if}
				</div>
			</div>
			{#if summary.sla}
				<a href={`/findings?project_id=${id}&sla=breached&sort=sla_due`} class="stat hover:bg-base-200 transition-colors">
					<div class="stat-title">{$t('home.statSla')}</div>
					<div class="stat-value {summary.sla.breached ? 'text-error' : 'text-success'}">{fmtNumber(summary.sla.breached)}</div>
					<div class="stat-desc">
						{$t('home.statDueSoon', { count: summary.sla.due_soon })}{#if summary.sla.compliance !== null} · {$t('proj.fixedOnTime', { percent: Math.round(summary.sla.compliance * 100) })}{/if}
					</div>
				</a>
			{/if}
			{#if serviceSummary?.total}
				<button class="stat text-left hover:bg-base-200 transition-colors" onclick={() => switchTab('sboms')} title={$t('proj.servicesTitle')}>
					<div class="stat-title">{$t('proj.services')}</div>
					<div class="stat-value">{fmtNumber(serviceSummary.total)}</div>
					<div class="stat-desc flex flex-wrap gap-1">
						{#if serviceSummary.unauthenticated_external}<span class="text-error">{$t('proj.unauthExternal', { count: serviceSummary.unauthenticated_external })}</span>{/if}
						{#if serviceSummary.crosses_trust_boundary}<span class="text-warning">{$t('proj.crossTrust', { count: serviceSummary.crosses_trust_boundary })}</span>{/if}
						{#if !serviceSummary.unauthenticated_external && !serviceSummary.crosses_trust_boundary}<span>{$t('proj.declared')}</span>{/if}
					</div>
				</button>
			{/if}
		</div>
	{/if}

	{#if isOn($features, 'custom_fields')}
		<div class="mb-4">
			<CustomFieldsEditor kind="projects" id={project.id} projectId={project.id} values={project.custom} canEdit
				onsaved={(v) => (project = { ...project, custom: v })} />
		</div>
	{/if}

	<!-- Tabs -->
	<div role="tablist" class="tabs tabs-bordered mb-4">
		{#each visibleTabs as tb}
			<button
				role="tab"
				class="tab"
				class:tab-active={tab === tb}
				onclick={() => switchTab(tb)}>{$t(/** @type {import('#lib/i18n.js').MessageKey} */ (`proj.tab.${tb}`))}</button
			>
		{/each}
	</div>

	{#if tab === 'findings'}
		<div class="flex flex-wrap items-center gap-2 mb-3">
			<select bind:value={fFilters.severity} onchange={reloadFindings} class="select select-bordered select-sm">
				<option value="">{$t('findings.allSeverities')}</option>
				{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
			</select>
			<select bind:value={fFilters.status} onchange={reloadFindings} class="select select-bordered select-sm">
				<option value="">{$t('findings.allStatuses')}</option>
				{#each STATUSES as s}<option value={s}>{$labelOf('status', s)}</option>{/each}
			</select>
			<select bind:value={fFilters.category} onchange={reloadFindings} class="select select-bordered select-sm">
				<option value="">{$t('findings.allCategories')}</option>
				{#each CATEGORIES as c}<option value={c}>{$labelOf('category', c)}</option>{/each}
			</select>
			{#if versions.length > 1}
				<select bind:value={fFilters.version} onchange={reloadFindings} class="select select-bordered select-sm" title={$t('proj.versionTitle')}>
					<option value="">{defaultVersion ? $t('proj.defaultSuffix', { name: defaultVersion.name }) : $t('proj.defaultBranch')}</option>
					{#each versions.filter((v) => !v.is_default) as v (v.id)}<option value={v.id}>{v.kind === 'release' ? '🏷 ' : ''}{v.name}</option>{/each}
					<option value="all">{$t('findings.allBranches')}</option>
				</select>
			{/if}
			<select bind:value={fFilters.sla} onchange={reloadFindings} class="select select-bordered select-sm">
				<option value="">{$t('findings.anySla')}</option>
				{#each SLA_STATUSES as v}<option value={v}>{$labelOf('sla', v)}</option>{/each}
			</select>
			<button class="btn btn-sm btn-outline ml-auto" onclick={() => manualDialog.open()} title={$t('proj.reportTitle')}>{$t('proj.reportFinding')}</button>
			<button class="btn btn-sm btn-outline" onclick={enrichNow} disabled={enriching}
				title={$t('proj.refreshTitle')}>
				{#if enriching}<span class="loading loading-spinner loading-xs"></span>{/if}
				{$t('proj.refresh')}
			</button>
			<ExportMenu run={(/** @type {string} */ format) => api.exportProjectFindings(id, findingQuery(), format)} />
		</div>

		<State loading={fLoading} empty={!fLoading && findings.length === 0}
			emptyText={$t('proj.findingsEmpty')} />

		{#if !fLoading && findings.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead>
						<tr>
							<th class="w-8">
								<input bind:this={fSelectAllEl} type="checkbox" class="checkbox checkbox-sm" checked={fAllSelected} onchange={fToggleAll} aria-label={$t('findings.selectAll')} />
							</th>
							<th>{$t('findings.colPriority')}</th><th>{$t('findings.colSeverity')}</th><th>{$t('findings.colTitle')}</th><th>{$t('findings.colPackage')}</th><th>{$t('findings.colScanner')}</th><th>{$t('findings.colStatus')}</th><th>{$t('findings.colSla')}</th><th>{$t('findings.colOwner')}</th>{#if fFilters.version === 'all'}<th>{$t('proj.colBranch')}</th>{/if}
						</tr>
					</thead>
					<tbody>
						{#each findings as f, i (f.id)}
							<tr class="hover cursor-pointer {fSelected[f.id] ? 'bg-primary/5' : ''} {fCursor.index === i ? 'bg-base-200 outline-2 -outline-offset-2 outline-primary' : ''}"
								aria-selected={fCursor.index === i ? 'true' : undefined} onclick={() => goto(`/findings/${f.id}`)}>
								<td onclick={(e) => e.stopPropagation()}>
									<input type="checkbox" class="checkbox checkbox-sm" checked={!!fSelected[f.id]} onchange={(e) => (fSelected[f.id] = e.currentTarget.checked)} aria-label={$t('findings.selectFinding')} />
								</td>
								<td>
									<span class="font-semibold">{fmtNumber(Math.round(f.priority))}</span>
									{#if f.kev}<span class="badge badge-error badge-xs ml-1" title={$t('proj.kevTitle')}>KEV</span>{/if}
									<ExploitBadge maturity={f.exploit_maturity} />
									{#if f.epss}<span class="text-base-content/40 text-xs ml-1">{fmtNumber(f.epss, { style: 'percent' })}</span>{/if}
								</td>
								<td><Badge kind="severity" value={f.severity} /></td>
								<td class="max-w-md truncate">{f.title}</td>
								<td class="text-xs">{f.package_name || '—'}{#if f.package_version}<span class="text-base-content/50"> @{f.package_version}</span>{/if}</td>
								<td class="text-xs">{f.scanner}</td>
								<td onclick={(e) => e.stopPropagation()}>
									<StatusCell status={f.status} editing={fEditing === f.id} disabled={fBusy === f.id}
										onedit={() => (fEditing = f.id)} onpick={(s) => triageFinding(f, s)} oncancel={() => (fEditing = '')} />
								</td>
								<td><SlaBadge status={f.sla_status} due={f.sla_due_at} /></td>
								<td class="max-w-32 truncate text-xs" title={f.assignee_email ?? $t('findings.unassigned')}>
									{#if f.assignee_email}{f.assignee_email.split('@')[0]}{:else}<span class="text-base-content/30">—</span>{/if}
								</td>
								{#if fFilters.version === 'all'}<td class="text-xs">{versionName(f.version_id)}</td>{/if}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if fMeta}
				<Pagination limit={fMeta.limit} offset={fMeta.offset} count={fMeta.count} hasMore={fMeta.has_more} onchange={goFindings} />
			{/if}
			<button type="button" class="mt-2 text-xs text-base-content/50 hover:text-base-content" onclick={() => help.toggle()}>
				{$t('findings.press')} <kbd class="kbd kbd-xs">?</kbd> {$t('findings.keyHelp')}
			</button>
		{/if}
		{#if fSelectedIds.length > 0}
			<div class="pointer-events-none fixed inset-x-0 bottom-4 z-40 flex justify-center px-4">
				<div class="pointer-events-auto flex max-w-full items-center gap-1 overflow-x-auto rounded-full bg-base-100 px-3 py-2 shadow-xl ring-1 ring-base-content/10">
					<span class="whitespace-nowrap px-2 text-sm font-medium">{$t('findings.selected', { count: fSelectedIds.length })}</span>
					<div class="mx-1 h-5 w-px bg-base-300"></div>
					<button class="btn btn-ghost btn-sm" disabled={fBulkBusy} title={$t('proj.confirmTitle')} onclick={() => triageSelected('confirmed')}>{$t('proj.confirmBtn')}</button>
					<button class="btn btn-ghost btn-sm" disabled={fBulkBusy} title={$t('proj.fpTitle')} onclick={() => triageSelected('false_positive')}>{$t('findings.actFP')}</button>
					<button class="btn btn-ghost btn-sm" disabled={fBulkBusy} title={$t('proj.acceptTitle')} onclick={() => triageSelected('risk_accepted')}>{$t('findings.actAccept')}</button>
					<button class="btn btn-ghost btn-sm" disabled={fBulkBusy} title={$t('proj.wontTitle')} onclick={() => triageSelected('wont_fix')}>{$t('findings.actWont')}</button>
					<button class="btn btn-ghost btn-sm" disabled={fBulkBusy} title={$t('proj.reopenTitle')} onclick={() => triageSelected('open')}>{$t('findings.actReopen')}</button>
					<button class="btn btn-ghost btn-sm whitespace-nowrap" disabled={fBulkBusy || !$me} title={$t('proj.takeTitle')} onclick={assignToMe}>{$t('findings.take')}</button>
					{#if fBulkBusy}<span class="loading loading-spinner loading-sm mx-1"></span>{/if}
					<button class="btn btn-ghost btn-circle btn-sm" onclick={() => (fSelected = {})} aria-label={$t('findings.clearSelection')}>✕</button>
				</div>
			</div>
		{/if}
	{:else if tab === 'trends'}
		<p class="text-sm text-base-content/60 mb-3">
			{$t('proj.trendsIntro')}
		</p>
		<State loading={tabLoading} />
		{#if !tabLoading}
			<div class="grid gap-4 lg:grid-cols-2">
				<div class="card bg-base-100 shadow-sm">
					<div class="card-body p-5">
						<h3 class="font-semibold mb-2">{$t('proj.openBySeverity')}</h3>
						<TrendChart points={trend} series={OPEN_BY_SEVERITY} stacked format={fmtCount} />
					</div>
				</div>
				<div class="card bg-base-100 shadow-sm">
					<div class="card-body p-5">
						<h3 class="font-semibold mb-2">{$t('proj.riskScore')}</h3>
						<TrendChart points={trend} series={RISK} format={fmtRisk} />
					</div>
				</div>
				<div class="card bg-base-100 shadow-sm lg:col-span-2">
					<div class="card-body p-5">
						<h3 class="font-semibold mb-2">{$t('proj.newVsFixed')}</h3>
						<TrendChart points={trend} series={FLOW} format={fmtCount} height={150} />
						{#if trend.length}
							<p class="text-xs text-base-content/60 mt-1">
								{$t('home.windowNew', { count: trendStats.opened })} · {$t('proj.fixedIn90', { count: trendStats.closed })}{#if trendStats.mttr !== null} · {$t('home.windowMttr', { days: trendStats.mttr })}{/if}{#if trendStats.compliance !== null} · {$t('home.windowSla', { percent: trendStats.compliance })}{/if}
							</p>
						{/if}
					</div>
				</div>
			</div>
		{/if}
	{:else if tab === 'fix-plan'}
		<FixPlan projectId={id ?? ''} />
	{:else if tab === 'remediation' && isOn($features, 'remediation')}
		<Remediation projectId={id ?? ''} />
	{:else if tab === 'engagements' && isOn($features, 'engagements')}
		<EngagementsEditor projectId={id ?? ''} onchanged={() => { loadFindings(); loadHeader(); }} />
	{:else if tab === 'acceptances'}
		<RiskAcceptances projectId={id ?? ''} />
	{:else if tab === 'scans'}
		<State loading={tabLoading} empty={!tabLoading && scans.length === 0} emptyText={$t('proj.noScans')} />
		{#if !tabLoading && scans.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colScanner')}</th><th>{$t('proj.colBranch')}</th><th>{$t('proj.colCategory')}</th><th>{$t('proj.colStatus')}</th><th>{$t('proj.colFindings')}</th><th>{$t('proj.colWhen')}</th></tr></thead>
					<tbody>
						{#each scans as s (s.id)}
							<tr class="hover">
								<td>{s.scanner}</td>
								<td class="text-xs">{versionName(s.version_id) || s.branch || '—'}</td>
								<td class="uppercase text-xs">{$labelOf('category', s.category)}</td>
								<td>
									<Badge kind="scan" value={s.status} />
									{#if s.unchanged_of}
										<span class="badge badge-ghost badge-sm ml-1" title={$t('proj.unchangedScan', { id: s.unchanged_of })}>{$t('proj.unchanged')}</span>
									{/if}
								</td>
								<td class="text-xs">
									{#each Object.entries(s.summary ?? {}) as [sev, n]}
										<span class="badge badge-sm mr-1 whitespace-nowrap capitalize {severityClass(sev)}">{$labelOf('severity', sev)}: {fmtNumber(Number(n))}</span>
									{/each}
								</td>
								<td class="text-xs text-base-content/60">{fmtDate(s.created_at)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'sboms'}
		{#if !tabLoading && sboms.length > 0}
			<div class="mb-3 flex justify-end">
			<button class="btn btn-sm btn-ghost" title={$t('proj.aiInventoryTitle')}
					onclick={() => { compKind = 'ai'; loaded.components = false; switchTab('components'); }}>{$t('proj.aiInventory')}</button>
			</div>
		{/if}
		<State loading={tabLoading} empty={!tabLoading && sboms.length === 0} emptyText={$t('proj.noSboms')} />
		{#if !tabLoading && sboms.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colArtifact')}</th><th>{$t('proj.colVersion')}</th><th>{$t('proj.colBranch')}</th><th>{$t('proj.colFormat')}</th><th>{$t('proj.colComponents')}</th><th>{$t('proj.colWhen')}</th><th></th></tr></thead>
					<tbody>
						{#each sboms as s (s.id)}
							<tr class="hover cursor-pointer" onclick={() => (location.href = `/sboms/${s.id}`)}>
								<td><a class="link link-hover" href={`/sboms/${s.id}`}>{s.artifact || '—'}</a></td>
								<td>{s.version || '—'}</td>
								<td class="text-xs">{versionName(s.version_id)}</td>
								<td class="text-xs">{s.format} {s.spec_version}</td>
								<td>{fmtNumber(s.component_count)}</td>
								<td class="text-xs text-base-content/60">{fmtDate(s.created_at)}</td>
								<td class="text-right whitespace-nowrap" onclick={(e) => e.stopPropagation()}>
									<a class="btn btn-ghost btn-xs" href={`/sboms/${s.id}?tab=vulnerabilities`}>{$t('proj.vulnerabilities')}</a>
									<a class="btn btn-ghost btn-xs" href={`/sboms/${s.id}?tab=changes`}>{$t('proj.changes')}</a>
									<a class="btn btn-ghost btn-xs" href={`/sboms/${s.id}?tab=graph`}>{$t('proj.graph')}</a>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'members'}
		<p class="mb-3 text-sm text-base-content/60">
			{$t('proj.membersIntro1')} <em>{$t('proj.membersOnly')}</em>{$t('proj.membersIntro2')}
			<strong>{$t('proj.membersHighest')}</strong> {$t('proj.membersIntro3')}
		</p>

		<form onsubmit={addMember} class="mb-4 flex flex-wrap items-end gap-2">
			{#if orgGroups.length > 0}
				<Field label={$t('proj.grantTo')}>
					<select bind:value={memberForm.kind} class="select select-bordered select-sm">
						<option value="user">{$t('proj.grantUser')}</option>
						<option value="group">{$t('proj.grantGroup')}</option>
					</select>
				</Field>
			{/if}
			{#if memberForm.kind === 'group'}
				<Field label={$t('proj.group')}>
					<select bind:value={memberForm.group_id} required class="select select-bordered select-sm w-64">
						<option value="" disabled>{$t('proj.pickGroup')}</option>
						{#each orgGroups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
					</select>
				</Field>
			{:else}
				<Field label={$t('proj.email')}>
					<input bind:value={memberForm.email} type="email" required placeholder="dana@example.com"
						class="input input-bordered input-sm w-64" />
				</Field>
			{/if}
			<Field label={$t('proj.role')}>
				<select bind:value={memberForm.role} class="select select-bordered select-sm">
					<option value="viewer">{$t('proj.roleViewer')}</option>
					<option value="editor">{$t('proj.roleEditor')}</option>
					<option value="owner">{$t('proj.roleOwner')}</option>
					<option value="uploader">{$t('proj.roleUploader')}</option>
				</select>
			</Field>
			{#if orgRoles.length > 0}
				<Field label={$t('proj.customRole')}>
					<select bind:value={memberForm.custom_role_id} class="select select-bordered select-sm">
						<option value="">{$t('proj.noCustomRole')}</option>
						{#each orgRoles as r (r.id)}<option value={r.id}>{r.name}</option>{/each}
					</select>
				</Field>
			{/if}
			<button class="btn btn-primary btn-sm" disabled={memberBusy}>
				{#if memberBusy}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('proj.grant')}
			</button>
			<a href="/groups" class="link text-xs self-center">{$t('proj.manageGroups')}</a>
		</form>

		<State loading={tabLoading} empty={!tabLoading && members.length === 0}
			emptyText={$t('proj.noGrants')} />
		{#if !tabLoading && members.length > 0}
			<div class="overflow-x-auto rounded-box bg-base-100 shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colUser')}</th><th>{$t('proj.colRoleHere')}</th><th></th></tr></thead>
					<tbody>
						{#each members as m (m.group_id || m.user_id)}
							<tr class="hover">
								<td class="font-medium">
									{#if m.group_id}<span class="badge badge-outline badge-xs mr-1">{$t('proj.grantGroup')}</span>{m.group_name}{:else}{m.email}{/if}
								</td>
								<td>
								<span class="badge badge-ghost badge-sm">{$labelOf('role', m.role)}</span>
								{#if m.custom_role_name}<span class="badge badge-info badge-outline badge-xs" title={$t('proj.customRole')}>{m.custom_role_name}</span>{/if}
								{#if m.source === 'sso'}<span class="badge badge-outline badge-xs" title={$t('home.ssoGrantTitle')}>SSO</span>{/if}
							</td>
								<td class="text-right">
									<button class="btn btn-ghost btn-xs" onclick={() => removeMember(m)}>{$t('proj.revoke')}</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}

		<div class="mt-6">
			<div class="flex items-center justify-between mb-2">
				<h3 class="font-semibold">{$t('proj.whoCanReach')}</h3>
				<button class="btn btn-ghost btn-sm" onclick={loadAccess} disabled={accessLoading}>
					{#if accessLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
					{access ? $t('proj.refreshAccess') : $t('proj.showAccess')}
				</button>
			</div>
			{#if accessError}
				<p class="text-sm text-warning">{accessError}</p>
			{:else if access}
				<AccessTable entries={access} showProject={false} />
			{/if}
		</div>

	{:else if tab === 'vex'}
		<div class="mb-3 flex items-center justify-between gap-3">
			<p class="text-sm text-base-content/60">
				{$t('proj.vexIntro1')} <em>{$t('proj.vexPresent')}</em>{$t('proj.vexIntro2')}
			</p>
			<div class="flex shrink-0 items-center gap-2">
				{#if versions.length > 1}
					<select class="select select-bordered select-sm" bind:value={vexExport.version} aria-label={$t('proj.branchExport')}>
						<option value="">{$t('proj.defaultBranch')}</option>
						{#each versions.filter((v) => !v.is_default) as v (v.id)}
							<option value={v.id}>{v.name}</option>
						{/each}
					</select>
				{/if}
				<div class="join">
					<select class="select select-bordered select-sm join-item" bind:value={vexExport.format} aria-label={$t('proj.vexFormat')}>
						{#each VEX_FORMATS as f (f.value)}
							<option value={f.value}>{f.label}</option>
						{/each}
					</select>
					<button class="btn btn-sm join-item" onclick={exportVex} disabled={exportingVex}
						title={$t('proj.vexExportTitle')}>
						{#if exportingVex}<span class="loading loading-spinner loading-xs"></span>{/if}
						{$t('proj.exportVex')}
					</button>
				</div>
				<button class="btn btn-primary btn-sm" onclick={() => vexDialog.showModal()}>{$t('proj.uploadVex')}</button>
			</div>
		</div>
		<State loading={tabLoading} empty={!tabLoading && vexStatements.length === 0}
			emptyText={$t('proj.noVex')} />
		{#if !tabLoading && vexStatements.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colVuln')}</th><th>{$t('proj.colProduct')}</th><th>{$t('proj.colStatus')}</th><th>{$t('proj.colJustification')}</th><th>{$t('proj.colSource')}</th><th></th></tr></thead>
					<tbody>
						{#each vexStatements as v (v.id)}
							<tr class="hover">
								<td class="font-mono text-xs">{v.vuln_id}</td>
								<td class="text-xs">{v.product || $t('proj.allProducts')}</td>
								<td>
									<span class="badge badge-sm {v.status === 'affected' ? 'badge-error' : v.status === 'under_investigation' ? 'badge-ghost' : 'badge-success'}">
										{$labelOf('vex', v.status)}
									</span>
								</td>
								<td class="max-w-xs truncate text-xs" title={v.detail}>{v.justification || '—'}</td>
								<td class="text-xs text-base-content/50">{v.source}</td>
								<td class="text-right">
									<button class="btn btn-ghost btn-xs" onclick={() => removeVex(v.id)}>{$t('common.remove')}</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}

	{:else if tab === 'components'}
		<div class="flex items-center gap-2 mb-3">
			<input bind:value={compSearch} placeholder={compExact ? $t('proj.exactName') : $t('proj.nameContains')}
				class="input input-bordered input-sm flex-1 max-w-xs"
				onkeydown={(e) => e.key === 'Enter' && searchComponents()} />
			<label class="label cursor-pointer gap-2">
				<input type="checkbox" bind:checked={compExact} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('proj.exact')}</span>
			</label>
			<select bind:value={compVulnerable} onchange={searchComponents} class="select select-bordered select-sm">
				<option value="">{$t('proj.vulnAny')}</option>
				<option value="true">{$t('proj.vulnOnly')}</option>
				<option value="false">{$t('proj.cleanOnly')}</option>
			</select>
			<select bind:value={compOutdated} onchange={searchComponents} class="select select-bordered select-sm"
				title={$t('proj.outdatedTitle')}>
				<option value="">{$t('proj.outdatedAny')}</option>
				<option value="true">{$t('proj.outdatedOnly')}</option>
				<option value="false">{$t('proj.latestOnly')}</option>
			</select>
			<select bind:value={compKind} onchange={searchComponents} class="select select-bordered select-sm" title={$t('comp.kindTitle')}>
				<option value="">{$t('comp.kindAny')}</option>
				<option value="ai">{$t('comp.kindAi')}</option>
				<option value="model">{$t('comp.kindModels')}</option>
				<option value="dataset">{$t('comp.kindDatasets')}</option>
				<option value="ai-service">{$t('comp.kindAiServices')}</option>
				<option value="software">{$t('comp.kindSoftware')}</option>
			</select>
			<button class="btn btn-sm" onclick={searchComponents}>{$t('findings.search')}</button>
			<div class="ml-auto">
				<ExportMenu run={(/** @type {string} */ format) => api.exportProjectComponents(id, componentQuery(), format)} />
			</div>
		</div>
		<State loading={tabLoading} empty={!tabLoading && components.length === 0} emptyText={$t('proj.noComponents')} />
		{#if !tabLoading && components.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('finding.colComponent')}</th><th>{$t('proj.colVersion')}</th><th>{$t('proj.colLatest')}</th><th>{$t('proj.vulnerabilities')}</th><th>{$t('proj.colFile')}</th><th>{$t('proj.colLicense')}</th><th>PURL</th></tr></thead>
					<tbody>
						{#each components as c (c.id)}
							<tr class="hover">
								<td>{c.name} <AIBadge {c} /></td>
								<td class="text-xs">{c.version || '—'}</td>
								<td><OutdatedBadge {c} /> <IntegrityBadge integrity={c.integrity} /></td>
								<td><VulnBadge count={c.vuln_count} severity={c.max_severity} kev={c.kev} vulns={c.vulns} /></td>
								<td class="text-xs font-mono text-base-content/70 max-w-xs truncate" title={c.file_path}>{c.file_path || '—'}</td>
								<td><LicenseBadge {c} /></td>
								<td class="text-xs text-base-content/50 max-w-xs truncate">{c.purl || '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'assets'}
		<div class="flex justify-end mb-3">
			<button class="btn btn-sm btn-outline" onclick={() => assetDialog.showModal()}>{$t('proj.addAsset')}</button>
		</div>
		<State loading={tabLoading} empty={!tabLoading && assets.length === 0}
			emptyText={$t('proj.noAssets')} />
		{#if !tabLoading && assets.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colType')}</th><th>{$t('proj.colName')}</th><th>{$t('proj.colIdentifier')}</th><th>{$t('proj.colExposure')}</th><th></th></tr></thead>
					<tbody>
						{#each assets as a (a.id)}
							<tr class="hover">
								<td><span class="badge badge-ghost badge-sm">{$labelOf('asset', a.type)}</span></td>
								<td>{a.name}</td>
								<td class="text-xs font-mono text-base-content/60 max-w-xs truncate" title={a.identifier}>{a.identifier || '—'}</td>
								<td>
									<ExposureBadge exposure={a.exposure} source={a.exposure_source} reason={a.exposure_reason} />
									{#if !a.exposure}<span class="text-xs text-base-content/40">{$t('common.unknown')}</span>{/if}
								</td>
								<td class="text-right"><button class="btn btn-ghost btn-xs" onclick={() => openAsset(a)}>{$t('proj.exposureRelations')}</button></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'policies'}
		<div class="flex items-center justify-between mb-3">
			<p class="text-sm text-base-content/60">
				{$t('proj.policiesIntro1')} <code>policy</code>{$t('proj.policiesIntro2')}
			</p>
			<a class="btn btn-sm btn-ghost" href={`/findings?project_id=${id}&scanner=policy`}>{$t('proj.allViolations')}</a>
		</div>
		<State loading={tabLoading} empty={!tabLoading && projectPolicies.length === 0}
			emptyText={$t('proj.noPolicies')} />
		{#if !tabLoading && projectPolicies.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colPolicy')}</th><th>{$t('proj.colState')}</th><th>{$t('proj.colScope')}</th><th>{$t('proj.colOpenViolations')}</th></tr></thead>
					<tbody>
						{#each projectPolicies as p (p.id)}
							<tr class="hover">
								<td>
									<a class="link link-hover font-medium" href="/policies">{p.name}</a>
									{#if p.description}<div class="text-xs text-base-content/50">{p.description}</div>{/if}
								</td>
								<td><span class="badge badge-sm {POLICY_TONE[p.violation_state] ?? 'badge-ghost'}">{p.violation_state}</span></td>
								<td class="text-xs">{p.scope === 'global' ? $t('proj.scopeAll') : $t('proj.scopeThis')}{p.versions === 'default' ? ` · ${$t('proj.defaultVersionOnly')}` : ''}</td>
								<td>
									{#if p.violations}
										<a class="link tabular-nums" href={`/findings?project_id=${id}&scanner=policy&rule_id=${p.id}`}>{p.violations}</a>
									{:else}
										<span class="text-base-content/40">0</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'compliance'}
		<div class="flex items-center mb-3">
			<p class="text-sm text-base-content/60">{$t('proj.complianceIntro')}</p>
		</div>
		<State loading={tabLoading} empty={!tabLoading && compliance.length === 0} emptyText={$t('home.noFrameworks')} />
		{#if !tabLoading && compliance.length > 0}
			<div class="grid gap-4 md:grid-cols-2">
				{#each compliance as fw (fw.framework)}
					<div class="card bg-base-100 shadow-sm">
						<div class="card-body p-5">
							<div class="flex items-center justify-between">
								<div>
									<h3 class="font-semibold">{fw.name}</h3>
									<p class="text-xs text-base-content/50">{fw.version}</p>
								</div>
								<div class="text-right">
									<div class="text-2xl font-bold {fw.score >= 90 ? 'text-success' : fw.score >= 60 ? 'text-warning' : 'text-error'}">{fw.score}%</div>
									<div class="text-xs text-base-content/50">{fw.passing_controls}/{fw.total_controls} controls{#if fw.manual_controls} · {fw.manual_controls} to attest{/if}</div>
								</div>
							</div>
							<progress class="progress {fw.score >= 90 ? 'progress-success' : fw.score >= 60 ? 'progress-warning' : 'progress-error'} w-full mt-1"
								value={fw.score} max="100"></progress>
							{#if fw.failing_controls > 0}
								<div class="mt-2 flex flex-col gap-1">
									{#each fw.controls.filter((/** @type {any} */ c) => c.status === 'failing') as c (c.code)}
										<div class="flex items-center justify-between text-sm">
											<span><span class="badge badge-error badge-xs mr-1">{$t('proj.fail')}</span>{c.code} · {c.title}</span>
											<span class="text-xs text-base-content/50" title={c.evidence}>{c.open_findings ? $t('proj.openCount', { count: c.open_findings }) : c.evidence}</span>
										</div>
									{/each}
								</div>
							{:else}
								<p class="text-sm text-success mt-2">{$t('proj.allPassing')}{#if fw.manual_controls}<span class="text-base-content/50"> · {$t('proj.toAttest', { count: fw.manual_controls })}</span>{/if}</p>
							{/if}
							<ManualControls projectId={id ?? ''} framework={fw} onchanged={reloadCompliance} />
							<div class="card-actions justify-end mt-2">
							<button class="btn btn-ghost btn-xs" onclick={() => api.openEvidenceReport(id ?? '', fw.framework).catch((err) => notify(errorMessage(err)))}
								title={$t('proj.evidenceReportTitle')}>{$t('proj.evidenceReport')}</button>
							</div>
						</div>
					</div>
				{/each}
			</div>
		{/if}
		{#if isOn($features, 'cra')}<CraCases projectId={id ?? ''} />{/if}
	{:else if tab === 'gate'}
		<p class="text-sm text-base-content/60 mb-3">
			{$t('proj.gateIntro1')}
			<span class="font-medium">{$t('proj.gateDeduped')}</span> {$t('proj.gateIntro2')}
			<span class="font-mono text-xs">POST /projects/{id}/gate</span> {$t('proj.gateReturns')}
		</p>

		{#if gateResult}
			<div class="rounded-box p-4 mb-4 {gateResult.passed ? 'bg-success/10' : 'bg-error/10'}">
				<div class="flex items-center gap-2">
					<span class="badge {gateResult.passed ? 'badge-success' : 'badge-error'} badge-lg">
						{gateResult.passed ? $t('proj.pass') : $t('proj.failUpper')}
					</span>
					<span class="text-sm text-base-content/60">
						{$t('proj.policyLabel', { scope: ['none', 'project', 'global'].includes(gateScope) ? $t(/** @type {import('#lib/i18n.js').MessageKey} */ ('proj.gateScope.' + gateScope)) : gateScope })}{#if gateResult.new_only} · {$t('proj.newOnly')}{/if}{#if gateResult.baseline} ({$t('proj.gateBaseline', { branch: gateResult.baseline })}){/if}
						{#if gateRunning}· <span class="loading loading-spinner loading-xs"></span>{/if}
					</span>
					<button class="btn btn-ghost btn-xs ml-auto" onclick={runGate} disabled={gateRunning}>{$t('proj.rerun')}</button>
				</div>
				{#if !gateResult.passed}
					<ul class="mt-2 text-sm list-disc list-inside text-error">
						{#each gateResult.violations as v}<li>{v.message}</li>{/each}
					</ul>
				{/if}
				<div class="mt-3 flex flex-wrap gap-3 text-xs text-base-content/60">
					<span>{$t('proj.statCritical', { count: gateResult.stats.open_critical })}</span>
					<span>{$t('proj.statHigh', { count: gateResult.stats.open_high })}</span>
					<span>{$t('proj.statKev', { count: gateResult.stats.open_kev })}</span>
					<span>{$t('proj.statLicense', { count: gateResult.stats.open_license })}</span>
					<span>{$t('proj.statSla', { count: gateResult.stats.sla_breached })}</span>
					<span>{$t('proj.statEpss', { value: fmtNumber(gateResult.stats.max_epss, { minimumFractionDigits: 3, maximumFractionDigits: 3 }) })}</span>
					<span>{$t('proj.gateRiskScore', { score: fmtNumber(gateResult.stats.risk_score, { maximumFractionDigits: 1 }) })}</span>
				</div>
			</div>
		{/if}

		{#if gatePolicy}
			<div class="bg-base-100 rounded-box shadow-sm p-4 grid gap-3 sm:grid-cols-2 max-w-xl">
				<h3 class="sm:col-span-2 font-semibold">{$t('proj.gatePolicy')} {gateScope === 'global' ? $t('proj.gateInherited') : ''}</h3>
				<Field label={$t('proj.maxCrit')} hint={$t('proj.noLimit')}>
					<input type="number" min="0" bind:value={gatePolicy.max_critical} placeholder="—" class="input input-bordered input-sm w-full" />
				</Field>
				<Field label={$t('proj.maxHigh')} hint={$t('proj.noLimit')}>
					<input type="number" min="0" bind:value={gatePolicy.max_high} placeholder="—" class="input input-bordered input-sm w-full" />
				</Field>
				<Field label={$t('proj.maxEpss')} hint={$t('proj.maxEpssHint')}>
					<input type="number" min="0" max="1" step="0.01" bind:value={gatePolicy.max_epss} placeholder="—" class="input input-bordered input-sm w-full" />
				</Field>
				<Field label={$t('proj.gateMaxRiskScore')} hint={$t('proj.gateNoLimit')}>
					<input type="number" min="0" step="0.1" bind:value={gatePolicy.max_risk_score} placeholder="—" class="input input-bordered input-sm w-full" />
				</Field>
				<div class="flex flex-col justify-end gap-2">
					<label class="label cursor-pointer justify-start gap-2 py-1">
						<input type="checkbox" bind:checked={gatePolicy.block_kev} class="checkbox checkbox-sm" />
						<span class="label-text">{$t('proj.blockKev')}</span>
					</label>
					<label class="label cursor-pointer justify-start gap-2 py-1">
						<input type="checkbox" bind:checked={gatePolicy.block_license} class="checkbox checkbox-sm" />
						<span class="label-text">{$t('proj.blockLicense')}</span>
					</label>
					<label class="label cursor-pointer justify-start gap-2 py-1">
						<input type="checkbox" bind:checked={gatePolicy.block_sla_breach} class="checkbox checkbox-sm" />
						<span class="label-text">{$t('proj.blockSla')}</span>
					</label>
				</div>
				<label class="sm:col-span-2 label cursor-pointer justify-start gap-2 py-1" title={$t('proj.newOnlyTitle')}>
					<input type="checkbox" bind:checked={gatePolicy.new_only} class="checkbox checkbox-sm" />
					<span class="label-text">{$t('proj.newOnlyLabel')}</span>
				</label>
				<Field label={$t('proj.gateBaselineBranch')} hint={$t('proj.gateBaselineHint')}>
					<input type="text" bind:value={gatePolicy.baseline_branch} placeholder="main" class="input input-bordered input-sm w-full" />
				</Field>
				<div class="sm:col-span-2 flex justify-end gap-2">
					<button class="btn btn-primary btn-sm" onclick={saveGate} disabled={saving}>
						{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('proj.savePolicy')}
					</button>
				</div>
			</div>
		{/if}
		{#if isOn($features, 'badges')}<BadgesCard projectId={id ?? ''} />{/if}
	{:else if tab === 'branches'}
		<p class="text-sm text-base-content/60 mb-3">
			{$t('proj.branchesIntro1')} <code>main</code> {$t('proj.branchesIntro2')} <strong>{$t('proj.branchesDefault')}</strong>{$t('proj.branchesIntro3')}
			<code>--branch</code> {$t('proj.branchesIntro4')} <code>--release</code>{$t('proj.branchesIntro5')}
		</p>
		<State loading={tabLoading} empty={!tabLoading && versions.length === 0} emptyText={$t('proj.noVersions')} />
		{#if !tabLoading && versions.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('proj.colName')}</th><th>{$t('proj.colKind')}</th><th>{$t('proj.colOpenFindings')}</th><th>{$t('proj.colScans')}</th><th>{$t('proj.colSboms')}</th><th>{$t('proj.colLastScan')}</th><th></th></tr></thead>
					<tbody>
						{#each versions as v (v.id)}
							<tr class="hover">
								<td class="font-mono text-sm">
									{v.name}
									{#if v.is_default}<span class="badge badge-primary badge-sm ml-1">{$t('finding.default')}</span>{/if}
								</td>
								<td class="text-xs">{v.kind === 'release' ? $t('proj.kind.release') : $t('proj.kind.branch')}</td>
								<td>
									<button class="link link-hover" onclick={() => { fFilters.version = v.is_default ? '' : v.id; switchTab('findings'); reloadFindings(); }}>{fmtNumber(v.open_findings)}</button>
								</td>
								<td>{fmtNumber(v.scans)}</td>
								<td>{fmtNumber(v.sboms)}</td>
								<td class="text-xs text-base-content/60">{fmtDate(v.last_scan_at)}</td>
								<td class="text-right whitespace-nowrap">
									{#if !v.is_default}
										<button class="btn btn-ghost btn-xs" onclick={() => makeDefault(v)}>{$t('proj.makeDefault')}</button>
										<button class="btn btn-ghost btn-xs text-error" onclick={() => removeVersion(v)}>{$t('common.delete')}</button>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{:else if tab === 'sla'}
		<p class="text-sm text-base-content/60 mb-3">
			{$t('proj.slaIntro')}
		</p>
		{#if summary?.sla}
			{@const s = summary.sla}
			<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100 w-full mb-4">
				<a href={`/findings?project_id=${id}&sla=breached&sort=sla_due`} class="stat hover:bg-base-200">
					<div class="stat-title">{$t('proj.breached')}</div>
					<div class="stat-value text-error">{fmtNumber(s.breached)}</div>
					<div class="stat-desc">
						{#each SEVERITIES as sev}{#if s.breached_by_severity?.[sev]}{$labelOf('severity', sev)}: {fmtNumber(s.breached_by_severity[sev])} {/if}{/each}
					</div>
				</a>
				<a href={`/findings?project_id=${id}&sla=due_soon&sort=sla_due`} class="stat hover:bg-base-200">
					<div class="stat-title">{$t('proj.dueSoon')}</div>
					<div class="stat-value text-warning">{fmtNumber(s.due_soon)}</div>
					<div class="stat-desc">{$t('proj.onTrackPaused', { onTrack: s.on_track, paused: s.paused })}</div>
				</a>
				<div class="stat">
					<div class="stat-title">{$t('proj.fixedOnTimeWindow', { days: s.window_days })}</div>
					<div class="stat-value">{s.compliance === null ? '—' : fmtNumber(s.compliance, { style: 'percent' })}</div>
					<div class="stat-desc">{$t('proj.metMissed', { met: s.met, missed: s.missed })}</div>
				</div>
				<div class="stat">
					<div class="stat-title">{$t('proj.mttf')}</div>
					<div class="stat-desc pt-2 flex flex-wrap gap-2">
						{#each SEVERITIES as sev}
							{#if s.mttr_days?.[sev] !== undefined}<span>{$labelOf('severity', sev)}: {$t('proj.daysShort', { days: fmtNumber(s.mttr_days[sev], { minimumFractionDigits: 1, maximumFractionDigits: 1 }) })}</span>{/if}
						{/each}
						{#if !Object.keys(s.mttr_days ?? {}).length}<span>{$t('proj.nothingFixed', { days: s.window_days })}</span>{/if}
					</div>
				</div>
			</div>
		{/if}
		<State loading={tabLoading} />
		{#if !tabLoading && slaPolicy}
			<div class="bg-base-100 rounded-box shadow-sm p-4 max-w-3xl">
				<SlaPolicyEditor policy={slaPolicy} own="project" onsave={saveSla} onreset={resetSla} />
			</div>
		{/if}
	{:else if tab === 'issues'}
		<div class="max-w-3xl"><IssueTrackerEditor projectId={id} /></div>
	{:else if tab === 'connectors'}
		<ConnectorsEditor
			projectId={id}
			onpulled={() => {
				loaded.scans = false;
				loadFindings();
				loadHeader();
			}}
		/>
	{:else if tab === 'alerts'}
		<p class="text-sm text-base-content/60 mb-3">
			{$t('proj.alertsIntro1')} <span class="font-medium">{project.name}</span>{$t('proj.alertsIntro2')}
			<a class="link" href="/notifications">{$t('nav.notifications')}</a>.
		</p>
		<form onsubmit={createAlert} class="flex flex-wrap items-end gap-2 mb-4 p-3 bg-base-100 rounded-box shadow-sm">
			<input bind:value={alertForm.name} required placeholder={$t('proj.namePh')} class="input input-bordered input-sm" />
			<select bind:value={alertForm.type} class="select select-bordered select-sm">
				{#each CHANNEL_TYPES as ct}<option value={ct.id}>{ct.id === 'email' ? $t('channel.email') : ct.label}</option>{/each}
			</select>
			<input bind:value={alertForm.url} required type={channelInputType(alertForm.type)} placeholder={channelPlaceholder(alertForm.type)} title={channelHint(alertForm.type, $t)} class="input input-bordered input-sm flex-1 min-w-48" />
			<select bind:value={alertForm.events} class="select select-bordered select-sm">
				{#each EVENT_TYPES.filter((e) => e.id !== 'exception.expired') as e}<option value={e.id}>{$t(e.key)}</option>{/each}
			</select>
			<select bind:value={alertForm.min_severity} class="select select-bordered select-sm" title={$t('proj.minSevTitle')}>
				<option value="">{$t('proj.anySeverity')}</option>
				{#each SEVERITIES as s}<option value={s}>{$t('rules.andAbove', { severity: $labelOf('severity', s) })}</option>{/each}
			</select>
			<select bind:value={alertForm.summary} class="select select-bordered select-sm" title={$t('proj.summaryTitle')}>
				<option value="none">{$t('proj.noSummary')}</option>
				<option value="daily">{$t('proj.dailySummary')}</option>
				<option value="weekly">{$t('proj.weeklySummary')}</option>
			</select>
			<input bind:value={alertForm.filter} placeholder={$t('proj.filterPh')} spellcheck="false"
				title={$t('proj.filterTitle')}
				class="input input-bordered input-sm font-mono flex-1 min-w-48" />
			<button class="btn btn-primary btn-sm" disabled={saving}>{$t('common.add')}</button>
		</form>

		<State loading={tabLoading} empty={!tabLoading && alertChannels.length === 0}
			emptyText={$t('proj.noAlerts')} />
		{#if !tabLoading && alertChannels.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table table-sm">
					<thead><tr><th>{$t('notif.colName')}</th><th>{$t('notif.colType')}</th><th>{$t('notif.colEvents')}</th><th>{$t('notif.colRules')}</th><th>{$t('notif.colUrl')}</th><th></th></tr></thead>
					<tbody>
						{#each alertChannels as ch (ch.id)}
							<tr class="hover">
								<td class="font-medium">{ch.name}</td>
								<td><span class="badge badge-ghost badge-sm capitalize">{ch.type}</span></td>
								<td class="text-xs">{ch.events.join(', ')}</td>
								<td class="text-xs">{describeRules(ch, $t, $labelOf, $contentLocale)}</td>
								<td class="text-xs font-mono text-base-content/50 max-w-xs truncate" title={ch.url}>{ch.url}</td>
								<td class="text-right whitespace-nowrap">
									<button class="btn btn-ghost btn-xs" onclick={() => testAlert(ch)} disabled={alertTesting === ch.id}>
										{#if alertTesting === ch.id}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('notif.test')}
									</button>
									<button class="btn btn-ghost btn-xs text-error" onclick={() => deleteAlert(ch)}>{$t('common.delete')}</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/if}
{:else}
	<State loading={true} />
{/if}

<!-- Upload scan modal -->
<dialog bind:this={scanDialog} class="modal">
	<div class="modal-box max-w-2xl">
		<h3 class="font-bold text-lg mb-4">{$t('proj.uploadScan')}</h3>
		<form onsubmit={submitScan} class="flex flex-col gap-3">
			<Field label={$t('proj.scannerFormat')} required hint={selectedPreset?.hint}>
				<select bind:value={scanForm.preset} class="select select-bordered w-full">
					{#each SCAN_PRESETS as p}<option value={p.id}>{p.label}</option>{/each}
				</select>
			</Field>

			{#if scanForm.preset === 'custom'}
				<div class="grid grid-cols-2 gap-3">
					<Field label={$t('proj.scannerName')} required hint={$t('proj.scannerNameHint')}>
						<input bind:value={scanForm.scanner} placeholder="semgrep" class="input input-bordered w-full" />
					</Field>
					<Field label={$t('proj.format')} hint={$t('proj.formatHint')}>
						<input bind:value={scanForm.format} placeholder="sarif" class="input input-bordered w-full" />
					</Field>
				</div>
			{/if}

			<div class="grid grid-cols-2 gap-3">
				<Field label={$t('proj.colBranch')} hint={$t('proj.optional')}>
					<input bind:value={scanForm.branch} placeholder="main" class="input input-bordered w-full" />
				</Field>
				<Field label={$t('proj.commit')} hint={$t('proj.optional')}>
					<input bind:value={scanForm.commit} placeholder="abc123" class="input input-bordered w-full" />
				</Field>
			</div>

			{#if assets.length > 0}
				<Field label={$t('proj.asset')} hint={$t('proj.assetHint')}>
					<select bind:value={scanForm.asset_id} class="select select-bordered w-full">
						<option value="">{$t('proj.projectLevel')}</option>
						{#each assets as a}<option value={a.id}>{$labelOf('asset', a.type)} · {a.name}</option>{/each}
					</select>
				</Field>
			{/if}

			<Field label={$t('proj.report')} required hint={$t('proj.reportHint')}>
				<input type="file" accept=".json,.sarif,.txt" onchange={readScanFile}
					class="file-input file-input-bordered file-input-sm w-full mb-2" />
				<textarea bind:value={scanForm.raw} required placeholder={$t('proj.reportPh')}
					class="textarea textarea-bordered font-mono text-xs h-40 w-full"></textarea>
			</Field>

			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => scanDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('proj.ingest')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- Asset exposure / relationships / blast radius -->
<dialog bind:this={assetDetailDialog} class="modal" onclose={() => (detailAsset = null)}>
	<div class="modal-box max-w-4xl">
		<h3 class="font-bold text-lg mb-4">{detailAsset?.name ?? $t('proj.assetFallback')}</h3>
		{#if detailAsset}
			<AssetDetail asset={detailAsset} onchanged={assetChanged} />
		{/if}
		<div class="modal-action">
			<button type="button" class="btn btn-ghost" onclick={() => assetDetailDialog.close()}>{$t('home.closeButton')}</button>
		</div>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- New asset modal -->
<dialog bind:this={assetDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('proj.registerAsset')}</h3>
		<form onsubmit={createAsset} class="flex flex-col gap-3">
			<Field label={$t('proj.colType')} required>
				<select bind:value={newAsset.type} class="select select-bordered w-full">
					{#each ASSET_TYPES as at}<option value={at}>{$labelOf('asset', at)}</option>{/each}
				</select>
			</Field>
			<Field label={$t('proj.colName')} required>
				<input bind:value={newAsset.name} required placeholder="web:1.0" class="input input-bordered w-full" />
			</Field>
			<Field label={$t('proj.colIdentifier')} hint={$t('proj.identifierHint')}>
				<input bind:value={newAsset.identifier} placeholder="registry/web@sha256:…" class="input input-bordered w-full" />
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => assetDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('proj.register')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<!-- Upload SBOM modal -->
<dialog bind:this={sbomDialog} class="modal">
	<div class="modal-box max-w-2xl">
		<h3 class="font-bold text-lg mb-4">{$t('proj.uploadSbom')}</h3>
		<form onsubmit={submitSbom} class="flex flex-col gap-3">
			<div class="grid grid-cols-2 gap-3">
				<Field label={$t('proj.colArtifact')} hint={$t('proj.artifactHint')}>
					<input bind:value={sbomForm.artifact} placeholder="web" class="input input-bordered w-full" />
				</Field>
				<Field label={$t('proj.colVersion')} hint={$t('proj.optional')}>
					<input bind:value={sbomForm.version} placeholder="1.4.0" class="input input-bordered w-full" />
				</Field>
			</div>
			<Field label={$t('proj.document')} required hint={$t('proj.sbomDocHint')}>
				<input type="file" accept=".json,.spdx,.cdx" onchange={readSbomFile}
					class="file-input file-input-bordered file-input-sm w-full mb-2" />
				<textarea bind:value={sbomForm.raw} required placeholder={$t('proj.sbomPh')}
					class="textarea textarea-bordered font-mono text-xs h-40 w-full"></textarea>
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => sbomDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('proj.upload')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<dialog bind:this={vexDialog} class="modal">
	<div class="modal-box max-w-2xl">
		<h3 class="font-bold text-lg mb-1">{$t('proj.uploadVex')}</h3>
		<p class="text-sm text-base-content/60 mb-4">
			{$t('proj.vexDialogIntro')}
		</p>
		<form onsubmit={submitVex} class="flex flex-col gap-3">
			<Field label={$t('proj.document')} required hint={$t('proj.vexDocHint')}>
				<input type="file" accept=".json,.vex,.cdx" onchange={readVexFile}
					class="file-input file-input-bordered file-input-sm w-full mb-2" />
				<textarea bind:value={vexForm.raw} required placeholder={$t('proj.vexPh')}
					class="textarea textarea-bordered font-mono text-xs h-40 w-full"></textarea>
			</Field>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => vexDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary" disabled={saving}>
					{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('proj.upload')}
				</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('common.close')}</button></form>
</dialog>

<TriageDialog bind:this={triageDialog} />
<KeyboardHelp bind:this={help} enabled={tab === 'findings'} />

<dialog bind:this={editDialog} class="modal">
	<div class="modal-box">
		<h3 class="font-bold text-lg mb-4">{$t('proj.editProjectTitle')}</h3>
		<form onsubmit={saveEdit} class="flex flex-col gap-3">
			<Field label={$t('home.name')} required>
				<input bind:value={editForm.name} required class="input input-bordered w-full" />
			</Field>
			<Field label={$t('proj.repoUrl')}>
				<input bind:value={editForm.repo_url} class="input input-bordered w-full" />
			</Field>
			<Field label={$t('home.criticality')} hint={$t('home.criticalityHint')}>
				<select bind:value={editForm.business_criticality} class="select select-bordered w-full capitalize">
				{#each ['low', 'medium', 'high', 'critical'] as c}<option value={c}>{$labelOf('criticality', c)}</option>{/each}
				</select>
			</Field>
			<Field label={$t('home.parent')} hint={$t('proj.editParentHint')}>
				<select bind:value={editForm.parent_id} class="select select-bordered w-full">
				<option value="">{$t('home.parentNone')}</option>
					{#each editParents as { project: pp, depth } (pp.id)}<option value={pp.id}>{'\u00a0\u00a0'.repeat(depth)}{pp.name}</option>{/each}
				</select>
			</Field>
			<label class="label cursor-pointer justify-start gap-2">
				<input type="checkbox" bind:checked={editForm.is_collection} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('home.collectionCheckbox')}</span>
			</label>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => editDialog.close()}>{$t('common.cancel')}</button>
				<button class="btn btn-primary">{$t('common.save')}</button>
			</div>
		</form>
	</div>
	<form method="dialog" class="modal-backdrop"><button>close</button></form>
</dialog>

<ManualFindingDialog bind:this={manualDialog} projectId={id ?? ''} oncreated={() => { loadFindings(); loadHeader(); }} />
