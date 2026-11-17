<script>
	import { onMount, untrack } from 'svelte';
	import ExploitBadge from '#lib/components/ExploitBadge.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify, me } from '#lib/stores.js';
	import { handleListKey, createListCursor, isExceptionStatus, scrollCursorIntoView } from '#lib/keyboard.js';
	import TriageDialog from '#lib/components/TriageDialog.svelte';
	import KeyboardHelp from '#lib/components/KeyboardHelp.svelte';
	import StatusCell from '#lib/components/StatusCell.svelte';
	import { SEVERITIES, STATUSES, CATEGORIES, SLA_STATUSES, severityAccent, kevCatalogs, fmtNumber } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import Badge from '#lib/components/Badge.svelte';
	import SlaBadge from '#lib/components/SlaBadge.svelte';
	import State from '#lib/components/State.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import ExportMenu from '#lib/components/ExportMenu.svelte';

	const LIMIT = 50;

	let loading = $state(true);
	let error = $state('');
	let findings = $state(/** @type {any[]} */ ([]));
	let meta = $state({ limit: LIMIT, offset: 0, count: 0, has_more: false });
	let projects = $state(/** @type {any[]} */ ([]));
	let busy = $state(''); // id of a finding currently being triaged
	let selected = $state(/** @type {Record<string, boolean>} */ ({})); // id -> bool, for bulk triage
	let bulkBusy = $state(false);
	let allMatching = $state(false); // bulk applies to the whole filter, not just this page
	/** @type {HTMLInputElement | undefined} */
	let selectAllEl = $state();
	/** @type {HTMLInputElement} */
	let searchEl;
	/** @type {TriageDialog} */
	let triageDialog;
	/** @type {KeyboardHelp} */
	let help;
	// Keyboard row cursor (j/k) and the inline status editor (row id or '').
	let cursor = $state(createListCursor());
	let editing = $state('');
	const cursorRow = $derived(cursor.index >= 0 ? findings[cursor.index] : undefined);
	$effect(() => {
		if (cursor.index >= 0) scrollCursorIntoView();
	});

	const selectedIds = $derived(findings.filter((f) => selected[f.id]).map((f) => f.id));
	const allSelected = $derived(findings.length > 0 && findings.every((f) => selected[f.id]));
	// Reflect a partial selection as the "indeterminate" checkbox state.
	$effect(() => {
		if (selectAllEl) selectAllEl.indeterminate = selectedIds.length > 0 && !allSelected;
	});

	// Seed filters from the URL so dashboard links (?category=cloud, ?kev=true) work.
	const p = page.url.searchParams;
	let filters = $state({
		severity: p.get('severity') ?? '',
		status: p.get('status') ?? '',
		category: p.get('category') ?? '',
		project_id: p.get('project_id') ?? '',
		sla: p.get('sla') ?? '',
		exploit: p.get('exploit') ?? '',
		assignee: p.get('assignee') ?? '',
		// Set by links only (a policy's violations: ?scanner=policy&rule_id=<policy id>).
		scanner: p.get('scanner') ?? '',
		rule_id: p.get('rule_id') ?? '',
		kev: p.get('kev') === 'true',
		kev_ransomware: p.get('kev_ransomware') === 'true',
		reachable: p.get('reachable') === 'true',
		include_duplicates: p.get('include_duplicates') === 'true',
		all_versions: p.get('all_versions') === 'true',
		q: p.get('q') ?? '',
		tag: p.get('tag') ?? '',
		sort: p.get('sort') ?? (p.get('q') ? '' : 'priority')
	});
	let tags = $state(/** @type {{tag: string, count: number}[]} */ ([]));
	// One custom-field filter (?cf.<key>=value), seeded from the URL.
	const cfParam = [...p.keys()].find((k) => k.startsWith('cf.'));
	let cf = $state({ key: cfParam ? cfParam.slice(3) : '', value: cfParam ? (p.get(cfParam) ?? '') : '' });
	let cfFields = $state(/** @type {any[]} */ ([]));
	$effect(() => {
		api.listCustomFields({ entity: 'finding' }).then((f) => (cfFields = f)).catch(() => (cfFields = []));
	});
	// Separate, user-editable local state: only seeded from filters.q once (it
	// should not track later filter changes), so the read is untracked.
	let searchText = $state(untrack(() => filters.q));
	let offset = $state(0);

	/** @param {string} id */
	const projectName = (id) => projects.find((pr) => pr.id === id)?.name ?? '—';
	const anyFilter = $derived(
		filters.severity || filters.status || filters.category || filters.project_id || filters.sla || filters.exploit || filters.assignee ||
			filters.scanner || filters.rule_id || filters.q || filters.tag ||
			filters.kev || filters.reachable || filters.include_duplicates || filters.all_versions || (cf.key && cf.value)
	);

	// A finding stays in view after triage only if it still matches the active
	// status filter (e.g. filtering "open" and marking it FP should drop it).
	/** @param {string} status */
	const matchesFilter = (status) => !filters.status || filters.status === status;

	const TEXT_KEYS = /** @type {const} */ (['severity', 'status', 'category', 'project_id', 'sla', 'exploit', 'assignee', 'scanner', 'rule_id', 'q', 'tag']);
	const FLAG_KEYS = /** @type {const} */ (['kev', 'kev_ransomware', 'reachable', 'include_duplicates', 'all_versions']);

	// Persist filters into the URL so a reload — or a shared link — keeps them.
	function syncURL() {
		const params = new URLSearchParams();
		for (const k of TEXT_KEYS) if (filters[k]) params.set(k, filters[k]);
		params.set('sort', filters.sort);
		if (filters.kev) params.set('kev', 'true');
		if (filters.kev_ransomware) params.set('kev_ransomware', 'true');
		if (filters.reachable) params.set('reachable', 'true');
		if (filters.include_duplicates) params.set('include_duplicates', 'true');
		if (filters.all_versions) params.set('all_versions', 'true');
		if (cf.key && cf.value) params.set('cf.' + cf.key, cf.value);
		goto('?' + params.toString(), { shallow: true, replace: true });
	}

	// Quick-triage actions available for a finding, given its current state.
	/** @type {{ status: string, label: import('#lib/i18n.js').MessageKey, title: import('#lib/i18n.js').MessageKey }[]} */
	const OPEN_ACTIONS = [
		{ status: 'false_positive', label: 'findings.actFP', title: 'findings.actFPTitle' },
		{ status: 'risk_accepted', label: 'findings.actAccept', title: 'findings.actAcceptTitle' },
		{ status: 'wont_fix', label: 'findings.actWont', title: 'findings.actWontTitle' }
	];
	/** @type {typeof OPEN_ACTIONS} */
	const REOPEN_ACTIONS = [{ status: 'open', label: 'findings.actReopen', title: 'findings.actReopenTitle' }];
	/** @param {any} f */
	const actionsFor = (f) => (f.status === 'open' || f.status === 'confirmed' ? OPEN_ACTIONS : REOPEN_ACTIONS);

	function clearSelection() {
		selected = {};
		allMatching = false;
	}
	function toggleAll() {
		const val = !allSelected;
		const next = { ...selected };
		for (const f of findings) next[f.id] = val;
		selected = next;
		if (!val) allMatching = false;
	}

	// The active filter as query keys (strings — also the bulk-by-filter body).
	function filterQuery() {
		/** @type {Record<string, string>} */
		const q = {};
		for (const k of TEXT_KEYS) if (filters[k]) q[k] = filters[k];
		for (const k of FLAG_KEYS) if (filters[k]) q[k] = 'true';
		if (cf.key && cf.value) q['cf.' + cf.key] = cf.value;
		return q;
	}

	async function loadFindings() {
		loading = true;
		error = '';
		clearSelection();
		cursor.reset();
		editing = '';
		try {
			const res = await api.searchFindings({ limit: LIMIT, offset, sort: filters.sort, ...filterQuery() });
			findings = res.findings ?? [];
			meta = res.pagination ?? meta;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('findings.loadFailed');
		} finally {
			loading = false;
		}
	}

	function applyFilters() {
		offset = 0;
		syncURL();
		loadFindings();
	}
	function clearFilters() {
		filters = { ...filters, severity: '', status: '', category: '', project_id: '', sla: '', exploit: '', assignee: '', scanner: '', rule_id: '', q: '', tag: '', kev: false, kev_ransomware: false, reachable: false, include_duplicates: false, all_versions: false };
		searchText = '';
		cf = { key: '', value: '' };
		applyFilters();
	}
	// A new search ranks by relevance unless an explicit order was picked.
	/** @param {SubmitEvent} e */
	function search(e) {
		e.preventDefault();
		const q = searchText.trim();
		if (q && !filters.q && filters.sort === 'priority') filters.sort = '';
		filters.q = q;
		applyFilters();
	}
	/** @param {string} tag */
	function filterByTag(tag) {
		filters.tag = tag;
		applyFilters();
	}
	/** @param {number} newOffset */
	function gotoPage(newOffset) {
		offset = newOffset;
		loadFindings();
	}
	// After triage empties the visible page, pull the next batch (same filters).
	function refillIfEmpty() {
		if (findings.length === 0 && meta.has_more) loadFindings();
	}

	// Bulk edit: one server call applies the change to the selection — or to
	// everything matching the filter — each finding authorized on its own
	// project and the change recorded in its history.
	/** @param {Record<string, unknown>} change @param {string} what @param {(f: any) => boolean} stillMatches */
	async function bulkApply(change, what, stillMatches) {
		const ids = selectedIds;
		if (ids.length === 0) return;
		bulkBusy = true;
		const byFilter = allMatching;
		try {
			const res = await api.bulkUpdateFindings(byFilter ? { filter: filterQuery() } : { ids }, change);
			const ok = res.updated?.length ?? 0;
			const failed = res.failed?.length ?? 0;
			const held = (res.pending?.length ?? 0) + (res.acceptances?.length ?? 0);
			if (held > 0) {
				// ASSESSMENT_REQUIRES_APPROVAL: status / severity wait for a reviewer.
				notify($t('findings.submitted', { count: held }) + (failed ? ' ' + $t('findings.submittedFailed', { count: failed }) : ''),
					failed ? 'error' : 'success');
			} else if (failed === 0) notify($t('findings.bulkDone', { count: ok, change: what }), 'success');
			else notify($t('findings.bulkPartial', { ok, failed }));
			if (byFilter) {
				offset = 0;
				await loadFindings();
				return;
			}
			// The server's copy carries what the change implies (SLA paused/resumed).
			const updated = Object.fromEntries((res.updated ?? []).map((/** @type {any} */ f) => [f.id, f]));
			findings = findings
				.filter((f) => !updated[f.id] || stillMatches(updated[f.id]))
				.map((f) => (updated[f.id] ? { ...f, ...updated[f.id] } : f));
			clearSelection();
			refillIfEmpty();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			bulkBusy = false;
		}
	}
	// Exception statuses always go through the reason / expiry dialog.
	/** @param {string} status */
	async function bulkTriage(status) {
		/** @type {Record<string, unknown>} */
		let change = { status };
		if (isExceptionStatus(status)) {
			const opts = await triageDialog.open(status, allMatching ? meta.count : selectedIds.length);
			if (!opts) return;
			change = { ...change, ...opts };
		}
		await bulkApply(change, $t('findings.changeSetTo', { status: $labelOf('status', status) }), (/** @type {any} */ f) => matchesFilter(f.status));
	}
	/** @param {any} f */
	const assigneeMatches = (f) =>
		!filters.assignee ||
		(filters.assignee === 'none' ? !f.assignee_id : filters.assignee === 'me' ? f.assignee_id === $me?.id : f.assignee_id === filters.assignee);
	const bulkAssignMe = () => bulkApply({ assignee_id: $me?.id }, $t('findings.changeAssigned'), assigneeMatches);
	const bulkUnassign = () => bulkApply({ assignee_id: null }, $t('findings.changeUnassigned'), assigneeMatches);
	/** @param {any} f */
	const tagMatches = (f) => !filters.tag || filters.tag.split(',').every((tg) => f.tags?.includes(tg));
	async function bulkTag() {
		const tag = prompt($t('findings.tagPrompt'))?.trim().toLowerCase();
		if (!tag) return;
		await bulkApply({ add_tags: [tag] }, $t('findings.changeTagged', { tag }), tagMatches);
		tags = await api.findingTags().catch(() => tags);
	}
	async function bulkUntag() {
		const tag = filters.tag.split(',')[0];
		await bulkApply({ remove_tags: [tag] }, $t('findings.changeUntagged', { tag }), tagMatches);
		tags = await api.findingTags().catch(() => tags);
	}

	// Put a row back as it was (a failed or held optimistic change).
	/** @param {any} f @param {number} at its index before the change */
	function restoreRow(f, at) {
		findings = findings.some((x) => x.id === f.id)
			? findings.map((x) => (x.id === f.id ? f : x))
			: [...findings.slice(0, at), f, ...findings.slice(at)];
	}

	// Inline triage: optimistic status update so a backlog clears without
	// leaving the page; rolled back if the server refuses. Exception statuses
	// ask for a reason first — cancelling changes nothing.
	/** @param {any} f @param {string} status */
	async function triage(f, status) {
		editing = '';
		if (f.status === status || busy === f.id) return;
		/** @type {Record<string, unknown>} */
		let opts = {};
		if (isExceptionStatus(status)) {
			const o = await triageDialog.open(status);
			if (!o) return;
			opts = o;
		}
		const at = findings.findIndex((x) => x.id === f.id);
		if (at < 0) return;
		busy = f.id;
		findings = matchesFilter(status)
			? findings.map((x) => (x.id === f.id ? { ...x, status } : x))
			: findings.filter((x) => x.id !== f.id);
		try {
			const updated = await api.setFindingStatus(f.id, status, opts);
			if (updated?.state === 'pending' || updated?.state === 'requested') {
				// Held for approval (an assessment, or a risk acceptance request).
				restoreRow(f, at);
				notify(updated.state === 'requested' ? $t('findings.raRequested') : $t('findings.forApproval'), 'success');
				return;
			}
			// The server's copy carries what the change implies (SLA paused/resumed).
			findings = findings.map((x) => (x.id === f.id ? { ...x, ...updated } : x));
			notify($t('findings.setTo', { status: $labelOf('status', status) }), 'success');
			refillIfEmpty();
		} catch (err) {
			restoreRow(f, at);
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	/** @param {any} f */
	async function assignToMe(f) {
		const user = $me;
		if (!user) return notify($t('findings.whoAreYou'));
		if (f.assignee_id === user.id) return;
		const at = findings.findIndex((x) => x.id === f.id);
		findings = findings.map((x) => (x.id === f.id ? { ...x, assignee_id: user.id, assignee_email: user.email } : x));
		try {
			await api.assignFinding(f.id, user.id);
			notify($t('findings.assignedToYou'), 'success');
		} catch (err) {
			restoreRow(f, at);
			notify(errorMessage(err));
		}
	}

	// Keymap (see #lib/keyboard.js): triage keys act on the selection if any,
	// else on the highlighted row.
	/** @param {KeyboardEvent} e */
	function onkeydown(e) {
		handleListKey(e, {
			move: (d) => cursor.move(d, findings.length),
			toggle: (range) => {
				if (!cursorRow) return;
				if (range) {
					const [lo, hi] = cursor.range();
					const next = { ...selected };
					for (const f of findings.slice(lo, hi + 1)) next[f.id] = true;
					selected = next;
				} else {
					selected[cursorRow.id] = !selected[cursorRow.id];
					if (!selected[cursorRow.id]) allMatching = false;
				}
				cursor.mark(cursor.index);
			},
			open: () => cursorRow && goto(`/findings/${cursorRow.id}`),
			triage: (status) => {
				if (bulkBusy) return;
				if (selectedIds.length > 0) bulkTriage(status);
				else if (cursorRow) triage(cursorRow, status);
			},
			assignMe: () => {
				if (bulkBusy) return;
				if (selectedIds.length > 0) bulkAssignMe();
				else if (cursorRow) assignToMe(cursorRow);
			},
			editStatus: () => cursorRow && (editing = cursorRow.id),
			focusSearch: () => searchEl?.focus(),
			escape: () => {
				clearSelection();
				editing = '';
			}
		});
	}

	onMount(async () => {
		projects = await api.listProjects().catch(() => []);
		api.findingTags().then((tg) => (tags = tg)).catch(() => {});
		await loadFindings();
	});
</script>

<svelte:window {onkeydown} />

<div class="mb-5 flex items-end justify-between gap-3">
	<div>
		<h1 class="text-2xl font-bold">{$t('findings.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('findings.subtitle')}</p>
	</div>
	<div class="flex items-center gap-3">
		{#if !loading && findings.length > 0}
			<div class="hidden text-xs text-base-content/50 sm:block">
				{$t('findings.shown', { count: findings.length })}{meta.has_more ? ` · ${$t('findings.more')}` : ''}
			</div>
		{/if}
		<ExportMenu run={(/** @type {'csv' | 'xlsx'} */ format) => api.exportFindings({ sort: filters.sort, ...filterQuery() }, format)}
			disabled={!loading && findings.length === 0} />
	</div>
</div>

<form class="mb-2 flex gap-2" onsubmit={search} role="search">
	<input
		type="search"
		bind:this={searchEl}
		bind:value={searchText}
		placeholder={$t('findings.searchPlaceholder')}
		class="input input-bordered input-sm w-full max-w-xl"
		aria-label={$t('findings.searchAria')}
	/>
	<button class="btn btn-sm">{$t('findings.search')}</button>
</form>

<div class="mb-3 flex flex-wrap items-center gap-2">
	<select bind:value={filters.sort} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="priority">{$t('findings.sortPriority')}</option>
		<option value="sla_due">{$t('findings.sortSla')}</option>
		<option value="">{filters.q ? $t('findings.sortRelevance') : $t('findings.sortRecent')}</option>
	</select>
	{#if cfFields.length > 0}
		{@const cfDef = cfFields.find((f) => f.key === cf.key)}
		<div class="join">
			<select bind:value={cf.key} onchange={() => { cf.value = ''; applyFilters(); }} class="select select-bordered select-sm join-item max-w-40" aria-label={$t('findings.cfField')}>
				<option value="">{$t('findings.cfFieldPick')}</option>
				{#each cfFields as f (f.id)}<option value={f.key}>{f.label}</option>{/each}
			</select>
			{#if cf.key}
				{#if cfDef?.type === 'enum'}
					<select bind:value={cf.value} onchange={applyFilters} class="select select-bordered select-sm join-item" aria-label={$t('findings.cfValue')}>
						<option value="">{$t('findings.cfAny')}</option>
						{#each cfDef.options as o}<option value={o}>{o}</option>{/each}
					</select>
				{:else}
					<input bind:value={cf.value} onchange={applyFilters} placeholder={$t('findings.cfEquals')} aria-label={$t('findings.cfValue')}
						type={cfDef?.type === 'number' ? 'number' : cfDef?.type === 'date' ? 'date' : 'text'}
						class="input input-bordered input-sm join-item w-36" />
				{/if}
			{/if}
		</div>
	{/if}
	{#if tags.length > 0 || filters.tag}
		<select bind:value={filters.tag} onchange={applyFilters} class="select select-bordered select-sm max-w-40">
			<option value="">{$t('findings.anyTag')}</option>
			{#each tags as tg (tg.tag)}<option value={tg.tag}>{tg.tag} ({fmtNumber(tg.count)})</option>{/each}
			{#if filters.tag && !tags.some((tg) => tg.tag === filters.tag)}<option value={filters.tag}>{filters.tag}</option>{/if}
		</select>
	{/if}
	<select bind:value={filters.status} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="">{$t('findings.allStatuses')}</option>
		{#each STATUSES as s}<option value={s}>{$labelOf('status', s)}</option>{/each}
	</select>
	<select bind:value={filters.severity} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="">{$t('findings.allSeverities')}</option>
		{#each SEVERITIES as s}<option value={s}>{$labelOf('severity', s)}</option>{/each}
	</select>
	<select bind:value={filters.category} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="">{$t('findings.allCategories')}</option>
		{#each CATEGORIES as c}<option value={c}>{$labelOf('category', c)}</option>{/each}
	</select>
	<select bind:value={filters.sla} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="">{$t('findings.anySla')}</option>
		{#each SLA_STATUSES as v}<option value={v}>{$labelOf('sla', v)}</option>{/each}
	</select>
	<select bind:value={filters.exploit} onchange={applyFilters} class="select select-bordered select-sm" title={$t('findings.exploitTitle')}>
		<option value="">{$t('findings.anyExploit')}</option>
		<option value="any">{$t('findings.publicExploit')}</option>
		<option value="weaponized">{$t('findings.weaponized')}</option>
		<option value="poc">{$t('findings.poc')}</option>
	</select>
	<select bind:value={filters.assignee} onchange={applyFilters} class="select select-bordered select-sm">
		<option value="">{$t('findings.anyone')}</option>
		<option value="me">{$t('findings.assignedToMe')}</option>
		<option value="none">{$t('findings.unassigned')}</option>
	</select>
	<select bind:value={filters.project_id} onchange={applyFilters} class="select select-bordered select-sm max-w-40">
		<option value="">{$t('findings.allProjects')}</option>
		{#each projects as pr}<option value={pr.id}>{pr.name}</option>{/each}
	</select>
	<label class="label cursor-pointer gap-2">
		<input type="checkbox" bind:checked={filters.kev} onchange={applyFilters} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('findings.kevOnly')}</span>
	</label>
	<label class="label cursor-pointer gap-2" title={$t('finding.ransomwareTitle')}>
		<input type="checkbox" bind:checked={filters.kev_ransomware} onchange={applyFilters} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('findings.ransomwareOnly')}</span>
	</label>
	<label class="label cursor-pointer gap-2" title={$t('findings.reachableTitle')}>
		<input type="checkbox" bind:checked={filters.reachable} onchange={applyFilters} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('findings.reachableOnly')}</span>
	</label>
	<label class="label cursor-pointer gap-2" title={$t('findings.duplicatesTitle')}>
		<input type="checkbox" bind:checked={filters.include_duplicates} onchange={applyFilters} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('findings.showDuplicates')}</span>
	</label>
	<label class="label cursor-pointer gap-2" title={$t('findings.branchesTitle')}>
		<input type="checkbox" bind:checked={filters.all_versions} onchange={applyFilters} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('findings.allBranches')}</span>
	</label>
	{#if filters.scanner || filters.rule_id}
		<span class="badge badge-ghost gap-1" title={$t('findings.linkFilterTitle')}>
			{filters.scanner ? $t('findings.linkScanner', { name: filters.scanner }) : ''}{filters.scanner && filters.rule_id ? ' · ' : ''}{filters.rule_id ? $t('findings.linkRule', { id: filters.rule_id.slice(0, 8) }) : ''}
		</span>
	{/if}
	{#if anyFilter}
		<button class="btn btn-ghost btn-sm" onclick={clearFilters}>{$t('findings.clear')}</button>
	{/if}
</div>

<State {loading} {error} empty={!loading && !error && findings.length === 0}
	emptyText={$t('findings.empty')} />

{#if !loading && findings.length > 0}
	<div class="overflow-x-auto rounded-box bg-base-100 shadow-sm">
		<table class="table table-sm">
			<thead>
				<tr>
					<th class="w-8">
						<input bind:this={selectAllEl} type="checkbox" class="checkbox checkbox-sm" checked={allSelected} onchange={toggleAll} aria-label={$t('findings.selectAll')} />
					</th>
					<th>{$t('findings.colPriority')}</th><th>{$t('findings.colSeverity')}</th><th>{$t('findings.colTitle')}</th><th>{$t('findings.colProject')}</th><th>{$t('findings.colPackage')}</th><th>{$t('findings.colScanner')}</th><th>{$t('findings.colStatus')}</th><th>{$t('findings.colSla')}</th><th>{$t('findings.colOwner')}</th><th></th>
				</tr>
			</thead>
			<tbody>
				{#each findings as f, i (f.id)}
					<tr class="group hover cursor-pointer {selected[f.id] ? 'bg-primary/5' : ''} {cursor.index === i ? 'bg-base-200 outline-2 -outline-offset-2 outline-primary' : ''}"
						aria-selected={cursor.index === i ? 'true' : undefined} onclick={() => goto(`/findings/${f.id}`)}>
						<td class="border-l-4 {severityAccent(f.severity)}" onclick={(e) => e.stopPropagation()}>
							<input type="checkbox" class="checkbox checkbox-sm" checked={!!selected[f.id]} onchange={(e) => (selected[f.id] = e.currentTarget.checked)} aria-label={$t('findings.selectFinding')} />
						</td>
						<td>
							<span class="font-semibold tabular-nums">{fmtNumber(Math.round(f.priority))}</span>
							{#if f.kev}<span class="badge badge-error badge-xs ml-1" title={kevCatalogs(f.kev_sources) || 'KEV'}>KEV</span>{/if}
							{#if f.kev_ransomware}<span class="badge badge-error badge-outline badge-xs ml-1" title={$t('finding.ransomwareTitle')}>{$t('finding.ransomware')}</span>{/if}
							<ExploitBadge maturity={f.exploit_maturity} />
							{#if f.epss}<span class="ml-1 text-xs text-base-content/40" title="EPSS">{fmtNumber(f.epss, { style: 'percent' })}</span>{/if}
						</td>
						<td><Badge kind="severity" value={f.severity} /></td>
						<td class="max-w-sm">
							<div class="truncate">{f.title}</div>
							{#if f.tags?.length}
								<div class="mt-0.5 flex flex-wrap gap-1">
									{#each f.tags as tg (tg)}
										<button class="badge badge-outline badge-xs hover:badge-primary" title={$t('findings.onlyTagged', { tag: tg })}
											onclick={(e) => { e.stopPropagation(); filterByTag(tg); }}>{tg}</button>
									{/each}
								</div>
							{/if}
						</td>
						<td class="text-xs">{projectName(f.project_id)}</td>
						<td class="text-xs">
							{f.package_name || '—'}{#if f.package_version}<span class="text-base-content/50"> @{f.package_version}</span>{/if}
							{#if f.dep_scope === 'dev'}<span class="badge badge-ghost badge-xs ml-1" title={$t('findings.devTitle')}>{$t('findings.dev')}</span>
							{:else if f.dep_scope === 'optional'}<span class="badge badge-ghost badge-xs ml-1" title={$t('findings.optionalTitle')}>{$t('findings.optional')}</span>{/if}
							{#if f.dep_direct === false}<span class="badge badge-ghost badge-xs ml-1" title="{$t('findings.transitiveTitle')}{f.dep_depth ? ' ' + $t('findings.depth', { depth: f.dep_depth }) : ''}">{$t('findings.transitive')}</span>{/if}
						</td>
						<td class="text-xs">
							{f.scanner}
							{#if f.duplicate_count}<span class="badge badge-ghost badge-xs ml-1" title={$t('findings.alsoReported', { count: f.duplicate_count })}>+{f.duplicate_count}</span>{/if}
							{#if f.duplicate_of}<span class="badge badge-ghost badge-xs ml-1 opacity-60" title={$t('findings.dupTitle')}>{$t('findings.dup')}</span>{/if}
						</td>
						<td onclick={(e) => e.stopPropagation()}>
							<StatusCell status={f.status} editing={editing === f.id} disabled={busy === f.id}
								onedit={() => (editing = f.id)} onpick={(s) => triage(f, s)} oncancel={() => (editing = '')} />
						</td>
						<td><SlaBadge status={f.sla_status} due={f.sla_due_at} /></td>
						<td class="max-w-32 truncate text-xs" title={f.assignee_email ?? $t('findings.unassigned')}>
							{#if f.assignee_email}{f.assignee_email.split('@')[0]}{:else}<span class="text-base-content/30">—</span>{/if}
						</td>
						<td class="text-right" onclick={(e) => e.stopPropagation()}>
							<div class="flex justify-end gap-1 opacity-100 transition-opacity sm:opacity-0 sm:group-hover:opacity-100 sm:focus-within:opacity-100">
								{#each actionsFor(f) as a (a.status)}
									<button
										class="btn btn-ghost btn-xs whitespace-nowrap"
										disabled={busy === f.id}
										title={$t(a.title)}
										onclick={() => triage(f, a.status)}
									>{$t(a.label)}</button>
								{/each}
							</div>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<Pagination limit={meta.limit} offset={meta.offset} count={meta.count} hasMore={meta.has_more} onchange={gotoPage} />
	<button type="button" class="mt-2 text-xs text-base-content/50 hover:text-base-content" onclick={() => help.toggle()}>
		{$t('findings.press')} <kbd class="kbd kbd-xs">?</kbd> {$t('findings.keyHelp')}
	</button>
{/if}

{#if selectedIds.length > 0}
	<div class="pointer-events-none fixed inset-x-0 bottom-4 z-40 flex justify-center px-4">
		<div class="pointer-events-auto flex max-w-full items-center gap-1 overflow-x-auto rounded-full bg-base-100 px-3 py-2 shadow-xl ring-1 ring-base-content/10">
			<span class="whitespace-nowrap px-2 text-sm font-medium">{allMatching ? $t('findings.allMatching') : $t('findings.selected', { count: selectedIds.length })}</span>
			{#if allSelected && meta.has_more && !allMatching}
				<button class="btn btn-link btn-sm whitespace-nowrap px-1" title={$t('findings.selectAllMatchingTitle')} onclick={() => (allMatching = true)}>{$t('findings.selectAllMatching')}</button>
			{/if}
			<div class="mx-1 h-5 w-px bg-base-300"></div>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.actFPTitle')} onclick={() => bulkTriage('false_positive')}>{$t('findings.actFP')}</button>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.actAcceptTitle')} onclick={() => bulkTriage('risk_accepted')}>{$t('findings.actAccept')}</button>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.actWontTitle')} onclick={() => bulkTriage('wont_fix')}>{$t('findings.actWont')}</button>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.reopenTitle')} onclick={() => bulkTriage('open')}>{$t('findings.actReopen')}</button>
			<div class="mx-1 h-5 w-px bg-base-300"></div>
			<button class="btn btn-ghost btn-sm whitespace-nowrap" disabled={bulkBusy || !$me} title={$t('findings.takeTitle')} onclick={bulkAssignMe}>{$t('findings.take')}</button>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.unassign')} onclick={bulkUnassign}>{$t('findings.unassign')}</button>
			<div class="mx-1 h-5 w-px bg-base-300"></div>
			<button class="btn btn-ghost btn-sm" disabled={bulkBusy} title={$t('findings.tagTitle')} onclick={bulkTag}>{$t('findings.tag')}</button>
			{#if filters.tag}
				<button class="btn btn-ghost btn-sm whitespace-nowrap" disabled={bulkBusy} title={$t('findings.untagTitle')} onclick={bulkUntag}>{$t('findings.untag', { tag: filters.tag.split(',')[0] })}</button>
			{/if}
			{#if bulkBusy}<span class="loading loading-spinner loading-sm mx-1"></span>{/if}
			<button class="btn btn-ghost btn-circle btn-sm" onclick={clearSelection} aria-label={$t('findings.clearSelection')}>✕</button>
		</div>
	</div>
{/if}

<TriageDialog bind:this={triageDialog} />
<KeyboardHelp bind:this={help} search />
