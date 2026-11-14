<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { me, notify } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';
	import Badge from '#lib/components/Badge.svelte';
	import { fmtDate } from '#lib/format.js';

	const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
	/** @type {{ id: string, labelKey: import('#lib/i18n.js').MessageKey, shortKey: import('#lib/i18n.js').MessageKey, tone: string }[]} */
	const STATES = [
		{ id: 'fail', labelKey: 'pol.state.fail', shortKey: 'pol.stateShort.fail', tone: 'badge-error' },
		{ id: 'warn', labelKey: 'pol.state.warn', shortKey: 'pol.stateShort.warn', tone: 'badge-warning' },
		{ id: 'info', labelKey: 'pol.state.info', shortKey: 'pol.stateShort.info', tone: 'badge-info' }
	];
	// Subjects, their operators, and how the value is entered (mirrors
	// internal/policy/condition.go — the API validates every condition).
	/** @type {{ id: string, groupKey: import('#lib/i18n.js').MessageKey, labelKey: import('#lib/i18n.js').MessageKey, ops: string[], input: string, placeholder?: string, min?: number }[]} */
	const SUBJECTS = [
		{ id: 'severity', groupKey: 'pol.group.security', labelKey: 'pol.subject.severity', ops: ['gte'], input: 'severity' },
		{ id: 'vulnerability_id', groupKey: 'pol.group.security', labelKey: 'pol.subject.vulnerabilityId', ops: ['is', 'matches'], input: 'list', placeholder: 'CVE-2021-44228, GHSA-*' },
		{ id: 'kev', groupKey: 'pol.group.security', labelKey: 'pol.subject.kev', ops: ['is'], input: 'bool' },
		{ id: 'epss', groupKey: 'pol.group.security', labelKey: 'pol.subject.epss', ops: ['gte'], input: 'epss' },
		{ id: 'cwe', groupKey: 'pol.group.security', labelKey: 'pol.subject.cwe', ops: ['in'], input: 'cwe', placeholder: '79, 89' },
		{ id: 'license', groupKey: 'pol.group.license', labelKey: 'pol.subject.license', ops: ['is', 'is_not'], input: 'license', placeholder: 'GPL-3.0*, AGPL-3.0*' },
		{ id: 'license_group', groupKey: 'pol.group.license', labelKey: 'pol.subject.licenseGroup', ops: ['in', 'not_in'], input: 'groups' },
		{ id: 'license_unresolved', groupKey: 'pol.group.license', labelKey: 'pol.subject.licenseUnresolved', ops: ['is'], input: 'bool' },
		{ id: 'outdated', groupKey: 'pol.group.operational', labelKey: 'pol.subject.outdated', ops: ['is'], input: 'bool' },
		{ id: 'versions_behind', groupKey: 'pol.group.operational', labelKey: 'pol.subject.versionsBehind', ops: ['gte'], input: 'int', min: 1 },
		{ id: 'age', groupKey: 'pol.group.operational', labelKey: 'pol.subject.age', ops: ['gte'], input: 'int', min: 1 },
		{ id: 'missing_hash', groupKey: 'pol.group.operational', labelKey: 'pol.subject.missingHash', ops: ['is'], input: 'hash' },
		{ id: 'integrity', groupKey: 'pol.group.operational', labelKey: 'pol.subject.integrity', ops: ['is'], input: 'integrity' },
		{ id: 'coordinates', groupKey: 'pol.group.operational', labelKey: 'pol.subject.coordinates', ops: ['matches', 'no_match'], input: 'coordinates' },
		{ id: 'purl', groupKey: 'pol.group.operational', labelKey: 'pol.subject.purl', ops: ['matches', 'no_match'], input: 'list', placeholder: 'pkg:npm/event-stream@*' },
		{ id: 'package_type', groupKey: 'pol.group.operational', labelKey: 'pol.subject.packageType', ops: ['in', 'not_in'], input: 'list', placeholder: 'npm, maven' },
		{ id: 'component.kind', groupKey: 'pol.group.ai', labelKey: 'pol.subject.componentKind', ops: ['in', 'not_in'], input: 'list', placeholder: 'model, dataset, ai-service' },
		{ id: 'model.name', groupKey: 'pol.group.ai', labelKey: 'pol.subject.modelName', ops: ['no_match', 'matches'], input: 'list', placeholder: 'mistralai/*, google/flan-t5-*' },
		{ id: 'model.supplier', groupKey: 'pol.group.ai', labelKey: 'pol.subject.modelSupplier', ops: ['not_in', 'in'], input: 'list', placeholder: 'Hugging Face, Mistral AI' },
		{ id: 'model.license', groupKey: 'pol.group.ai', labelKey: 'pol.subject.modelLicense', ops: ['is_not', 'is'], input: 'license', placeholder: 'Apache-2.0, MIT' },
		{ id: 'model.task', groupKey: 'pol.group.ai', labelKey: 'pol.subject.modelTask', ops: ['not_in', 'in'], input: 'list', placeholder: 'text-generation, text-classification' },
		{ id: 'dataset.name', groupKey: 'pol.group.ai', labelKey: 'pol.subject.datasetName', ops: ['no_match', 'matches'], input: 'list', placeholder: 'wikipedia, ultrachat_*' },
		{ id: 'expression', groupKey: 'pol.group.advanced', labelKey: 'pol.subject.expression', ops: ['matches'], input: 'expression',
			placeholder: 'vulns.kev && pkg.versions_behind >= 3' }
	];
	/** @param {string} id */
	const subject = (id) => SUBJECTS.find((s) => s.id === id) ?? SUBJECTS[0];
	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const OP_LABEL_KEY = {
		is: 'pol.op.is', is_not: 'pol.op.isNot', matches: 'pol.op.matches', no_match: 'pol.op.noMatch',
		in: 'pol.op.in', not_in: 'pol.op.notIn', gte: 'pol.op.gte'
	};
	const EXPR_OP_LABEL_KEY = 'pol.op.holds';
	/** @type {Record<string, Record<string, import('#lib/i18n.js').MessageKey>>} */
	const OP_HINT_KEY = {
		license: { is: 'pol.hint.licenseIs', is_not: 'pol.hint.licenseIsNot' },
		'model.name': { no_match: 'pol.hint.modelNameNoMatch', matches: 'pol.hint.modelNameMatches' },
		'model.supplier': { not_in: 'pol.hint.modelSupplierNotIn', in: 'pol.hint.modelSupplierIn' },
		'dataset.name': { no_match: 'pol.hint.datasetNameNoMatch', matches: 'pol.hint.datasetNameMatches' },
		license_group: { in: 'pol.hint.licenseGroupIn', not_in: 'pol.hint.licenseGroupNotIn' }
	};

	let policies = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);
	let projects = $state(/** @type {any[]} */ ([]));
	// Every tag in use on a project the caller can see, for the tag pickers.
	const projectTags = $derived([...new Set(projects.flatMap((p) => p.tags ?? []))].sort());
	let groups = $state(/** @type {{ custom: any[], builtin: any[] }} */ ({ custom: [], builtin: [] }));
	let licenseHints = $state(/** @type {string[]} */ ([]));
	let evaluating = $state(false);
	// The policy being edited (null = a new one); the form is open when set.
	let editing = $state(/** @type {any} */ (null));
	let form = $state(blankForm());
	// Dry-run result: { title, components, total, truncated, violations } — null when closed.
	let preview = $state(/** @type {any} */ (null));
	let previewing = $state(false);
	let previewProject = $state('');
	// The policy whose violations are listed: { policy, findings } — null when closed.
	let shown = $state(/** @type {any} */ (null));

	const isAdmin = $derived(!!$me?.is_admin);

	/** @typedef {ReturnType<typeof blankCondition>} Cond */
	function blankCondition(id = 'license') {
		const s = subject(id);
		return { subject: s.id, operator: s.ops[0], text: '', bool: 'true', num: '', severity: 'high', hash: 'strong', integrity: 'mismatch', refs: /** @type {string[]} */ ([]), group: '', name: '', version: '' };
	}
	function blankForm() {
		return {
			name: '', description: '', enabled: true, operator: 'any', violation_state: 'fail',
			scope: 'global', project_ids: /** @type {string[]} */ ([]), include_tags: '', exclude_tags: '',
			versions: 'all', conditions: [blankCondition()]
		};
	}

	/** @param {string} s */
	const splitList = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);

	// toValue turns a condition row into the API's value for its subject.
	/** @param {Cond} c */
	function toValue(c) {
		switch (subject(c.subject).input) {
			case 'severity': return c.severity;
			case 'bool': return c.bool === 'true';
			case 'epss': return c.num === '' ? null : Number(c.num);
			case 'int': return c.num === '' ? null : Math.trunc(Number(c.num));
			case 'cwe': return splitList(c.text).map((x) => Number(x.replace(/^CWE-/i, '')));
			case 'hash': return c.hash;
			case 'integrity': return c.integrity;
			case 'groups': return c.refs;
			case 'coordinates': return { group: c.group, name: c.name, version: c.version };
			case 'expression': return c.text.trim();
			default: return splitList(c.text);
		}
	}
	// fromValue is toValue's inverse, for editing a stored policy.
	/** @param {any} cond */
	function fromValue(cond) {
		const c = { ...blankCondition(cond.subject), operator: cond.operator };
		const v = cond.value;
		switch (subject(cond.subject).input) {
			case 'severity': c.severity = v; break;
			case 'bool': c.bool = String(v); break;
			case 'epss': case 'int': c.num = String(v); break;
			case 'hash': c.hash = v; break;
			case 'integrity': c.integrity = v; break;
			case 'groups': c.refs = [...v]; break;
			case 'coordinates': Object.assign(c, { group: v.group ?? '', name: v.name ?? '', version: v.version ?? '' }); break;
			case 'expression': c.text = v; break;
			default: c.text = (Array.isArray(v) ? v : [v]).join(', ');
		}
		return c;
	}

	/** @param {string} s @returns {string[]} */
	function splitTags(s) {
		return s.split(',').map((t) => t.trim()).filter(Boolean);
	}

	function body() {
		return {
			name: form.name, description: form.description, enabled: form.enabled,
			operator: form.operator, violation_state: form.violation_state,
			scope: form.scope, project_ids: form.scope === 'projects' ? form.project_ids : [],
			include_tags: splitTags(form.include_tags), exclude_tags: splitTags(form.exclude_tags),
			versions: form.versions,
			conditions: form.conditions.map((c) => ({ subject: c.subject, operator: c.operator, value: toValue(c) }))
		};
	}

	async function load() {
		loading = true;
		try {
			policies = await api.listPolicies();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(() => {
		load();
		// Pickers: best-effort, the form still works with typed values.
		api.listProjects().then((p) => (projects = p)).catch(() => {});
		api.listLicenseGroups()
			.then((r) => (groups = { custom: r.groups ?? [], builtin: r.builtin ?? [] }))
			.catch(() => {});
	});

	// License-id suggestions for the row being typed in (catalog search).
	/** @type {ReturnType<typeof setTimeout> | undefined} */
	let hintTimer;
	/** @param {string} text */
	function suggestLicenses(text) {
		clearTimeout(hintTimer);
		const last = (text.split(',').pop() ?? '').trim().replace(/\*$/, '');
		if (last.length < 2) return;
		hintTimer = setTimeout(() => {
			api.listLicenses({ q: last, limit: 20 })
				.then((r) => (licenseHints = (r.licenses ?? []).map((/** @type {any} */ l) => l.id)))
				.catch(() => {});
		}, 200);
	}

	/** @param {Cond} c @param {string} id */
	function setSubject(c, id) {
		Object.assign(c, blankCondition(id));
	}
	const addCondition = () => (form.conditions = [...form.conditions, blankCondition('severity')]);
	/** @param {number} i */
	const removeCondition = (i) => (form.conditions = form.conditions.filter((_, j) => j !== i));
	/** @param {Cond} c @param {string} ref */
	function toggleRef(c, ref) {
		c.refs = c.refs.includes(ref) ? c.refs.filter((r) => r !== ref) : [...c.refs, ref];
	}
	/** @param {string} id */
	function toggleProject(id) {
		form.project_ids = form.project_ids.includes(id) ? form.project_ids.filter((p) => p !== id) : [...form.project_ids, id];
	}

	function openNew() {
		editing = { id: null };
		form = blankForm();
		preview = null;
	}
	/** @param {any} p */
	function openEdit(p) {
		editing = p;
		form = {
			name: p.name, description: p.description, enabled: p.enabled, operator: p.operator,
			violation_state: p.violation_state, scope: p.scope, project_ids: [...(p.project_ids ?? [])],
			include_tags: (p.include_tags ?? []).join(', '), exclude_tags: (p.exclude_tags ?? []).join(', '),
			versions: p.versions, conditions: p.conditions.map(fromValue)
		};
		preview = null;
	}
	function closeForm() {
		editing = null;
		preview = null;
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			if (editing?.id) await api.updatePolicy(editing.id, body());
			else await api.createPolicy(body());
			notify($t('pol.savedToast'), 'success');
			closeForm();
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} p */
	async function toggle(p) {
		try {
			await api.updatePolicy(p.id, { ...p, enabled: !p.enabled });
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	/** @param {any} p */
	async function remove(p) {
		if (!confirm($t('pol.confirmDelete', { name: p.name }))) return;
		try {
			await api.deletePolicy(p.id);
			if (shown?.policy.id === p.id) shown = null;
			await load();
		} catch (err) {
			notify(errorMessage(err));
		}
	}
	async function evaluateNow() {
		evaluating = true;
		try {
			const res = await api.evaluatePolicies();
			notify($t('pol.evaluatedToast', { projects: res.projects, violations: res.violations }), 'success');
			await load();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			evaluating = false;
		}
	}

	/** @param {string} title @param {any} draft */
	async function runPreview(title, draft) {
		previewing = true;
		try {
			const res = await api.previewPolicy(draft, previewProject || undefined);
			preview = { title, ...res };
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			previewing = false;
		}
	}
	const previewForm = () => runPreview(form.name || $t('pol.newPolicy'), body());
	/** @param {any} p */
	const previewStored = (p) => runPreview(p.name, { ...p, enabled: true });

	/** @param {any} p */
	async function showViolations(p) {
		try {
			const res = await api.policyViolations(p.id, { limit: 200 });
			shown = { policy: p, findings: res.findings ?? [], more: res.pagination?.has_more };
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {string} id */
	const stateOf = (id) => STATES.find((s) => s.id === id) ?? STATES[0];
	/** @param {any} c */
	function valueText(c) {
		const v = c.value;
		if (Array.isArray(v)) return v.join(', ');
		if (v && typeof v === 'object') return ['group', 'name', 'version'].filter((k) => v[k]).map((k) => `${k} ${v[k]}`).join(' · ');
		return String(v);
	}
	/** @param {any} c */
	const conditionText = (c) => `${c.subject} ${OP_LABEL_KEY[c.operator] ? $t(OP_LABEL_KEY[c.operator]) : c.operator} ${valueText(c)}`;
	/** @param {string} id */
	const projectName = (id) => projects.find((p) => p.id === id)?.name ?? id.slice(0, 8);
	/** @param {string} ref */
	const groupLabel = (ref) => groups.custom.find((g) => g.id === ref)?.name ?? ref;
</script>

<div class="flex items-center justify-between mb-2">
	<div>
		<h1 class="text-2xl font-bold">{$t('pol.title')}</h1>
		<p class="text-sm text-base-content/60 mb-4">
			{$t('pol.subtitle1')} <code>policy</code>{$t('pol.subtitle2')}
		</p>
	</div>
	{#if isAdmin}
		<div class="flex gap-2 shrink-0">
			<button class="btn btn-ghost btn-sm" onclick={evaluateNow} disabled={evaluating}>
				{#if evaluating}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('pol.evaluateNow')}
			</button>
			<button class="btn btn-primary btn-sm" onclick={openNew}>{$t('pol.newPolicy')}</button>
		</div>
	{/if}
</div>

{#if editing}
	<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 mb-5 grid gap-3 md:grid-cols-2">
		<h2 class="md:col-span-2 font-semibold">{editing.id ? $t('pol.editHeading', { name: editing.name }) : $t('pol.newPolicy')}</h2>
		<Field label={$t('home.name')} required>
			<input bind:value={form.name} required placeholder={$t('pol.namePlaceholder')} class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('lic.description')}>
			<input bind:value={form.description} placeholder={$t('pol.descriptionPlaceholder')} class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('pol.violationStateLabel')} hint={$t('pol.violationStateHint')}>
			<select bind:value={form.violation_state} class="select select-bordered select-sm w-full">
				{#each STATES as s}<option value={s.id}>{$t(s.labelKey)}</option>{/each}
			</select>
		</Field>
		<Field label={$t('pol.violatedWhen')}>
			<select bind:value={form.operator} class="select select-bordered select-sm w-full">
				<option value="any">{$t('pol.operatorAny')}</option>
				<option value="all">{$t('pol.operatorAll')}</option>
			</select>
		</Field>
		<Field label={$t('pol.appliesTo')}>
			<select bind:value={form.scope} class="select select-bordered select-sm w-full">
				<option value="global">{$t('pol.scopeGlobal')}</option>
				<option value="projects">{$t('pol.scopeProjects')}</option>
			</select>
		</Field>
		<Field label={$t('pol.versionsLabel')} hint={$t('pol.versionsHint')}>
			<select bind:value={form.versions} class="select select-bordered select-sm w-full">
				<option value="all">{$t('pol.versionsAll')}</option>
				<option value="default">{$t('pol.versionsDefault')}</option>
			</select>
		</Field>
		<Field label={$t('pol.includeTagsLabel')} hint={$t('pol.includeTagsHint')}>
			<input bind:value={form.include_tags} list="policy-tags" placeholder="pci, internet-facing"
				class="input input-bordered input-sm w-full" />
		</Field>
		<Field label={$t('pol.excludeTagsLabel')} hint={$t('pol.excludeTagsHint')}>
			<input bind:value={form.exclude_tags} list="policy-tags" placeholder="internal-tool"
				class="input input-bordered input-sm w-full" />
		</Field>
		<datalist id="policy-tags">
			{#each projectTags as tag}<option value={tag}></option>{/each}
		</datalist>
		{#if form.scope === 'projects'}
			<div class="md:col-span-2">
				<span class="label-text font-medium">{$t('pol.projectsLabel')}</span>
				<div class="flex flex-wrap gap-2 mt-1 max-h-40 overflow-y-auto">
					{#each projects as p (p.id)}
						<label class="label cursor-pointer gap-1 py-0">
							<input type="checkbox" class="checkbox checkbox-xs" checked={form.project_ids.includes(p.id)} onchange={() => toggleProject(p.id)} />
							<span class="label-text text-sm">{p.name}</span>
						</label>
					{/each}
				</div>
			</div>
		{/if}

		<div class="md:col-span-2">
			<div class="flex items-center justify-between mb-1">
				<span class="label-text font-medium">{$t('pol.conditionsLabel')}</span>
				<button type="button" class="btn btn-ghost btn-xs" onclick={addCondition}>{$t('pol.addCondition')}</button>
			</div>
			<div class="space-y-2">
				{#each form.conditions as c, i}
					{@const s = subject(c.subject)}
					<div class="flex flex-wrap items-start gap-2 bg-base-200/60 rounded-box p-2">
						<select class="select select-bordered select-sm" value={c.subject} onchange={(e) => setSubject(c, e.currentTarget.value)}>
							{#each ['pol.group.security', 'pol.group.license', 'pol.group.operational', 'pol.group.ai', 'pol.group.advanced'] as g}
								<optgroup label={$t(/** @type {any} */ (g))}>
									{#each SUBJECTS.filter((x) => x.groupKey === g) as x}<option value={x.id}>{$t(x.labelKey)}</option>{/each}
								</optgroup>
							{/each}
						</select>
						<select class="select select-bordered select-sm" bind:value={c.operator}>
							{#each s.ops as op}<option value={op}>{s.input === 'expression' ? $t(EXPR_OP_LABEL_KEY) : OP_LABEL_KEY[op] ? $t(OP_LABEL_KEY[op]) : op}</option>{/each}
						</select>
						<div class="flex-1 min-w-48">
							{#if s.input === 'severity'}
								<select class="select select-bordered select-sm w-full" bind:value={c.severity}>
									{#each SEVERITIES as sev}<option value={sev}>{$labelOf('severity', sev)}</option>{/each}
								</select>
							{:else if s.input === 'bool'}
								<select class="select select-bordered select-sm w-full" bind:value={c.bool}>
									<option value="true">{$t('common.yes')}</option>
									<option value="false">{$t('common.no')}</option>
								</select>
							{:else if s.input === 'epss'}
								<input type="number" min="0" max="1" step="0.01" bind:value={c.num} placeholder="0.1" class="input input-bordered input-sm w-full" />
							{:else if s.input === 'int'}
								<input type="number" min={s.min} step="1" bind:value={c.num} class="input input-bordered input-sm w-full" />
							{:else if s.input === 'hash'}
								<select class="select select-bordered select-sm w-full" bind:value={c.hash}>
									<option value="strong">{$t('pol.hashNone')}</option>
									<option value="any">{$t('pol.hashAny')}</option>
								</select>
							{:else if s.input === 'integrity'}
								<select class="select select-bordered select-sm w-full" bind:value={c.integrity}>
									<option value="mismatch">{$t('pol.integrityMismatchLong')}</option>
									<option value="verified">{$t('pol.integrityVerified')}</option>
								</select>
							{:else if s.input === 'groups'}
								<div class="flex flex-wrap gap-x-3 gap-y-1">
									{#each groups.custom as g (g.id)}
										<label class="label cursor-pointer gap-1 py-0">
											<input type="checkbox" class="checkbox checkbox-xs" checked={c.refs.includes(g.id)} onchange={() => toggleRef(c, g.id)} />
											<span class="label-text text-sm">{g.name}</span>
										</label>
									{/each}
									{#each groups.builtin as g (g.ref)}
										<label class="label cursor-pointer gap-1 py-0">
											<input type="checkbox" class="checkbox checkbox-xs" checked={c.refs.includes(g.ref)} onchange={() => toggleRef(c, g.ref)} />
										<span class="label-text text-sm">{$labelOf('licenseCategory', g.category)} <span class="text-base-content/40">({g.count})</span></span>
										</label>
									{/each}
									{#if groups.custom.length === 0 && groups.builtin.length === 0}
										<span class="text-xs text-base-content/50">{$t('pol.noLicenseGroups')}</span>
									{/if}
								</div>
							{:else if s.input === 'coordinates'}
								<div class="grid grid-cols-3 gap-1">
									<input bind:value={c.group} placeholder={$t('pol.coordGroupPlaceholder')} class="input input-bordered input-sm" />
									<input bind:value={c.name} placeholder={$t('pol.coordNamePlaceholder')} class="input input-bordered input-sm" />
									<input bind:value={c.version} placeholder={$t('pol.coordVersionPlaceholder')} class="input input-bordered input-sm" />
								</div>
							{:else if s.input === 'expression'}
								<textarea bind:value={c.text} rows="2" spellcheck="false" placeholder={s.placeholder}
									class="textarea textarea-bordered textarea-sm w-full font-mono"></textarea>
								<p class="text-xs text-base-content/50 mt-1">
									<a class="link" href="https://cel.dev" target="_blank" rel="noreferrer">CEL</a> {$t('pol.celOver')}
									<code>component</code> (name, group, version, purl, type, hashes, license.ids…),
									<code>vulns</code> (count, ids, max_severity, max_severity_rank, kev, epss, cwes),
									<code>pkg</code> (known, latest, outdated, versions_behind, age_days) {$t('pol.celAnd')}
									<code>project</code> (name, version, default_version). {$t('pol.celCheckedNote')}
								</p>
							{:else if s.input === 'license'}
								<input bind:value={c.text} list="license-ids" oninput={(e) => suggestLicenses(e.currentTarget.value)} placeholder={s.placeholder} class="input input-bordered input-sm w-full font-mono" />
							{:else}
								<input bind:value={c.text} placeholder={s.placeholder} class="input input-bordered input-sm w-full font-mono" />
							{/if}
							{#if OP_HINT_KEY[c.subject]?.[c.operator]}
								<p class="text-xs text-base-content/50 mt-1">{$t(OP_HINT_KEY[c.subject][c.operator])}</p>
							{/if}
						</div>
						<button type="button" class="btn btn-ghost btn-xs text-error" onclick={() => removeCondition(i)} disabled={form.conditions.length === 1} aria-label={$t('pol.removeConditionAria')}>✕</button>
					</div>
				{/each}
			</div>
			<datalist id="license-ids">
				{#each licenseHints as id}<option value={id}></option>{/each}
			</datalist>
			<p class="text-xs text-base-content/50 mt-1">
				{$t('pol.globsIntro')} <code>*</code> {$t('pol.globsAnyRun')} <code>?</code> {$t('pol.globsOneChar')} {$t('pol.globsNote')}
			</p>
		</div>

		<label class="label cursor-pointer justify-start gap-2">
			<input type="checkbox" class="toggle toggle-sm toggle-primary" bind:checked={form.enabled} />
			<span class="label-text">{$t('common.enabled')}</span>
		</label>
		<div class="flex justify-end gap-2 flex-wrap">
			<select class="select select-bordered select-sm" bind:value={previewProject} title={$t('pol.previewScopeTitle')}>
				<option value="">{$t('pol.allMyProjects')}</option>
				{#each projects as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
			</select>
			<button type="button" class="btn btn-ghost btn-sm" onclick={previewForm} disabled={previewing}>
				{#if previewing}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('pol.preview')}
			</button>
			<button type="button" class="btn btn-ghost btn-sm" onclick={closeForm}>{$t('common.cancel')}</button>
			<button class="btn btn-primary btn-sm" disabled={saving}>
				{#if saving}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('pol.savePolicy')}
			</button>
		</div>
	</form>
{/if}

{#if preview}
	<div class="bg-base-100 rounded-box shadow-sm p-4 mb-5">
		<div class="flex items-center justify-between mb-2">
			<h2 class="font-semibold">
				{$t('pol.previewPrefix', { title: preview.title })} {$t('pol.previewViolations', { count: preview.total })} {$t('pol.previewIn', { count: preview.components })}
				{#if preview.truncated}<span class="text-xs text-base-content/60">{$t('pol.previewShowing', { count: preview.violations.length })}</span>{/if}
			</h2>
			<button class="btn btn-ghost btn-xs" onclick={() => (preview = null)}>{$t('pol.close')}</button>
		</div>
		<p class="text-xs text-base-content/60 mb-2">{$t('pol.previewDryRun')}</p>
		{#if preview.violations.length === 0}
			<p class="text-sm text-base-content/60">{$t('pol.previewNone')}</p>
		{:else}
			<div class="overflow-x-auto max-h-96">
				<table class="table table-xs">
					<thead><tr><th>{$t('pol.colProject')}</th><th>{$t('pol.colVersion')}</th><th>{$t('pol.colComponent')}</th><th>{$t('pol.colWhy')}</th><th>{$t('pol.colSeverity')}</th></tr></thead>
					<tbody>
						{#each preview.violations as v, i (i)}
							<tr>
								<td><a class="link link-hover" href="/projects/{v.project_id}">{v.project_name}</a></td>
								<td class="text-xs">{v.version_name}</td>
								<td class="font-mono text-xs">{v.group ? v.group + '/' : ''}{v.name}@{v.version}</td>
								<td class="text-xs text-base-content/70">{v.matches.map((/** @type {any} */ m) => m.fact || m.subject).join(' · ')}</td>
								<td><Badge kind="severity" value={v.severity} /></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}

<State {loading} empty={!loading && policies.length === 0} emptyText={$t('pol.empty')} />
{#if !loading && policies.length > 0}
	<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
		<table class="table table-sm">
			<thead><tr><th>{$t('pol.colOn')}</th><th>{$t('pol.colName')}</th><th>{$t('pol.violatedWhen')}</th><th>{$t('pol.colState')}</th><th>{$t('pol.colScope')}</th><th>{$t('pol.colViolations')}</th><th>{$t('pol.colUpdated')}</th><th></th></tr></thead>
			<tbody>
				{#each policies as p (p.id)}
					<tr class="hover" class:opacity-50={!p.enabled}>
						<td>
							<input type="checkbox" class="toggle toggle-sm toggle-primary" checked={p.enabled} disabled={!isAdmin} onchange={() => toggle(p)} />
						</td>
						<td>
							<div class="font-medium">{p.name}</div>
							{#if p.description}<div class="text-xs text-base-content/50">{p.description}</div>{/if}
						</td>
						<td class="text-xs text-base-content/70">
							{#each p.conditions as c, i}
								{#if i > 0}<span class="badge badge-ghost badge-xs mx-1">{p.operator === 'all' ? $t('pol.celAnd') : $t('pol.or')}</span>{/if}
								<span class="font-mono">{conditionText(c)}</span>
							{/each}
						</td>
						<td><span class="badge badge-sm {stateOf(p.violation_state).tone}">{$t(stateOf(p.violation_state).shortKey)}</span></td>
						<td class="text-xs">
							{p.scope === 'global' ? $t('pol.scopeAllProjects') : p.project_ids.map(projectName).join(', ')}
							{#if p.include_tags?.length}<div class="text-base-content/70">{$t('pol.taggedList', { tags: p.include_tags.join(' or ') })}</div>{/if}
							{#if p.exclude_tags?.length}<div class="text-base-content/70">{$t('pol.exceptList', { tags: p.exclude_tags.join(', ') })}</div>{/if}
							{#if p.versions === 'default'}<div class="text-base-content/50">{$t('pol.versionsDefault')}</div>{/if}
						</td>
						<td>
							<button class="btn btn-ghost btn-xs tabular-nums" onclick={() => showViolations(p)} title={$t('pol.openViolationsTitle')}>
								{p.violations ?? 0}
							</button>
						</td>
						<td class="text-xs whitespace-nowrap">{fmtDate(p.updated_at)}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-ghost btn-xs" onclick={() => previewStored(p)} disabled={previewing}>{$t('pol.preview')}</button>
							{#if isAdmin}
								<button class="btn btn-ghost btn-xs" onclick={() => openEdit(p)}>{$t('common.edit')}</button>
								<button class="btn btn-ghost btn-xs text-error" onclick={() => remove(p)}>{$t('common.delete')}</button>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if shown}
	<div class="bg-base-100 rounded-box shadow-sm p-4 mt-5">
		<div class="flex items-center justify-between mb-2">
			<h2 class="font-semibold">{$t('pol.openViolationsHeading', { name: shown.policy.name })}</h2>
			<button class="btn btn-ghost btn-xs" onclick={() => (shown = null)}>{$t('pol.close')}</button>
		</div>
		{#if shown.findings.length === 0}
			<p class="text-sm text-base-content/60">{$t('pol.noViolations')}</p>
		{:else}
			<div class="overflow-x-auto max-h-96">
				<table class="table table-xs">
					<thead><tr><th>{$t('pol.colFinding')}</th><th>{$t('pol.colSeverity')}</th><th>{$t('pol.colStatus')}</th><th>{$t('pol.colFirstSeen')}</th></tr></thead>
					<tbody>
						{#each shown.findings as f (f.id)}
							<tr>
								<td><a class="link link-hover" href="/findings/{f.id}">{f.title}</a></td>
								<td><Badge kind="severity" value={f.severity} /></td>
								<td><Badge kind="status" value={f.status} /></td>
								<td class="text-xs whitespace-nowrap">{fmtDate(f.first_seen_at)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if shown.more}<p class="text-xs text-base-content/50 mt-1">{$t('pol.previewShowing', { count: shown.findings.length })}</p>{/if}
		{/if}
		<p class="text-xs text-base-content/50 mt-2">
			{$t('pol.triageInbox')} <a class="link" href="/findings?scanner=policy&rule_id={shown.policy.id}">{$t('pol.findingsThisPolicy')}</a>
			· <a class="link" href="/findings?scanner=policy">{$t('pol.allPolicyViolations')}</a>.
		</p>
	</div>
{/if}
