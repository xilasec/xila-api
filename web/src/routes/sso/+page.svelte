<script>
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { fmtDate } from '#lib/format.js';
	import { t, labelOf } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	// { providers, auto_create_users, password_login_enabled, public_url, secrets_configured, cookie_secure }
	let info = $state(/** @type {any} */ (null));
	let mappings = $state(/** @type {any[]} */ ([]));
	let loading = $state(true);
	let saving = $state(false);

	let canAdd = $derived(Boolean(info?.public_url) && Boolean(info?.secrets_configured));
	let providers = $derived(/** @type {any[]} */ (info?.providers ?? []));
	// The server's slug rule (HTML pattern syntax; `-` escaped for the v flag).
	const SLUG_PATTERN = '[a-z0-9]([a-z0-9\\-]{0,38}[a-z0-9])?';

	// Target pickers.
	let orgs = $state(/** @type {any[]} */ ([]));
	let teams = $state(/** @type {any[]} */ ([]));
	let projects = $state(/** @type {any[]} */ ([]));

	async function load() {
		loading = true;
		try {
			[info, mappings, orgs, teams, projects] = await Promise.all([
				api.ssoProviders(),
				api.listGroupMappings(),
				api.listOrgs(),
				api.listTeams(),
				api.listProjects()
			]);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	async function refreshProviders() {
		try {
			info = await api.ssoProviders();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {string} value */
	async function copy(value) {
		try {
			await navigator.clipboard.writeText(value);
			notify($t('common.copied'), 'success');
		} catch {
			notify($t('sso.copyFailed'));
		}
	}

	/** @type {Record<string, { cls: string, label: import('#lib/i18n.js').MessageKey }>} */
	const STATUS = {
		ok: { cls: 'badge-success', label: 'sso.statusOk' },
		error: { cls: 'badge-error', label: 'sso.statusError' },
		pending: { cls: 'badge-warning', label: 'sso.statusPending' },
		disabled: { cls: 'badge-ghost', label: 'sso.statusDisabled' }
	};

	// What to give the IdP, per kind.
	/** @param {any} p */
	function endpointRows(p) {
		const e = p.endpoints ?? {};
		return p.kind === 'oidc'
			? [{ label: $t('sso.endpointRedirectUri'), value: e.redirect_uri }]
			: [
					{ label: $t('sso.endpointAcsUrl'), value: e.acs_url },
					{ label: $t('sso.endpointSpEntityId'), value: e.sp_entity_id },
					{ label: $t('sso.endpointSpMetadataUrl'), value: e.sp_metadata_url }
				];
	}

	// ---- presets ----------------------------------------------------------

	const OIDC_PRESETS = [
		{
			id: 'google',
			label: $t('sso.presetOidcGoogleLabel'),
			name: 'Google',
			issuer: 'https://accounts.google.com',
			groups_claim: '',
			help: $t('sso.presetOidcGoogleHelp')
		},
		{
			id: 'gitlab',
			label: $t('sso.presetOidcGitlabLabel'),
			name: 'GitLab',
			issuer: 'https://gitlab.com',
			groups_claim: 'groups_direct',
			help: $t('sso.presetOidcGitlabHelp')
		},
		{
			id: 'keycloak',
			label: $t('sso.presetOidcKeycloakLabel'),
			name: 'Keycloak',
			issuer: 'https://keycloak.example.com/realms/REALM',
			groups_claim: 'groups',
			help: $t('sso.presetOidcKeycloakHelp')
		},
		{
			id: 'entra',
			label: $t('sso.presetOidcEntraLabel'),
			name: 'Microsoft',
			issuer: 'https://login.microsoftonline.com/TENANT-ID/v2.0',
			groups_claim: 'groups',
			help: $t('sso.presetOidcEntraHelp')
		},
		{
			id: 'okta',
			label: $t('sso.presetOidcOktaLabel'),
			name: 'Okta',
			issuer: 'https://YOUR-ORG.okta.com',
			groups_claim: 'groups',
			help: $t('sso.presetOidcOktaHelp')
		},
		{ id: 'generic', label: $t('sso.presetOidcGenericLabel'), name: '', issuer: '', groups_claim: 'groups', help: $t('sso.presetOidcGenericHelp') }
	];

	const SAML_PRESETS = [
		{
			id: 'entra',
			label: $t('sso.presetSamlEntraLabel'),
			name: 'Microsoft',
			idp_metadata_url: 'https://login.microsoftonline.com/TENANT-ID/federationmetadata/2007-06/federationmetadata.xml?appid=APP-ID',
			email_attribute: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
			groups_attributes: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
			help: $t('sso.presetSamlEntraHelp')
		},
		{
			id: 'okta',
			label: $t('sso.presetSamlOktaLabel'),
			name: 'Okta',
			idp_metadata_url: 'https://YOUR-ORG.okta.com/app/APP-ID/sso/saml/metadata',
			email_attribute: '',
			groups_attributes: 'groups',
			help: $t('sso.presetSamlOktaHelp')
		},
		{
			id: 'keycloak',
			label: $t('sso.presetSamlKeycloakLabel'),
			name: 'Keycloak',
			idp_metadata_url: 'https://keycloak.example.com/realms/REALM/protocol/saml/descriptor',
			email_attribute: '',
			groups_attributes: 'groups',
			help: $t('sso.presetSamlKeycloakHelp')
		},
		{ id: 'generic', label: $t('sso.presetSamlGenericLabel'), name: '', idp_metadata_url: '', email_attribute: '', groups_attributes: 'groups', help: $t('sso.presetSamlGenericHelp') }
	];

	// ---- add / edit dialog ---------------------------------------------------

	/** @type {HTMLDialogElement} */
	let dialog;
	let step = $state('kind'); // 'kind' | 'form'
	let editing = $state(/** @type {any} */ (null)); // the provider being edited, or null
	let preset = $state(/** @type {any} */ (null));
	let form = $state(blankForm('oidc'));
	let metadataSource = $state('url'); // 'url' | 'xml'
	let testResult = $state(/** @type {any} */ (null));
	let testing = $state(false);
	let slugTouched = $state(false);

	/** @param {string} kind */
	function blankForm(kind) {
		return {
			kind,
			slug: '',
			name: '',
			enabled: true,
			sort_order: 0,
			auto_create_users: 'default',
			link_by_email: true,
			issuer: '',
			client_id: '',
			client_secret: '',
			scopes: 'openid email profile',
			groups_claim: 'groups',
			trust_unverified_email: false,
			idp_metadata_url: '',
			idp_metadata: '',
			entity_id: '',
			email_attribute: '',
			groups_attributes: 'groups',
			allow_idp_initiated: false,
			sign_requests: true,
			sp_cert: '',
			sp_key: ''
		};
	}

	function openAdd() {
		editing = null;
		preset = null;
		testResult = null;
		slugTouched = false;
		step = 'kind';
		dialog.showModal();
	}

	/** @param {string} kind @param {any} p */
	function chooseKind(kind, p) {
		form = blankForm(kind);
		preset = p;
		if (kind === 'oidc') {
			form.name = p.name;
			form.issuer = p.issuer;
			form.groups_claim = p.groups_claim;
		} else {
			form.name = p.name;
			form.idp_metadata_url = p.idp_metadata_url;
			form.email_attribute = p.email_attribute;
			form.groups_attributes = p.groups_attributes;
		}
		form.slug = slugify(p.id === 'generic' ? '' : p.id);
		metadataSource = 'url';
		step = 'form';
	}

	/** @param {any} p */
	function openEdit(p) {
		editing = p;
		preset = null;
		testResult = null;
		slugTouched = true;
		form = {
			...blankForm(p.kind),
			slug: p.slug,
			name: p.name,
			enabled: p.enabled,
			sort_order: p.sort_order,
			auto_create_users: p.auto_create_users === null ? 'default' : p.auto_create_users ? 'on' : 'off',
			link_by_email: p.link_by_email,
			issuer: p.issuer ?? '',
			client_id: p.client_id ?? '',
			scopes: (p.scopes ?? []).join(' '),
			groups_claim: p.groups_claim ?? '',
			trust_unverified_email: p.trust_unverified_email,
			idp_metadata_url: p.idp_metadata_url ?? '',
			idp_metadata: p.idp_metadata ?? '',
			entity_id: p.entity_id ?? '',
			email_attribute: p.email_attribute ?? '',
			groups_attributes: (p.groups_attributes ?? []).join(', '),
			allow_idp_initiated: p.allow_idp_initiated,
			sign_requests: p.sign_requests,
			sp_cert: p.sp_cert ?? ''
		};
		metadataSource = p.idp_metadata ? 'xml' : 'url';
		step = 'form';
		dialog.showModal();
	}

	/** @param {string} s */
	function slugify(s) {
		return s
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-+|-+$/g, '')
			.slice(0, 40);
	}

	function onName() {
		if (!editing && !slugTouched) form.slug = slugify(form.name);
	}

	// URLs the IdP needs, shown before saving so they can be registered first.
	let previewEndpoints = $derived.by(() => {
		const base = `${info?.public_url ?? ''}/api/v1/auth/${form.kind}/${form.slug || '<slug>'}`;
		return form.kind === 'oidc'
			? [{ label: $t('sso.endpointRedirectUri'), value: `${base}/callback` }]
			: [
					{ label: $t('sso.endpointAcsUrl'), value: `${base}/acs` },
					{ label: $t('sso.endpointSpEntityId'), value: form.entity_id.trim() || `${base}/metadata` },
					{ label: $t('sso.endpointSpMetadataUrl'), value: `${base}/metadata` }
				];
	});

	function body() {
		/** @type {Record<string, any>} */
		const b = {
			name: form.name.trim(),
			enabled: form.enabled,
			sort_order: Number(form.sort_order) || 0,
			auto_create_users: form.auto_create_users === 'default' ? null : form.auto_create_users === 'on',
			link_by_email: form.link_by_email
		};
		if (!editing) {
			b.slug = form.slug.trim();
			b.kind = form.kind;
		}
		if (form.kind === 'oidc') {
			Object.assign(b, {
				issuer: form.issuer.trim(),
				client_id: form.client_id.trim(),
				scopes: form.scopes.split(/[\s,]+/).filter(Boolean),
				groups_claim: form.groups_claim.trim(),
				trust_unverified_email: form.trust_unverified_email
			});
			if (form.client_secret) b.client_secret = form.client_secret;
		} else {
			Object.assign(b, {
				idp_metadata_url: metadataSource === 'url' ? form.idp_metadata_url.trim() : '',
				idp_metadata: metadataSource === 'xml' ? form.idp_metadata.trim() : '',
				entity_id: form.entity_id.trim(),
				email_attribute: form.email_attribute.trim(),
				groups_attributes: form.groups_attributes.split(',').map((s) => s.trim()).filter(Boolean),
				allow_idp_initiated: form.allow_idp_initiated,
				sign_requests: form.sign_requests,
				sp_cert: form.sp_cert.trim()
			});
			if (form.sp_key.trim()) b.sp_key = form.sp_key.trim();
		}
		return b;
	}

	async function runDraftTest() {
		testing = true;
		testResult = null;
		try {
			const b = body();
			if (editing) Object.assign(b, { id: editing.id, slug: editing.slug, kind: editing.kind });
			testResult = await api.testSsoDraft(b);
		} catch (err) {
			testResult = { ok: false, error: errorMessage(err) };
		} finally {
			testing = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		saving = true;
		try {
			const saved = editing
				? await api.updateSsoProvider(editing.id, body())
				: await api.createSsoProvider(body());
			notify(
				saved.status === 'error'
					? $t('sso.savedButNotWorking', { error: saved.last_error })
					: editing
						? $t('sso.providerUpdated')
						: $t('sso.providerAdded'),
				saved.status === 'error' ? 'warning' : 'success'
			);
			dialog.close();
			await refreshProviders();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	// ---- list actions --------------------------------------------------------

	let listTests = $state(/** @type {Record<string, any>} */ ({})); // provider id → test result
	let listTesting = $state(/** @type {Record<string, boolean>} */ ({}));

	/** @param {any} p */
	async function testSaved(p) {
		listTesting = { ...listTesting, [p.id]: true };
		try {
			listTests = { ...listTests, [p.id]: await api.testSsoProvider(p.id) };
			await refreshProviders();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			listTesting = { ...listTesting, [p.id]: false };
		}
	}

	// Re-sends the stored settings with only `enabled` flipped (secrets omitted
	// are kept server-side).
	/** @param {any} p */
	async function toggle(p) {
		try {
			await api.updateSsoProvider(p.id, {
				name: p.name,
				enabled: !p.enabled,
				sort_order: p.sort_order,
				auto_create_users: p.auto_create_users,
				link_by_email: p.link_by_email,
				issuer: p.issuer,
				client_id: p.client_id,
				scopes: p.scopes,
				groups_claim: p.groups_claim,
				trust_unverified_email: p.trust_unverified_email,
				idp_metadata_url: p.idp_metadata_url,
				idp_metadata: p.idp_metadata,
				entity_id: p.entity_id,
				email_attribute: p.email_attribute,
				groups_attributes: p.groups_attributes,
				allow_idp_initiated: p.allow_idp_initiated,
				sign_requests: p.sign_requests,
				sp_cert: p.sp_cert
			});
			notify(p.enabled ? $t('sso.providerDisabled', { name: p.name }) : $t('sso.providerEnabled', { name: p.name }), 'success');
			await refreshProviders();
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} p */
	async function removeProvider(p) {
		const linked = p.linked_identities ? $t('sso.removeProviderLinkedNote', { count: p.linked_identities }) : '';
		if (!confirm($t('sso.removeProviderConfirm', { name: p.name, linked }))) return;
		try {
			await api.deleteSsoProvider(p.id);
			notify($t('sso.providerDeleted'), 'success');
			[info, mappings] = await Promise.all([api.ssoProviders(), api.listGroupMappings()]);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	// ---- group mappings ------------------------------------------------------

	/** @type {{ id: string, label: import('#lib/i18n.js').MessageKey }[]} */
	const KINDS = [
		{ id: 'instance_admin', label: 'sso.kindInstanceAdmin' },
		{ id: 'org', label: 'sso.kindOrg' },
		{ id: 'team', label: 'sso.kindTeam' },
		{ id: 'project', label: 'sso.kindProject' }
	];
	/** @type {Record<string, string[]>} */
	const ROLES = { org: ['member', 'admin'], team: ['viewer', 'editor', 'owner', 'uploader'], project: ['viewer', 'editor', 'owner', 'uploader'] };

	// Scope picker values: "any", "kind:oidc", "kind:saml", "id:<provider id>".
	const blankMapping = () => ({ scope: 'any', group: '', target_kind: 'team', target_id: '', role: 'viewer' });
	let mform = $state(blankMapping());

	let targets = $derived(
		mform.target_kind === 'org' ? orgs : mform.target_kind === 'team' ? teams : mform.target_kind === 'project' ? projects : []
	);

	/** @param {string} kind */
	function setKind(kind) {
		mform.target_kind = kind;
		mform.target_id = '';
		mform.role = kind === 'instance_admin' ? '' : ROLES[kind][0];
	}

	/** @param {SubmitEvent} e */
	async function createMapping(e) {
		e.preventDefault();
		saving = true;
		try {
			/** @type {Record<string, string>} */
			const b = { group: mform.group.trim(), target_kind: mform.target_kind };
			if (mform.scope === 'any') b.provider = 'any';
			else if (mform.scope.startsWith('kind:')) b.provider = mform.scope.slice(5);
			else b.provider_id = mform.scope.slice(3);
			if (mform.target_kind !== 'instance_admin') {
				b.target_id = mform.target_id;
				b.role = mform.role;
			}
			await api.createGroupMapping(b);
			notify($t('sso.mappingAdded'), 'success');
			mform = { ...blankMapping(), scope: mform.scope, target_kind: mform.target_kind, role: mform.role };
			mappings = await api.listGroupMappings();
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {any} m */
	async function removeMapping(m) {
		if (!confirm($t('sso.removeMappingConfirm', { group: m.group }))) return;
		try {
			await api.deleteGroupMapping(m.id);
			mappings = mappings.filter((x) => x.id !== m.id);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} m */
	function scopeLabel(m) {
		if (m.provider_id) return m.provider_name || providers.find((p) => p.id === m.provider_id)?.name || m.provider_id;
		return m.provider === 'any' ? $t('sso.anyProviderScope') : $t('sso.everyProviderKind', { kind: m.provider.toUpperCase() });
	}

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const KIND_LABEL = Object.fromEntries(KINDS.map((k) => [k.id, k.label]));
	/** @param {any} m */
	function targetLabel(m) {
		if (m.target_kind === 'instance_admin') return $t('sso.kindInstanceAdmin');
		const kind = KIND_LABEL[m.target_kind] ? $t(KIND_LABEL[m.target_kind]) : m.target_kind;
		return $t('sso.targetFormat', { kind, name: m.target_name || m.target_id });
	}
</script>

{#snippet testView(/** @type {any} */ r)}
	<div class="rounded-box border border-base-300 p-3 text-sm">
		{#if r.ok}
			<div class="font-semibold text-success mb-2">{$t('sso.testOkHeading')}</div>
		{:else}
			<div class="font-semibold text-error mb-1">{$t('sso.testFailedHeading')}</div>
			<div class="font-mono text-xs break-all">{r.error}</div>
		{/if}
		{#each r.warnings ?? [] as w (w)}
			<div class="alert alert-warning py-1 px-2 text-xs mt-2"><span>{w}</span></div>
		{/each}
		{#if r.details?.length}
			<table class="table table-xs mt-2">
				<tbody>
					{#each r.details as d (d.label)}
						<tr>
							<td class="text-base-content/60 whitespace-nowrap">{d.label}</td>
							<td class="font-mono text-xs break-all">{d.value || '—'}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
		{#if r.certificates?.length}
			<div class="mt-2 text-xs font-semibold">{$t('sso.certsHeading')}</div>
			<ul class="text-xs mt-1">
				{#each r.certificates as c, i (i)}
					<li class:text-error={c.expired}>
						<span class="font-mono">{c.subject || $t('sso.noSubject')}</span> — {c.expired ? $t('sso.certExpired') : $t('sso.certValidUntil')}
						{fmtDate(c.not_after)}
					</li>
				{/each}
			</ul>
		{/if}
	</div>
{/snippet}

{#snippet copyRows(/** @type {{ label: string, value: string }[]} */ rows)}
	<table class="table table-xs">
		<tbody>
			{#each rows as s (s.label)}
				<tr>
					<td class="text-base-content/60 whitespace-nowrap">{s.label}</td>
					<td class="font-mono text-xs break-all">{s.value || '—'}</td>
					<td class="text-right">
						{#if s.value}
							<button type="button" class="btn btn-ghost btn-xs" onclick={() => copy(s.value)}>{$t('common.copy')}</button>
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/snippet}

<div class="mb-4">
	<h1 class="text-2xl font-bold">{$t('sso.title')}</h1>
	<p class="text-sm text-base-content/60">
		{$t('sso.introPre')}<code>OIDC_*</code>, <code>SAML_*</code>{$t('sso.introMid')}
	</p>
</div>

<State {loading} />
{#if !loading && info}
	<section class="mb-8">
		<div class="flex items-center justify-between mb-2">
			<h2 class="text-lg font-semibold">{$t('sso.providersHeading')}</h2>
			<button class="btn btn-primary btn-sm" onclick={openAdd} disabled={!canAdd}>{$t('sso.addProviderButton')}</button>
		</div>
		<div class="flex flex-wrap gap-2 mb-3 text-xs">
			<span class="badge {info.password_login_enabled ? 'badge-ghost' : 'badge-warning'}">
				{info.password_login_enabled ? $t('sso.passwordOnBadge') : $t('sso.passwordOffBadge')}
			</span>
			<span class="badge badge-ghost">{info.auto_create_users ? $t('sso.autoCreateOnBadge') : $t('sso.autoCreateOffBadge')}</span>
		</div>
		{#if !info.public_url}
			<div class="alert alert-warning text-sm mb-3">
				<span>{$t('sso.noPublicUrlPre')} <code>PUBLIC_URL</code> {$t('sso.noPublicUrlPost')}</span>
			</div>
		{:else if !info.secrets_configured}
			<div class="alert alert-warning text-sm mb-3">
				<span>{$t('sso.noSecretsPre')} <code>INTEGRATION_SECRET_KEY</code> {$t('sso.noSecretsPost')}</span>
			</div>
		{/if}
		{#if !info.cookie_secure && providers.some((p) => p.kind === 'saml')}
			<div class="alert text-sm mb-3">
				<span>
					<code>COOKIE_SECURE</code> {$t('sso.cookieInsecureMid1')}
					<code>COOKIE_SECURE=true</code> {$t('sso.cookieInsecureMid2')}
				</span>
			</div>
		{/if}
		{#if providers.length === 0}
			<div class="alert text-sm">
				<span>{$t('sso.noProvidersPre')} <code>OIDC_*</code> / <code>SAML_*</code> {$t('sso.noProvidersPost')}</span>
			</div>
		{/if}

		<div class="grid gap-4 lg:grid-cols-2">
			{#each providers as p (p.id)}
				{@const st = STATUS[p.status] ?? STATUS.pending}
				<div class="card bg-base-100 shadow-sm">
					<div class="card-body p-4 gap-2">
						<div class="flex items-start justify-between gap-2">
							<h3 class="card-title text-base flex-wrap">
								{p.name}
								<span class="badge badge-outline badge-sm uppercase">{p.kind}</span>
								<span class="badge badge-sm {st.cls}">{$t(st.label)}</span>
								{#if p.source === 'environment'}
									<span class="badge badge-ghost badge-sm" title={$t('sso.envBadgeTitle')}>{$t('sso.envBadge')}</span>
								{/if}
							</h3>
							{#if p.source === 'database'}
								<input
									type="checkbox"
									class="toggle toggle-sm toggle-success"
									checked={p.enabled}
									onchange={() => toggle(p)}
									title={p.enabled ? $t('sso.toggleEnabledTitle') : $t('sso.toggleDisabledTitle')}
								/>
							{/if}
						</div>
						<div class="text-xs text-base-content/60">
							<span class="font-mono">{p.slug}</span>
							· {p.kind === 'oidc' ? p.issuer : p.idp_metadata_url || $t('sso.metadataXmlLabel')}
							{#if p.linked_identities}· {$t('sso.linkedAccounts', { count: p.linked_identities })}{/if}
						</div>
						{#if p.last_error}
							<div class="alert {p.status === 'error' ? 'alert-error' : 'alert-warning'} py-1 px-2 text-xs">
								<span class="break-all">{p.last_error}</span>
							</div>
						{/if}
						{@render copyRows(endpointRows(p))}
						{#if listTests[p.id]}
							{@render testView(listTests[p.id])}
						{/if}
						<div class="card-actions justify-end">
							<button class="btn btn-ghost btn-xs" onclick={() => testSaved(p)} disabled={listTesting[p.id]}>
								{#if listTesting[p.id]}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('sso.testButton')}
							</button>
							{#if p.source === 'database'}
								<button class="btn btn-ghost btn-xs" onclick={() => openEdit(p)}>{$t('svcacct.editButton')}</button>
								<button class="btn btn-ghost btn-xs text-error" onclick={() => removeProvider(p)}>{$t('svcacct.deleteButton')}</button>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>
	</section>

	<section>
		<h2 class="text-lg font-semibold mb-2">{$t('sso.mappingsHeading')}</h2>
		<p class="text-xs text-base-content/60 mb-2">
			{$t('sso.mappingsIntro')}
		</p>
		<form onsubmit={createMapping} class="card bg-base-100 shadow-sm mb-4">
			<div class="card-body p-4 grid gap-3 md:grid-cols-5 items-end">
				<Field label={$t('sso.appliesToLabel')}>
					<select bind:value={mform.scope} class="select select-bordered select-sm w-full">
						<option value="any">{$t('sso.anyProviderOption')}</option>
						<option value="kind:oidc">{$t('sso.everyOidcOption')}</option>
						<option value="kind:saml">{$t('sso.everySamlOption')}</option>
						{#each providers as p (p.id)}
							<option value={`id:${p.id}`}>{p.name} ({p.kind.toUpperCase()})</option>
						{/each}
					</select>
				</Field>
				<Field label={$t('sso.idpGroupLabel')} required hint={$t('sso.idpGroupHint')}>
					<input bind:value={mform.group} required class="input input-bordered input-sm w-full" placeholder="xila-admins" />
				</Field>
				<Field label={$t('sso.grantsLabel')}>
					<select value={mform.target_kind} onchange={(e) => setKind(e.currentTarget.value)} class="select select-bordered select-sm w-full">
						{#each KINDS as k (k.id)}<option value={k.id}>{$t(k.label)}</option>{/each}
					</select>
				</Field>
				{#if mform.target_kind !== 'instance_admin'}
					<Field label={$t('sso.targetLabel')} required>
						<select bind:value={mform.target_id} required class="select select-bordered select-sm w-full">
							<option value="" disabled>{$t('sso.chooseOption')}</option>
							{#each targets as tgt (tgt.id)}<option value={tgt.id}>{tgt.name}</option>{/each}
						</select>
					</Field>
					<Field label={$t('sso.roleLabel')}>
						<select bind:value={mform.role} class="select select-bordered select-sm w-full">
							{#each ROLES[mform.target_kind] as r (r)}<option value={r}>{$labelOf('role', r)}</option>{/each}
						</select>
					</Field>
				{/if}
				<div class="md:col-span-5 flex justify-end">
					<button class="btn btn-primary btn-sm" disabled={saving || !mform.group.trim()}>{$t('sso.addMappingButton')}</button>
				</div>
			</div>
		</form>

		<State loading={false} empty={mappings.length === 0} emptyText={$t('sso.noMappingsYet')} />
		{#if mappings.length > 0}
			<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
				<table class="table">
					<thead><tr><th>{$t('sso.idpGroupLabel')}</th><th>{$t('sso.appliesToLabel')}</th><th>{$t('sso.grantsLabel')}</th><th>{$t('sso.roleLabel')}</th><th></th></tr></thead>
					<tbody>
						{#each mappings as m (m.id)}
							<tr class="hover">
								<td class="font-mono text-sm">{m.group}</td>
								<td><span class="badge badge-ghost badge-sm">{scopeLabel(m)}</span></td>
								<td>{targetLabel(m)}</td>
								<td>{m.role || '—'}</td>
								<td class="text-right">
									<button class="btn btn-ghost btn-xs text-error" onclick={() => removeMapping(m)}>{$t('sso.removeButton')}</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
{/if}

<dialog bind:this={dialog} class="modal">
	<div class="modal-box max-w-3xl">
		{#if step === 'kind'}
			<h3 class="font-bold text-lg mb-4">{$t('sso.addProviderTitle')}</h3>
			<div class="grid gap-4 md:grid-cols-2">
				<div>
					<div class="font-semibold mb-2">{$t('sso.openidConnectHeading')}</div>
					<div class="flex flex-col gap-2">
						{#each OIDC_PRESETS as p (p.id)}
							<button class="btn btn-outline btn-sm justify-start" onclick={() => chooseKind('oidc', p)}>{p.label}</button>
						{/each}
					</div>
				</div>
				<div>
					<div class="font-semibold mb-2">{$t('sso.samlHeading')}</div>
					<div class="flex flex-col gap-2">
						{#each SAML_PRESETS as p (p.id)}
							<button class="btn btn-outline btn-sm justify-start" onclick={() => chooseKind('saml', p)}>{p.label}</button>
						{/each}
					</div>
				</div>
			</div>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost" onclick={() => dialog.close()}>{$t('sso.cancelButton')}</button>
			</div>
		{:else}
			<h3 class="font-bold text-lg mb-1">
				{editing ? $t('sso.editProviderTitle', { name: editing.name }) : form.kind === 'oidc' ? $t('sso.newOidcProviderTitle') : $t('sso.newSamlProviderTitle')}
				{#if preset}<span class="text-base-content/60 font-normal">· {preset.label}</span>{/if}
			</h3>
			{#if preset?.help}
				<p class="text-xs text-base-content/70 mb-3">{preset.help}</p>
			{/if}

			<form onsubmit={save} class="flex flex-col gap-3">
				<div class="grid gap-3 md:grid-cols-2">
					<Field label={$t('sso.buttonLabelLabel')} required hint={$t('sso.buttonLabelHint')}>
						<input bind:value={form.name} oninput={onName} required maxlength="80" class="input input-bordered input-sm w-full" />
					</Field>
					<Field label={$t('sso.slugLabel')} required hint={editing ? $t('sso.slugHintFixed') : $t('sso.slugHintNew')}>
						<input
							bind:value={form.slug}
							oninput={() => (slugTouched = true)}
							required
							disabled={!!editing}
							pattern={SLUG_PATTERN}
							class="input input-bordered input-sm w-full font-mono"
						/>
					</Field>
				</div>

				<div class="rounded-box bg-base-200 p-2">
					<div class="text-xs font-semibold mb-1">{$t('sso.giveToIdpHeading')}</div>
					{@render copyRows(previewEndpoints)}
				</div>

				{#if form.kind === 'oidc'}
					<div class="grid gap-3 md:grid-cols-2">
						<Field label={$t('sso.issuerLabel')} required hint={$t('sso.issuerHint')}>
							<input bind:value={form.issuer} required class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<Field label={$t('sso.clientIdLabel')} required>
							<input bind:value={form.client_id} required class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<Field label={$t('sso.clientSecretLabel')} required={!editing?.has_client_secret} hint={editing?.has_client_secret ? $t('sso.clientSecretHintEdit') : $t('sso.clientSecretHintNew')}>
							<input
								bind:value={form.client_secret}
								type="password"
								autocomplete="new-password"
								required={!editing?.has_client_secret}
								placeholder={editing?.has_client_secret ? '•••••••• (' + $t('sso.unchangedPlaceholder') + ')' : ''}
								class="input input-bordered input-sm w-full"
							/>
						</Field>
						<Field label={$t('sso.scopesLabel')} hint={$t('sso.scopesHint')}>
							<input bind:value={form.scopes} class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<Field label={$t('sso.groupsClaimLabel')} hint={$t('sso.groupsClaimHint')}>
							<input bind:value={form.groups_claim} class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<label class="label cursor-pointer justify-start gap-2 self-end">
							<input type="checkbox" bind:checked={form.trust_unverified_email} class="checkbox checkbox-sm" />
							<span class="label-text text-sm">{$t('sso.trustUnverifiedLabel')} <code>email_verified</code></span>
						</label>
					</div>
				{:else}
					<div class="flex gap-4 text-sm">
						<label class="label cursor-pointer gap-2"><input type="radio" bind:group={metadataSource} value="url" class="radio radio-sm" /> {$t('sso.metadataUrlOption')}</label>
						<label class="label cursor-pointer gap-2"><input type="radio" bind:group={metadataSource} value="xml" class="radio radio-sm" /> {$t('sso.metadataXmlOption')}</label>
					</div>
					{#if metadataSource === 'url'}
						<Field label={$t('sso.idpMetadataUrlLabel')} required hint={$t('sso.idpMetadataUrlHint')}>
							<input bind:value={form.idp_metadata_url} required class="input input-bordered input-sm w-full font-mono" />
						</Field>
					{:else}
						<Field label={$t('sso.idpMetadataXmlLabel')} required>
							<textarea bind:value={form.idp_metadata} required rows="4" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs"></textarea>
						</Field>
					{/if}
					<div class="grid gap-3 md:grid-cols-2">
						<Field label={$t('sso.entityIdOverrideLabel')} hint={$t('sso.entityIdOverrideHint')}>
							<input bind:value={form.entity_id} class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<Field label={$t('sso.emailAttributeLabel')} hint={$t('sso.emailAttributeHint')}>
							<input bind:value={form.email_attribute} class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<Field label={$t('sso.groupsAttributesLabel')} hint={$t('sso.groupsAttributesHint')}>
							<input bind:value={form.groups_attributes} class="input input-bordered input-sm w-full font-mono" />
						</Field>
						<div class="flex flex-col gap-1 self-end">
							<label class="label cursor-pointer justify-start gap-2 py-0">
								<input type="checkbox" bind:checked={form.sign_requests} class="checkbox checkbox-sm" />
								<span class="label-text text-sm">{$t('sso.signRequestsLabel')}</span>
							</label>
							<label class="label cursor-pointer justify-start gap-2 py-0">
								<input type="checkbox" bind:checked={form.allow_idp_initiated} class="checkbox checkbox-sm" />
								<span class="label-text text-sm">{$t('sso.allowIdpInitiatedLabel')} <span class="text-warning">{$t('sso.loginCsrfRisk')}</span></span>
							</label>
						</div>
					</div>
					<details class="text-sm">
						<summary class="cursor-pointer text-base-content/70">{$t('sso.ownSpCertSummary')}</summary>
						<p class="text-xs text-base-content/60 my-2">
							{$t('sso.ownSpCertIntro')}
						</p>
						<div class="grid gap-3 md:grid-cols-2">
							<Field label={$t('sso.spCertLabel')}>
								<textarea bind:value={form.sp_cert} rows="3" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs"></textarea>
							</Field>
							<Field label={$t('sso.spKeyLabel')} hint={editing?.has_sp_key ? $t('sso.spKeyHintEdit') : $t('sso.spKeyHintNew')}>
								<textarea bind:value={form.sp_key} rows="3" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs" placeholder={editing?.has_sp_key ? $t('sso.unchangedPlaceholder') : ''}></textarea>
							</Field>
						</div>
					</details>
				{/if}

				<div class="grid gap-3 md:grid-cols-3">
					<Field label={$t('sso.newUsersLabel')} hint={$t('sso.newUsersHint')}>
						<select bind:value={form.auto_create_users} class="select select-bordered select-sm w-full">
							<option value="default">{$t('sso.instanceDefaultOption', { mode: info?.auto_create_users ? $t('sso.createMode') : $t('sso.refuseMode') })}</option>
							<option value="on">{$t('sso.createAccountOption')}</option>
							<option value="off">{$t('sso.refuseOption')}</option>
						</select>
					</Field>
					<Field label={$t('sso.loginOrderLabel')} hint={$t('sso.loginOrderHint')}>
						<input bind:value={form.sort_order} type="number" class="input input-bordered input-sm w-full" />
					</Field>
					<div class="flex flex-col gap-1 self-end">
						<label class="label cursor-pointer justify-start gap-2 py-0">
							<input type="checkbox" bind:checked={form.link_by_email} class="checkbox checkbox-sm" />
							<span class="label-text text-sm">{$t('sso.linkByEmailLabel')}</span>
						</label>
						<label class="label cursor-pointer justify-start gap-2 py-0">
							<input type="checkbox" bind:checked={form.enabled} class="checkbox checkbox-sm" />
							<span class="label-text text-sm">{$t('sso.enabledLabel')}</span>
						</label>
					</div>
				</div>

				{#if testResult}
					{@render testView(testResult)}
				{/if}

				<div class="modal-action">
					{#if !editing}
						<button type="button" class="btn btn-ghost mr-auto" onclick={() => (step = 'kind')}>{$t('sso.backButton')}</button>
					{/if}
					<button type="button" class="btn btn-ghost" onclick={() => dialog.close()}>{$t('sso.cancelButton')}</button>
					<button type="button" class="btn btn-outline" onclick={runDraftTest} disabled={testing}>
						{#if testing}<span class="loading loading-spinner loading-sm"></span>{/if}{$t('sso.testButtonAction')}
					</button>
					<button class="btn btn-primary" disabled={saving}>
						{#if saving}<span class="loading loading-spinner loading-sm"></span>{/if}{editing ? $t('sso.saveButton') : $t('sso.addProviderSubmitButton')}
					</button>
				</div>
			</form>
		{/if}
	</div>
	<form method="dialog" class="modal-backdrop"><button>{$t('sso.closeButton')}</button></form>
</dialog>
