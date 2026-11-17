<script>
	// Groups & roles (organization admins): user groups, which are granted on
	// teams and projects like a person; custom roles, a base role minus denied
	// capabilities; and, for instance admins, the SCIM tokens an identity
	// provider uses to provision users and groups into an organization.
	import { onMount } from 'svelte';
	import { api, errorMessage } from '#lib/api.js';
	import { notify, me } from '#lib/stores.js';
	import { t, labelOf } from '#lib/i18n.js';
	import { fmtDate } from '#lib/format.js';
	import State from '#lib/components/State.svelte';
	import Field from '#lib/components/Field.svelte';

	const BASE_ROLES = ['viewer', 'uploader', 'editor', 'owner'];

	let orgs = $state(/** @type {any[]} */ ([]));
	let orgId = $state('');
	let loading = $state(true);
	let error = $state('');
	let groups = $state(/** @type {any[]} */ ([]));
	let roles = $state(/** @type {any[]} */ ([]));
	let capabilities = $state(/** @type {string[]} */ ([]));
	let busy = $state('');

	// Group editing.
	let newGroup = $state('');
	let openGroup = $state(/** @type {string | null} */ (null));
	let groupMembers = $state(/** @type {any[]} */ ([]));
	let newMemberEmail = $state('');

	// Custom role editing (null = closed, '' = new, else the role id).
	let editingRole = $state(/** @type {string | null} */ (null));
	let roleForm = $state({ name: '', base_role: 'editor', denied: /** @type {string[]} */ ([]) });

	// SCIM tokens (instance admin).
	let tokens = $state(/** @type {any[]} */ ([]));
	let tokenName = $state('');
	let secret = $state('');

	async function loadOrg() {
		if (!orgId) return;
		loading = true;
		error = '';
		openGroup = null;
		try {
			[groups, roles] = await Promise.all([api.listGroups(orgId), api.listCustomRoles(orgId)]);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	onMount(async () => {
		try {
			[orgs, capabilities] = await Promise.all([api.listOrgs(), api.capabilities()]);
			orgId = orgs[0]?.id ?? '';
			if ($me?.is_admin) tokens = await api.listSCIMTokens();
		} catch (err) {
			error = errorMessage(err);
		}
		if (orgId) await loadOrg();
		else loading = false;
	});

	/** @param {string} key @param {() => Promise<any>} fn @param {string} [ok] */
	async function act(key, fn, ok) {
		busy = key;
		try {
			await fn();
			if (ok) notify(ok, 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = '';
		}
	}

	/** @param {SubmitEvent} e */
	function createGroup(e) {
		e.preventDefault();
		act('group', async () => {
			await api.createGroup(orgId, newGroup.trim());
			newGroup = '';
			groups = await api.listGroups(orgId);
		});
	}

	/** @param {any} g */
	async function toggleGroup(g) {
		if (openGroup === g.id) {
			openGroup = null;
			return;
		}
		openGroup = g.id;
		groupMembers = [];
		try {
			groupMembers = (await api.getGroup(orgId, g.id)).members ?? [];
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {any} g */
	function renameGroup(g) {
		const name = prompt($t('groups.renamePrompt'), g.name);
		if (!name || name.trim() === g.name) return;
		act('rename-' + g.id, async () => {
			await api.renameGroup(orgId, g.id, name.trim());
			groups = await api.listGroups(orgId);
		});
	}

	/** @param {any} g */
	function deleteGroup(g) {
		if (!confirm($t('groups.deleteConfirm', { name: g.name }))) return;
		act('delete-' + g.id, async () => {
			await api.deleteGroup(orgId, g.id);
			groups = await api.listGroups(orgId);
			if (openGroup === g.id) openGroup = null;
		});
	}

	/** @param {SubmitEvent} e @param {any} g */
	function addGroupMember(e, g) {
		e.preventDefault();
		act('member', async () => {
			await api.addGroupMember(orgId, g.id, newMemberEmail.trim().toLowerCase());
			newMemberEmail = '';
			groupMembers = (await api.getGroup(orgId, g.id)).members ?? [];
			groups = await api.listGroups(orgId);
		});
	}

	/** @param {any} g @param {any} m */
	function removeGroupMember(g, m) {
		act('member', async () => {
			await api.removeGroupMember(orgId, g.id, m.user_id);
			groupMembers = (await api.getGroup(orgId, g.id)).members ?? [];
			groups = await api.listGroups(orgId);
		});
	}

	/** @param {any | null} r */
	function editRole(r) {
		editingRole = r ? r.id : '';
		roleForm = r
			? { name: r.name, base_role: r.base_role, denied: [...(r.denied_capabilities ?? [])] }
			: { name: '', base_role: 'editor', denied: [] };
	}

	/** @param {string} cap */
	function toggleCap(cap) {
		roleForm.denied = roleForm.denied.includes(cap) ? roleForm.denied.filter((c) => c !== cap) : [...roleForm.denied, cap];
	}

	/** @param {SubmitEvent} e */
	function saveRole(e) {
		e.preventDefault();
		const body = { name: roleForm.name.trim(), base_role: roleForm.base_role, denied_capabilities: roleForm.denied };
		act('role', async () => {
			if (editingRole) await api.updateCustomRole(orgId, editingRole, body);
			else await api.createCustomRole(orgId, body);
			editingRole = null;
			roles = await api.listCustomRoles(orgId);
		});
	}

	/** @param {any} r */
	function deleteRole(r) {
		if (!confirm($t('groups.deleteRoleConfirm', { name: r.name }))) return;
		act('delete-role-' + r.id, async () => {
			await api.deleteCustomRole(orgId, r.id);
			roles = await api.listCustomRoles(orgId);
		});
	}

	/** @param {SubmitEvent} e */
	function createToken(e) {
		e.preventDefault();
		act('token', async () => {
			const res = await api.createSCIMToken(tokenName.trim(), orgId);
			secret = res.secret;
			tokenName = '';
			tokens = await api.listSCIMTokens();
		});
	}

	/** @param {any} tok */
	function revokeToken(tok) {
		if (!confirm($t('groups.revokeTokenConfirm', { name: tok.name }))) return;
		act('revoke-' + tok.id, async () => {
			await api.revokeSCIMToken(tok.id);
			tokens = await api.listSCIMTokens();
		});
	}

	/** @param {string} cap */
	const capLabel = (cap) => $labelOf('capability', cap);
</script>

<div class="mb-5">
	<h1 class="text-2xl font-bold">{$t('groups.title')}</h1>
	<p class="text-sm text-base-content/60">{$t('groups.subtitle')}</p>
</div>

{#if orgs.length > 1}
	<Field label={$t('groups.org')}>
		<select bind:value={orgId} onchange={loadOrg} class="select select-bordered select-sm w-64 mb-4">
			{#each orgs as o (o.id)}<option value={o.id}>{o.name}</option>{/each}
		</select>
	</Field>
{/if}

<State {loading} {error} empty={!loading && !error && !orgId} emptyText={$t('groups.noOrgs')} />

{#if !loading && !error && orgId}
	<div class="grid gap-6 lg:grid-cols-2">
		<section>
			<h2 class="font-semibold mb-1">{$t('groups.groups')}</h2>
			<p class="text-xs text-base-content/60 mb-3">{$t('groups.groupsIntro')}</p>
			<form onsubmit={createGroup} class="flex gap-2 mb-3">
				<input bind:value={newGroup} required placeholder={$t('groups.groupName')} class="input input-bordered input-sm flex-1" />
				<button class="btn btn-primary btn-sm" disabled={busy === 'group'}>{$t('groups.create')}</button>
			</form>
			{#if groups.length === 0}
				<p class="text-sm text-base-content/50">{$t('groups.noGroups')}</p>
			{:else}
				<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
					{#each groups as g (g.id)}
						<li class="p-3 text-sm">
							<div class="flex items-center gap-2">
								<button class="link link-hover font-medium" onclick={() => toggleGroup(g)}>{g.name}</button>
								<span class="text-base-content/50">{$t('groups.memberCount', { count: g.member_count ?? 0 })}</span>
								{#if g.external_id}<span class="badge badge-outline badge-xs" title={$t('groups.scimManaged')}>SCIM</span>{/if}
								<span class="ml-auto flex gap-1">
									<button class="btn btn-ghost btn-xs" onclick={() => renameGroup(g)}>{$t('groups.rename')}</button>
									<button class="btn btn-ghost btn-xs text-error" onclick={() => deleteGroup(g)}>{$t('common.remove')}</button>
								</span>
							</div>
							{#if openGroup === g.id}
								<div class="mt-2 pl-2 border-l border-base-300">
									{#each groupMembers as m (m.user_id)}
										<div class="flex items-center gap-2 py-0.5">
											<span>{m.email}</span>
											<button class="btn btn-ghost btn-xs ml-auto" onclick={() => removeGroupMember(g, m)}>{$t('common.remove')}</button>
										</div>
									{:else}
										<p class="text-xs text-base-content/50">{$t('groups.emptyGroup')}</p>
									{/each}
									<form onsubmit={(e) => addGroupMember(e, g)} class="flex gap-2 mt-2">
										<input bind:value={newMemberEmail} type="email" required placeholder="dana@example.com" class="input input-bordered input-xs flex-1" />
										<button class="btn btn-xs" disabled={busy === 'member'}>{$t('groups.addMember')}</button>
									</form>
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</section>

		<section>
			<div class="flex items-center justify-between mb-1">
				<h2 class="font-semibold">{$t('groups.roles')}</h2>
				<button class="btn btn-ghost btn-xs" onclick={() => editRole(null)}>{$t('groups.newRole')}</button>
			</div>
			<p class="text-xs text-base-content/60 mb-3">{$t('groups.rolesIntro')}</p>
			{#if editingRole !== null}
				<form onsubmit={saveRole} class="bg-base-100 rounded-box shadow-sm p-3 mb-3 grid gap-2">
					<Field label={$t('groups.roleName')}>
						<input bind:value={roleForm.name} required class="input input-bordered input-sm w-full" />
					</Field>
					<Field label={$t('groups.baseRole')}>
						<select bind:value={roleForm.base_role} class="select select-bordered select-sm">
							{#each BASE_ROLES as r}<option value={r}>{$labelOf('role', r)}</option>{/each}
						</select>
					</Field>
					<div>
						<span class="label-text text-xs">{$t('groups.denied')}</span>
						<div class="flex flex-wrap gap-x-4 gap-y-1 mt-1">
							{#each capabilities as cap}
								<label class="label cursor-pointer gap-1 py-0">
									<input type="checkbox" class="checkbox checkbox-xs" checked={roleForm.denied.includes(cap)} onchange={() => toggleCap(cap)} />
									<span class="label-text text-xs">{capLabel(cap)}</span>
								</label>
							{/each}
						</div>
					</div>
					<div class="flex justify-end gap-2">
						<button type="button" class="btn btn-ghost btn-sm" onclick={() => (editingRole = null)}>{$t('common.cancel')}</button>
						<button class="btn btn-primary btn-sm" disabled={busy === 'role'}>{$t('common.save')}</button>
					</div>
				</form>
			{/if}
			{#if roles.length === 0}
				<p class="text-sm text-base-content/50">{$t('groups.noRoles')}</p>
			{:else}
				<ul class="bg-base-100 rounded-box shadow-sm divide-y divide-base-200">
					{#each roles as r (r.id)}
						<li class="p-3 text-sm">
							<div class="flex items-center gap-2">
								<span class="font-medium">{r.name}</span>
								<span class="badge badge-ghost badge-sm">{$labelOf('role', r.base_role)}</span>
								<span class="ml-auto flex gap-1">
									<button class="btn btn-ghost btn-xs" onclick={() => editRole(r)}>{$t('groups.edit')}</button>
									<button class="btn btn-ghost btn-xs text-error" onclick={() => deleteRole(r)}>{$t('common.remove')}</button>
								</span>
							</div>
							{#if r.denied_capabilities?.length}
								<div class="text-xs text-base-content/60 mt-1">
									{$t('groups.cannot')} {r.denied_capabilities.map(capLabel).join(', ')}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	</div>

	{#if $me?.is_admin}
		<section class="mt-8">
			<h2 class="font-semibold mb-1">{$t('groups.scim')}</h2>
			<p class="text-xs text-base-content/60 mb-3">
				{$t('groups.scimIntro')} <code class="text-xs">{location.origin}/api/v1/scim/v2</code>
			</p>
			{#if secret}
				<div class="alert alert-warning text-sm mb-3 flex-col items-start">
					<span>{$t('groups.secretOnce')}</span>
					<code class="text-xs break-all select-all">{secret}</code>
				</div>
			{/if}
			<form onsubmit={createToken} class="flex gap-2 mb-3">
				<input bind:value={tokenName} required placeholder={$t('groups.tokenName')} class="input input-bordered input-sm w-64" />
				<button class="btn btn-primary btn-sm" disabled={busy === 'token'}>{$t('groups.createToken')}</button>
			</form>
			{#if tokens.length > 0}
				<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
					<table class="table table-sm">
						<thead><tr><th>{$t('groups.tokenName')}</th><th>{$t('groups.org')}</th><th>{$t('groups.lastUsed')}</th><th></th></tr></thead>
						<tbody>
							{#each tokens as tok (tok.id)}
								<tr class:opacity-50={tok.revoked_at}>
									<td>{tok.name}</td>
									<td>{tok.org_name}</td>
									<td class="text-xs">{tok.last_used_at ? fmtDate(tok.last_used_at) : $t('groups.never')}</td>
									<td class="text-right">
										{#if tok.revoked_at}
											<span class="text-xs">{$t('groups.revoked')}</span>
										{:else}
											<button class="btn btn-ghost btn-xs text-error" onclick={() => revokeToken(tok)}>{$t('groups.revoke')}</button>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
	{/if}
{/if}
