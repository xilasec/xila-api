<script>
	// Access entries (GET /permissions, /projects/{id}/access): principal,
	// project, effective role, and each grant with its source.
	import { t, labelOf } from '#lib/i18n.js';

	/** @type {{ entries: any[], showPrincipal?: boolean, showProject?: boolean }} */
	let { entries, showPrincipal = true, showProject = true } = $props();

	/** @type {Record<string, import('#lib/i18n.js').MessageKey>} */
	const KIND = { project: 'access.kind.project', team: 'access.kind.team', org_admin: 'access.kind.org_admin', instance_admin: 'access.kind.instance_admin' };
	/** @type {Record<string, string>} */
	const ROLE_TONE = { admin: 'badge-error', owner: 'badge-warning', editor: 'badge-info', viewer: 'badge-ghost', uploader: 'badge-accent' };
</script>

<div class="overflow-x-auto bg-base-100 rounded-box shadow-sm">
	<table class="table table-sm">
		<thead>
			<tr>
				{#if showPrincipal}<th>{$t('access.principal')}</th>{/if}
				{#if showProject}<th>{$t('access.project')}</th>{/if}
				<th>{$t('access.role')}</th>
				<th>{$t('access.because')}</th>
			</tr>
		</thead>
		<tbody>
			{#each entries as e (e.user_id + (e.project_id ?? '*'))}
				<tr class="hover align-top">
					{#if showPrincipal}
						<td>
							<div class="font-medium">{e.email}</div>
							{#if e.principal_kind === 'service'}<span class="badge badge-ghost badge-xs">{$t('access.serviceAccount')}</span>{/if}
							{#if e.disabled}<span class="badge badge-error badge-outline badge-xs">{$t('access.deactivated')}</span>{/if}
						</td>
					{/if}
					{#if showProject}
						<td class="text-xs">
							{#if e.project_id}
								<a class="link link-hover font-medium" href="/projects/{e.project_id}">{e.project_name}</a>
								<div class="text-base-content/50">{e.org_name} / {e.team_name}</div>
							{:else}
								<span class="italic">{$t('access.everyProject')}</span>
							{/if}
						</td>
					{/if}
					<td><span class="badge badge-sm {ROLE_TONE[e.effective_role] ?? ''}">{$labelOf('role', e.effective_role)}</span></td>
					<td class="text-xs">
						<ul class="space-y-0.5">
							{#each e.grants as g}
								<li>
									<span class="font-medium">{KIND[g.kind] ? $t(KIND[g.kind]) : g.kind}</span>
									{#if g.via_name}{$t('access.on')} <span class="font-medium">{g.via_name}</span>{/if}
									<span class="text-base-content/60">({$labelOf('role', g.role)})</span>
									{#if g.source === 'sso'}
										<span class="badge badge-outline badge-xs" title={$t('access.syncedTitle')}>SSO</span>
										{#if g.sso_mappings.length}<span class="text-base-content/60">{$t('access.via', { names: g.sso_mappings.join(', ') })}</span>{/if}
									{/if}
								</li>
							{/each}
						</ul>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
