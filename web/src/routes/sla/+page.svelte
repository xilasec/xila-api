<script>
	import { onMount } from 'svelte';
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { me, notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';
	import State from '#lib/components/State.svelte';
	import SlaPolicyEditor from '#lib/components/SlaPolicyEditor.svelte';
	import SlaScalingEditor from '#lib/components/SlaScalingEditor.svelte';

	let loading = $state(true);
	let error = $state('');
	let overview = $state(/** @type {any} */ (null));
	let globalPolicy = $state(/** @type {any} */ (null));
	let scaling = $state(/** @type {any} */ (null)); // admin only: criticality scaling settings + matrix
	let orgs = $state(/** @type {{ org: any, policy: any }[]} */ ([])); // [{ org, policy }]
	let sweeping = $state(false);

	/** @param {unknown} err @param {string} who */
	const denied = (err, who) => (err instanceof ApiError && err.status === 403 ? $t('slap.deniedAdmin', { who }) : errorMessage(err));

	async function load() {
		loading = true;
		error = '';
		try {
			const list = await api.listOrgs();
			const [ov, ...policies] = await Promise.all([
				api.portfolio().catch(() => null),
				...list.map((/** @type {any} */ o) => api.orgSlaPolicy(o.id))
			]);
			overview = ov;
			orgs = list.map((/** @type {any} */ org, /** @type {number} */ i) => ({ org, policy: policies[i] }));
			// The layout fills $me asynchronously; don't let a race hide the admin editor.
			const who = $me ?? (await api.me().catch(() => null));
			globalPolicy = who?.is_admin ? await api.globalSlaPolicy() : null;
			scaling = who?.is_admin ? await api.slaSettings() : null;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t('appr.loadFailed');
		} finally {
			loading = false;
		}
	}

	// Any policy change re-dates findings server-side; reload so every scope's
	// "in force" badge and the posture numbers reflect it.
	/** @param {any} days */
	async function saveGlobal(days) {
		try {
			await api.setGlobalSlaPolicy(days);
			notify($t('slap.savedGlobal'), 'success');
			await load();
		} catch (err) {
			notify(denied(err, $t('slap.anInstanceAdmin')));
		}
	}
	async function resetGlobal() {
		try {
			await api.deleteGlobalSlaPolicy();
			notify($t('slap.removedGlobal'), 'success');
			await load();
		} catch (err) {
			notify(denied(err, $t('slap.anInstanceAdmin')));
		}
	}
	/** @param {any} s */
	async function saveScaling(s) {
		try {
			await api.setSlaSettings(s);
			notify(
				s.scale_by_criticality ? $t('slap.scalingSavedOn') : $t('slap.scalingSavedOff'),
				'success'
			);
			await load();
		} catch (err) {
			notify(denied(err, $t('slap.anInstanceAdmin')));
		}
	}
	/** @param {string} orgId @param {any} days */
	async function saveOrg(orgId, days) {
		try {
			await api.setOrgSlaPolicy(orgId, days);
			notify($t('slap.savedOrg'), 'success');
			await load();
		} catch (err) {
			notify(denied(err, $t('slap.anOrgAdmin')));
		}
	}
	/** @param {string} orgId */
	async function resetOrg(orgId) {
		try {
			await api.deleteOrgSlaPolicy(orgId);
			notify($t('slap.removedOrg'), 'success');
			await load();
		} catch (err) {
			notify(denied(err, $t('slap.anOrgAdmin')));
		}
	}
	async function sweep() {
		sweeping = true;
		try {
			const res = await api.slaSweep();
			notify($t('slap.sweepResult', { breached: res.breached, dueSoon: res.due_soon }), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			sweeping = false;
		}
	}

	onMount(load);
</script>

<div class="flex items-center justify-between mb-5 gap-3">
	<div>
		<h1 class="text-2xl font-bold">{$t('slap.title')}</h1>
		<p class="text-sm text-base-content/60">{$t('slap.subtitle')}</p>
	</div>
	{#if $me?.is_admin}
		<button class="btn btn-outline btn-sm" onclick={sweep} disabled={sweeping}
			title={$t('slap.sendAlertsTitle')}>
			{#if sweeping}<span class="loading loading-spinner loading-xs"></span>{/if}
			{$t('slap.sendAlertsNow')}
		</button>
	{/if}
</div>

<State {loading} {error} />

{#if !loading && !error}
	{#if overview?.sla}
		{@const s = overview.sla}
		<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100 w-full mb-6">
			<a href="/findings?sla=breached&sort=sla_due" class="stat hover:bg-base-200">
				<div class="stat-title">{$t('slap.breached')}</div>
				<div class="stat-value text-error">{s.breached}</div>
				<div class="stat-desc">{$t('slap.pastDeadline')}</div>
			</a>
			<a href="/findings?sla=due_soon&sort=sla_due" class="stat hover:bg-base-200">
				<div class="stat-title">{$t('slap.dueSoon')}</div>
				<div class="stat-value text-warning">{s.due_soon}</div>
				<div class="stat-desc">{$t('slap.onTrackPaused', { onTrack: s.on_track, paused: s.paused })}</div>
			</a>
			<div class="stat">
				<div class="stat-title">{$t('slap.fixedOnTime', { days: s.window_days })}</div>
				<div class="stat-value">{s.compliance === null ? '—' : `${Math.round(s.compliance * 100)}%`}</div>
				<div class="stat-desc">{$t('slap.metMissed', { met: s.met, missed: s.missed })}</div>
			</div>
		</div>
	{/if}

	{#if globalPolicy}
		<div class="card bg-base-100 shadow-sm mb-4">
			<div class="card-body p-5">
				<h2 class="card-title text-base">{$t('slap.instanceDefault')}</h2>
				<p class="text-xs text-base-content/50 -mt-1">{$t('slap.instanceDefaultNote')}</p>
				<SlaPolicyEditor policy={globalPolicy} own="global" onsave={saveGlobal} onreset={resetGlobal} />
			</div>
		</div>
	{/if}

	{#if scaling}
		<div class="card bg-base-100 shadow-sm mb-4">
			<div class="card-body p-5">
				<h2 class="card-title text-base">{$t('slap.criticality')}</h2>
				<SlaScalingEditor settings={scaling} onsave={saveScaling} />
			</div>
		</div>
	{/if}

	{#each orgs as { org, policy } (org.id)}
		<div class="card bg-base-100 shadow-sm mb-4">
			<div class="card-body p-5">
				<h2 class="card-title text-base">{org.name}</h2>
				<p class="text-xs text-base-content/50 -mt-1">
					{$t('slap.orgNote', { tab: $t('nav.sla') })}
				</p>
				<SlaPolicyEditor {policy} own="org" onsave={(/** @type {any} */ d) => saveOrg(org.id, d)} onreset={() => resetOrg(org.id)} />
			</div>
		</div>
	{/each}
{/if}
