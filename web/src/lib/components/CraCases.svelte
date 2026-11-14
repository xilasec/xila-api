<script>
	// A project's EU CRA Article 14 reporting: the product declaration and the
	// cases opened for actively exploited vulnerabilities, with their clocks.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { fmtDate } from '#lib/format.js';
	import { t } from '#lib/i18n.js';
	import { stateLabel, stateClass, deadlineClass, deadlineLabel, countdown, nextDeadline } from '#lib/cra.js';
	import State from '#lib/components/State.svelte';
	import CraCaseDetail from '#lib/components/CraCaseDetail.svelte';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	let loading = $state(true);
	let error = $state('');
	let cases = $state(/** @type {any[]} */ ([]));
	let manufacturer = $state(/** @type {any} */ (null));
	let product = $state({ cra_in_scope: false, product_name: '', product_version: '', member_states: '' });
	let saving = $state(false);
	let selected = $state(/** @type {string | null} */ (null));
	let findingId = $state('');
	let now = $state(Date.now());

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await api.projectCRA(projectId);
			cases = res.cases ?? [];
			manufacturer = res.manufacturer;
			product = {
				cra_in_scope: res.product.cra_in_scope,
				product_name: res.product.product_name,
				product_version: res.product.product_version,
				member_states: (res.product.member_states ?? []).join(', ')
			};
		} catch (err) {
			error = errorMessage(err);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		projectId;
		load();
	});
	$effect(() => {
		const timer = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(timer);
	});

	/** @param {SubmitEvent} e */
	async function saveProduct(e) {
		e.preventDefault();
		saving = true;
		try {
			await api.setProjectCRA(projectId, {
				cra_in_scope: product.cra_in_scope,
				product_name: product.product_name,
				product_version: product.product_version,
				member_states: product.member_states.split(',').map((s) => s.trim()).filter(Boolean)
			});
			notify($t('cra.productSaved'), 'success');
			await load();
		} catch (err) {
			notify(err instanceof ApiError && err.status === 403 ? $t('cra.ownerDeclare') : errorMessage(err));
		} finally {
			saving = false;
		}
	}

	/** @param {SubmitEvent} e */
	async function openManual(e) {
		e.preventDefault();
		try {
			const c = await api.openCRACase(projectId, { finding_id: findingId.trim() });
			findingId = '';
			notify($t('cra.caseOpened'), 'success');
			await load();
			selected = c.id;
		} catch (err) {
			notify(errorMessage(err));
		}
	}
</script>

<div class="card bg-base-100 shadow-sm mt-6">
	<div class="card-body p-5">
		<h3 class="font-semibold">{$t('cra.heading')}</h3>
		<p class="text-sm text-base-content/60">
			{$t('cra.intro')}
		</p>
		<State {loading} {error} />
		{#if !loading && !error}
			<form class="flex flex-wrap items-end gap-2 mt-2" onsubmit={saveProduct}>
				<label class="label cursor-pointer gap-2">
					<input type="checkbox" class="toggle toggle-sm" bind:checked={product.cra_in_scope} />
					<span class="label-text">{$t('cra.inScope')}</span>
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cra.productName')}</span>
					<input class="input input-bordered input-sm" bind:value={product.product_name} />
				</label>
				<label class="form-control w-28">
					<span class="label-text text-xs">{$t('proj.colVersion')}</span>
					<input class="input input-bordered input-sm" bind:value={product.product_version} />
				</label>
				<label class="form-control">
					<span class="label-text text-xs">{$t('cra.memberStates')}</span>
					<input class="input input-bordered input-sm" bind:value={product.member_states} placeholder="DE, FR, NL" />
				</label>
				<button class="btn btn-sm" type="submit" disabled={saving}>{$t('common.save')}</button>
			</form>
			{#if manufacturer && (!manufacturer.name || !manufacturer.main_establishment)}
				<div class="alert alert-warning text-sm mt-2">
					{$t('cra.manufacturerWarning')}
				</div>
			{/if}

			{#if cases.length === 0}
				<p class="text-sm text-base-content/50 mt-3">{$t('cra.noCases')}</p>
			{:else}
				<div class="overflow-x-auto mt-3">
					<table class="table table-sm">
						<thead><tr><th>{$t('proj.colVuln')}</th><th>{$t('finding.status')}</th><th>{$t('cra.colAware')}</th><th>{$t('cra.colNextDeadline')}</th><th>{$t('cra.colClocks')}</th></tr></thead>
						<tbody>
							{#each cases as c (c.id)}
								{@const d = nextDeadline(c)}
								<tr class="cursor-pointer hover" class:bg-base-200={selected === c.id} onclick={() => (selected = selected === c.id ? null : c.id)}>
									<td><span class="font-medium">{c.vuln_id}</span><div class="text-xs text-base-content/60 truncate max-w-xs">{c.title}</div></td>
									<td><span class="badge badge-sm {stateClass(c.state)}">{stateLabel(c.state)}</span></td>
									<td class="text-xs">{fmtDate(c.aware_at)}</td>
									<td class="text-xs">
										{#if d && d.due_at}{fmtDate(d.due_at)}<div class={d.status === 'missed' ? 'text-error' : 'text-base-content/60'}>{countdown(d.due_at, now)}</div>{:else}—{/if}
									</td>
									<td>
										{#each c.deadlines as dl (dl.stage)}
											<span class="badge badge-xs mr-1 {deadlineClass(dl.status)}" title={dl.stage}>{deadlineLabel(dl.status)}</span>
										{/each}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
			{#if selected}
				<div class="border border-base-300 rounded-box p-4 mt-3">
					<CraCaseDetail caseId={selected} onchange={load} />
				</div>
			{/if}
			{#if product.cra_in_scope}
				<form class="flex flex-wrap items-end gap-2 mt-3" onsubmit={openManual}>
					<label class="form-control">
						<span class="label-text text-xs">{$t('cra.openByHandLabel')}</span>
						<input class="input input-bordered input-sm w-80" bind:value={findingId} placeholder={$t('cra.findingIdPlaceholder')} />
					</label>
					<button class="btn btn-sm btn-outline" type="submit" disabled={!findingId.trim()}>{$t('cra.openCase')}</button>
				</form>
			{/if}
		{/if}
	</div>
</div>
