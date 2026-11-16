<script>
	// A project's priority weights (owner): the factors of severity ×
	// exploitability × reachability × exposure. Empty fields keep the default;
	// the API refuses an override that would let a discount raise a priority
	// or bury an exploited critical under a quiet medium.
	import { api, ApiError, errorMessage } from '#lib/api.js';
	import { notify } from '#lib/stores.js';
	import { t } from '#lib/i18n.js';

	/** @type {{ projectId: string }} */
	let { projectId } = $props();

	/** @type {{ key: string, label: import('#lib/i18n.js').MessageKey }[][]} */
	const GROUPS = [
		[
			{ key: 'critical', label: 'enum.severity.critical' },
			{ key: 'high', label: 'enum.severity.high' },
			{ key: 'medium', label: 'enum.severity.medium' },
			{ key: 'low', label: 'enum.severity.low' },
			{ key: 'info', label: 'enum.severity.info' }
		],
		[
			{ key: 'kev', label: 'pw.kev' },
			{ key: 'epss_slope', label: 'pw.epssSlope' },
			{ key: 'weaponized', label: 'pw.weaponized' },
			{ key: 'poc', label: 'pw.poc' }
		],
		[
			{ key: 'transitive', label: 'pw.transitive' },
			{ key: 'dev', label: 'pw.dev' },
			{ key: 'optional', label: 'pw.optional' },
			{ key: 'internet', label: 'pw.internet' },
			{ key: 'isolated', label: 'pw.isolated' }
		]
	];

	let data = $state(/** @type {any} */ (null));
	/** @type {Record<string, string | number>} */
	let form = $state({});
	let busy = $state(false);
	let forbidden = $state(false);

	/** @param {any} d */
	function show(d) {
		data = d;
		/** @type {Record<string, string | number>} */
		const f = {};
		for (const group of GROUPS) {
			for (const { key } of group) {
				f[key] = d.custom && d.weights[key] !== d.defaults[key] ? d.weights[key] : '';
			}
		}
		form = f;
	}

	$effect(() => {
		projectId;
		api.priorityWeights(projectId).then(show).catch((err) => notify(errorMessage(err)));
	});

	/** @param {SubmitEvent} e */
	async function save(e) {
		e.preventDefault();
		busy = true;
		try {
			/** @type {Record<string, number>} */
			const body = {};
			for (const [k, v] of Object.entries(form)) {
				if (v !== '' && v !== null) body[k] = Number(v);
			}
			const res = await api.setPriorityWeights(projectId, body);
			show(res);
			notify($t('pw.saved', { count: res.reprioritized ?? 0 }), 'success');
		} catch (err) {
			if (err instanceof ApiError && err.status === 403) forbidden = true;
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}

	async function reset() {
		busy = true;
		try {
			const res = await api.resetPriorityWeights(projectId);
			show(res);
			notify($t('pw.saved', { count: res.reprioritized ?? 0 }), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			busy = false;
		}
	}
</script>

{#if data}
	<form onsubmit={save} class="bg-base-100 rounded-box shadow-sm p-4 max-w-3xl mt-6">
		<h3 class="font-semibold">{$t('pw.title')} {#if data.custom}<span class="badge badge-info badge-sm">{$t('pw.custom')}</span>{/if}</h3>
		<p class="text-xs text-base-content/60 mb-3">{$t('pw.intro')}</p>
		{#each GROUPS as group, gi}
			<div class="text-xs font-semibold text-base-content/60 mt-2 mb-1">
				{gi === 0 ? $t('pw.severity') : gi === 1 ? $t('pw.exploitability') : $t('pw.reachExposure')}
			</div>
			<div class="flex flex-wrap gap-3">
				{#each group as { key, label } (key)}
					<label class="form-control w-28">
						<span class="label-text text-xs">{$t(label)}</span>
						<input type="number" step="any" min="0" bind:value={form[key]} placeholder={String(data.defaults[key])}
							disabled={forbidden} class="input input-bordered input-xs" />
					</label>
				{/each}
			</div>
		{/each}
		<div class="flex gap-2 justify-end mt-3">
			{#if data.custom}<button type="button" class="btn btn-ghost btn-sm" onclick={reset} disabled={busy}>{$t('pw.reset')}</button>{/if}
			<button class="btn btn-primary btn-sm" disabled={busy || forbidden}>
				{#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}{$t('common.save')}
			</button>
		</div>
	</form>
{/if}
