<script>
	// Dependency-free SVG line / stacked-area chart for daily metric trends.
	//
	// points: the API's trend points ({ date: 'YYYY-MM-DD', reconstructed, … }),
	//         oldest first. Days missing from the series are drawn as gaps.
	// series: [{ label, color, value: (point) => number }], label an i18n key
	// stacked: draw series as stacked areas (e.g. open findings by severity)
	//          instead of independent lines.
	// Reconstructed days (the first-run backfill) are shaded faintly.
	import { t, activeLocale } from '#lib/i18n.js';

	/** @type {{ points?: any[], series?: import('#lib/trends.js').Series[], stacked?: boolean, height?: number, format?: (v: number) => string }} */
	let { points = [], series = [], stacked = false, height = 180, format = (/** @type {number} */ v) => String(v) } = $props();

	const DAY = 86_400_000;
	const PAD = { top: 10, right: 10, bottom: 22, left: 40 };

	let width = $state(0);
	let hover = $state(-1); // index into points

	const plotW = $derived(Math.max(0, width - PAD.left - PAD.right));
	const plotH = $derived(Math.max(0, height - PAD.top - PAD.bottom));

	const times = $derived(points.map((p) => Date.parse(p.date + 'T00:00:00Z')));
	const t0 = $derived(times[0] ?? 0);
	const t1 = $derived(times[times.length - 1] ?? 0);

	// values[s][i] = series s at point i; tops/bottoms are the stacked bounds.
	const values = $derived(series.map((s) => points.map((p) => Number(s.value(p)) || 0)));
	const bounds = $derived.by(() => {
		const lo = [];
		const hi = [];
		let base = points.map(() => 0);
		for (const vs of values) {
			const top = stacked ? vs.map((v, i) => base[i] + v) : vs;
			lo.push(stacked ? base : vs);
			hi.push(top);
			if (stacked) base = top;
		}
		return { lo, hi };
	});

	// A "nice" axis maximum: 1, 2, 2.5 or 5 × 10^n at or above the data.
	const yMax = $derived.by(() => {
		let m = 0;
		for (const hs of bounds.hi) for (const v of hs) m = Math.max(m, v);
		if (m <= 0) return 1;
		const p = 10 ** Math.floor(Math.log10(m));
		for (const f of [1, 2, 2.5, 5, 10]) if (f * p >= m) return f * p;
		return 10 * p;
	});

	// Skip a fractional middle tick on count data (e.g. 0.5 findings).
	const yTicks = $derived.by(() => {
		const integral = values.every((vs) => vs.every(Number.isInteger));
		return Number.isInteger(yMax / 2) || !integral ? [0, yMax / 2, yMax] : [0, yMax];
	});
	/** @param {number} i */
	const x = (i) => PAD.left + (t1 === t0 ? plotW / 2 : ((times[i] - t0) / (t1 - t0)) * plotW);
	/** @param {number} v */
	const y = (v) => PAD.top + plotH - (v / yMax) * plotH;

	// Runs of consecutive days: a missing day breaks the line instead of
	// interpolating across it.
	const runs = $derived.by(() => {
		const out = [];
		let start = 0;
		for (let i = 1; i <= times.length; i++) {
			if (i === times.length || times[i] - times[i - 1] > DAY * 1.5) {
				out.push([start, i - 1]);
				start = i;
			}
		}
		return out;
	});

	/** @param {number[]} vs */
	function linePath(vs) {
		return runs
			.map(([a, b]) => {
				let d = '';
				for (let i = a; i <= b; i++) d += `${i === a ? 'M' : 'L'}${x(i).toFixed(1)},${y(vs[i]).toFixed(1)}`;
				return d;
			})
			.join('');
	}

	/** @param {number[]} lo @param {number[]} hi */
	function areaPath(lo, hi) {
		return runs
			.map(([a, b]) => {
				let d = '';
				for (let i = a; i <= b; i++) d += `${i === a ? 'M' : 'L'}${x(i).toFixed(1)},${y(hi[i]).toFixed(1)}`;
				for (let i = b; i >= a; i--) d += `L${x(i).toFixed(1)},${y(lo[i]).toFixed(1)}`;
				return d + 'Z';
			})
			.join('');
	}

	// Contiguous reconstructed spans, widened by half a day on each side.
	const reconstructed = $derived.by(() => {
		const out = [];
		const half = times.length > 1 ? (plotW / Math.max(1, (t1 - t0) / DAY)) / 2 : 0;
		let start = -1;
		for (let i = 0; i <= points.length; i++) {
			const on = i < points.length && points[i].reconstructed;
			if (on && start < 0) start = i;
			if (!on && start >= 0) {
				const x0 = Math.max(PAD.left, x(start) - half);
				const x1 = Math.min(PAD.left + plotW, x(i - 1) + half);
				out.push({ x: x0, w: Math.max(1, x1 - x0) });
				start = -1;
			}
		}
		return out;
	});

	/** @param {number} i */
	const shortDate = (i) =>
		new Date(times[i]).toLocaleDateString(activeLocale(), { month: 'short', day: 'numeric', timeZone: 'UTC' });
	const xTicks = $derived(
		points.length === 0 ? [] : [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])]
	);

	/** @param {MouseEvent & { currentTarget: Element }} e */
	function onMove(e) {
		if (points.length === 0) return;
		const rect = e.currentTarget.getBoundingClientRect();
		const px = e.clientX - rect.left;
		let best = 0;
		for (let i = 1; i < points.length; i++) if (Math.abs(x(i) - px) < Math.abs(x(best) - px)) best = i;
		hover = best;
	}
</script>

<div class="relative w-full" bind:clientWidth={width}>
	{#if points.length === 0}
		<div class="flex items-center justify-center text-sm text-base-content/50" style="height:{height}px">
			{$t('trend.noHistory')}
		</div>
	{:else if width > 0}
		<svg
			{width}
			{height}
			role="img"
			aria-label={$t('trend.aria')}
			class="block select-none"
			onmousemove={onMove}
			onmouseleave={() => (hover = -1)}
		>
			{#each reconstructed as r, i (i)}
				<rect x={r.x} y={PAD.top} width={r.w} height={plotH} class="fill-base-content/5">
					<title>{$t('trend.reconstructedTitle')}</title>
				</rect>
			{/each}

			{#each yTicks as v (v)}
				<line x1={PAD.left} x2={PAD.left + plotW} y1={y(v)} y2={y(v)} class="stroke-base-content/10" />
				<text x={PAD.left - 6} y={y(v)} dy="0.32em" text-anchor="end" class="fill-base-content/50 text-[10px]">
					{format(v)}
				</text>
			{/each}
			{#each xTicks as i (i)}
				<text
					x={x(i)}
					y={height - 6}
					text-anchor={i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle'}
					class="fill-base-content/50 text-[10px]">{shortDate(i)}</text
				>
			{/each}

			{#each series as s, si (s.label)}
				{#if stacked}
					<path d={areaPath(bounds.lo[si], bounds.hi[si])} fill={s.color} fill-opacity="0.35" />
					<path d={linePath(bounds.hi[si])} fill="none" stroke={s.color} stroke-width="1.5" />
				{:else}
					<path d={linePath(values[si])} fill="none" stroke={s.color} stroke-width="2" stroke-linejoin="round" />
				{/if}
				{#if points.length === 1}
					<circle cx={x(0)} cy={y(bounds.hi[si][0])} r="3" fill={s.color} />
				{/if}
			{/each}

			{#if hover >= 0}
				<line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={PAD.top + plotH} class="stroke-base-content/30" />
				{#each series as s, si (s.label)}
					<circle cx={x(hover)} cy={y(bounds.hi[si][hover])} r="3" fill={s.color} />
				{/each}
			{/if}
		</svg>

		{#if hover >= 0}
			<div
				class="pointer-events-none absolute top-0 z-10 rounded-box bg-base-100 border border-base-300 shadow px-2 py-1 text-xs"
				style="{x(hover) > width / 2 ? `right:${width - x(hover) + 8}px` : `left:${x(hover) + 8}px`}"
			>
				<div class="font-semibold mb-0.5">
					{points[hover].date}{#if points[hover].reconstructed}<span class="font-normal text-base-content/50"> · {$t('trend.reconstructed')}</span>{/if}
				</div>
				{#each [...series].reverse() as s (s.label)}
					<div class="flex items-center gap-1.5">
						<span class="inline-block w-2 h-2 rounded-full" style="background:{s.color}"></span>
						<span class="text-base-content/70">{$t(s.label)}</span>
						<span class="ml-auto pl-3 font-semibold tabular-nums">{format(Number(s.value(points[hover])) || 0)}</span>
					</div>
				{/each}
			</div>
		{/if}
	{/if}

	{#if series.length > 1 || reconstructed.length}
		<div class="flex flex-wrap gap-3 mt-1 text-xs text-base-content/60">
			{#each series as s (s.label)}
				<span class="flex items-center gap-1">
					<span class="inline-block w-2 h-2 rounded-full" style="background:{s.color}"></span>{$t(s.label)}
				</span>
			{/each}
			{#if reconstructed.length}
				<span class="flex items-center gap-1">
					<span class="inline-block w-3 h-2 bg-base-content/10"></span>{$t('trend.reconstructed')}
				</span>
			{/if}
		</div>
	{/if}
</div>
