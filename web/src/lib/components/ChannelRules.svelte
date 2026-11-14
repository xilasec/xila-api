<script>
	// A channel's delivery rules: the lowest severity it wants, an optional CEL
	// filter over the event, and an optional scheduled summary (daily or
	// weekly, at an hour in UTC).
	import { SEVERITIES } from '#lib/format.js';
	import { weekday } from '#lib/channels.js';
	import { t, labelOf, contentLocale } from '#lib/i18n.js';
	import Field from '#lib/components/Field.svelte';

	/** @type {{ rules: { min_severity: string, filter: string, summary: string, summary_hour: number, summary_weekday: number } }} */
	let { rules = $bindable() } = $props();
	const hours = Array.from({ length: 24 }, (_, h) => h);
</script>

<div class="grid grid-cols-2 gap-3">
	<Field label={$t('rules.minSeverity')} hint={$t('rules.minSeverityHint')}>
		<select bind:value={rules.min_severity} class="select select-bordered w-full">
			<option value="">{$t('rules.everything')}</option>
			{#each SEVERITIES as s}<option value={s}>{$t('rules.andAbove', { severity: $labelOf('severity', s) })}</option>{/each}
		</select>
	</Field>
	<div class="col-span-2">
		<Field label={$t('rules.filter')} hint={$t('rules.filterHint')}>
			<textarea bind:value={rules.filter} rows="2" spellcheck="false"
				placeholder={'event.finding.kev && "internet-facing" in event.project.tags'}
				class="textarea textarea-bordered textarea-sm w-full font-mono"></textarea>
			<span class="label-text-alt text-base-content/50 mt-1">
				<code>event</code>: type, title, severity, project_id, finding_id, fields ·
				<code>event.project</code>: name, slug, tags, criticality ·
				<code>event.finding</code>: scanner, category, rule_id, title, severity, status, cve, cvss, epss, kev,
				kev_sources, package, fixed_version, file_path, tags
			</span>
		</Field>
	</div>
	<Field label={$t('rules.summary')} hint={$t('rules.summaryHint')}>
		<select bind:value={rules.summary} class="select select-bordered w-full">
			<option value="none">{$t('rules.none')}</option>
			<option value="daily">{$t('rules.dailyOption')}</option>
			<option value="weekly">{$t('rules.weeklyOption')}</option>
		</select>
	</Field>
	{#if rules.summary === 'weekly'}
		<Field label={$t('rules.on')}>
			<select bind:value={rules.summary_weekday} class="select select-bordered w-full">
				{#each [0, 1, 2, 3, 4, 5, 6] as i}<option value={i}>{weekday(i, $contentLocale)}</option>{/each}
			</select>
		</Field>
	{/if}
	{#if rules.summary !== 'none'}
		<Field label={$t('rules.at')}>
			<select bind:value={rules.summary_hour} class="select select-bordered w-full">
				{#each hours as h}<option value={h}>{String(h).padStart(2, '0')}:00</option>{/each}
			</select>
		</Field>
	{/if}
</div>
