<script>
	// A kafka channel's brokers, TLS and SASL settings. `kafka.brokers` is a
	// comma-separated string in the UI; callers split it into an array before
	// the API call (see defaultKafka in #lib/channels.js).
	import { t } from '#lib/i18n.js';
	import Field from '#lib/components/Field.svelte';

	/** @type {{
	 *   kafka: { brokers: string, key_template: string, tls: boolean, tls_ca: string,
	 *            sasl_mechanism: string, sasl_username: string, sasl_password: string },
	 *   hasSecret?: boolean,
	 *   clearSecret?: boolean
	 * }} */
	let { kafka = $bindable(), hasSecret = false, clearSecret = $bindable(false) } = $props();
</script>

<div class="grid grid-cols-2 gap-3">
	<div class="col-span-2">
		<Field label={$t('notif.kafkaBrokers')} required hint={$t('notif.kafkaBrokersHint')}>
			<input bind:value={kafka.brokers} required placeholder="broker-1:9092,broker-2:9092"
				class="input input-bordered w-full font-mono" />
		</Field>
	</div>
	<Field label={$t('notif.kafkaKeyTemplate')} hint={$t('notif.kafkaKeyTemplateHint')}>
		<input bind:value={kafka.key_template} placeholder="{'{project_id}'}" class="input input-bordered w-full font-mono" />
	</Field>
	<Field label={$t('notif.kafkaSaslMechanism')}>
		<select bind:value={kafka.sasl_mechanism} class="select select-bordered w-full">
			<option value="">{$t('notif.kafkaSaslNone')}</option>
			<option value="PLAIN">PLAIN</option>
			<option value="SCRAM-SHA-256">SCRAM-SHA-256</option>
			<option value="SCRAM-SHA-512">SCRAM-SHA-512</option>
		</select>
	</Field>
	{#if kafka.sasl_mechanism}
		<Field label={$t('notif.kafkaSaslUsername')} required>
			<input bind:value={kafka.sasl_username} required class="input input-bordered w-full" />
		</Field>
		<Field label={$t('notif.kafkaSaslPassword')}
			hint={hasSecret ? $t('notif.secretSet') : $t('notif.secretHint')}>
			<input bind:value={kafka.sasl_password} type="password" autocomplete="new-password" disabled={clearSecret}
				placeholder={hasSecret ? '••••••••' : ''} class="input input-bordered w-full font-mono" />
		</Field>
		{#if hasSecret}
			<label class="label cursor-pointer justify-start gap-2">
				<input type="checkbox" bind:checked={clearSecret} class="checkbox checkbox-sm" />
				<span class="label-text">{$t('notif.removeSecret')}</span>
			</label>
		{/if}
	{/if}
	<label class="label cursor-pointer justify-start gap-2">
		<input type="checkbox" bind:checked={kafka.tls} class="checkbox checkbox-sm" />
		<span class="label-text">{$t('notif.kafkaTls')}</span>
	</label>
	{#if kafka.tls}
		<div class="col-span-2">
			<Field label={$t('notif.kafkaTlsCa')} hint={$t('notif.kafkaTlsCaHint')}>
				<textarea bind:value={kafka.tls_ca} rows="3" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"
					class="textarea textarea-bordered textarea-sm w-full font-mono"></textarea>
			</Field>
		</div>
	{/if}
</div>
