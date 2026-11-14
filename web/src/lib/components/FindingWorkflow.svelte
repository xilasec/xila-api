<script>
	// Analyst workflow on one finding: who owns it, the discussion, evidence
	// files, and the full history of what happened (by whom, and why).
	import { api, ApiError, errorMessage } from '$lib/api.js';
	import { notify } from '$lib/stores.js';
	import { fmtDate, fmtNumber } from '$lib/format.js';
	import { t, labelOf } from '$lib/i18n.js';

	/** @type {{ finding: any, onchange: (f: any) => void, revision?: number, onconflict?: () => void }} */
	let { finding, onchange, revision = 0, onconflict = () => {} } = $props();

	// A 412 (someone else changed the finding since it was loaded): reload.
	/** @param {unknown} err */
	function failed(err) {
		if (err instanceof ApiError && err.status === 412) {
			notify($t('fields.conflict'));
			onconflict();
		} else {
			notify(errorMessage(err));
		}
	}

	let assignees = $state(/** @type {any[]} */ ([]));
	let events = $state(/** @type {any[]} */ ([]));
	let comments = $state(/** @type {any[]} */ ([]));
	let attachments = $state(/** @type {any[]} */ ([]));
	let draft = $state('');
	let posting = $state(false);
	let uploading = $state(false);
	let me = $state(/** @type {any} */ (null));
	/** @type {HTMLInputElement} */
	let fileInput;

	const commentById = $derived(Object.fromEntries(comments.map((c) => [c.id, c])));

	/** @param {{ id: string, updated_at?: string, revision?: number }} f — the extra fields only make the $effect depend on them */
	async function loadAll(f) {
		const [ev, cm, at] = await Promise.all([
			api.findingHistory(f.id).catch(() => []),
			api.findingComments(f.id).catch(() => []),
			api.findingAttachments(f.id).catch(() => [])
		]);
		if (f.id !== finding.id) return; // navigated away meanwhile
		events = ev;
		comments = cm;
		attachments = at;
	}

	// Reload on navigation and whenever the finding itself changes (status,
	// severity, assignee all bump updated_at), so the history never lags.
	// `revision` bumps for events that don't touch the finding (an assessment
	// requested or rejected).
	$effect(() => {
		loadAll({ id: finding.id, updated_at: finding.updated_at, revision });
	});
	$effect(() => {
		const pid = finding.project_id;
		api.projectAssignees(pid).then((a) => (assignees = a)).catch(() => (assignees = []));
	});
	$effect(() => {
		api.me().then((u) => (me = u)).catch(() => {});
	});

	/** @param {{ currentTarget: { value: string } }} e */
	async function assign(e) {
		try {
			onchange(await api.assignFinding(finding.id, e.currentTarget.value, finding.updated_at));
			notify($t('wf.assigneeUpdated'), 'success');
		} catch (err) {
			failed(err);
			e.currentTarget.value = finding.assignee_id ?? '';
		}
	}

	let tagDraft = $state('');
	let tagBusy = $state(false);
	/** @param {string[]} next */
	async function saveTags(next) {
		tagBusy = true;
		try {
			onchange(await api.setFindingTags(finding.id, next, finding.updated_at));
		} catch (err) {
			failed(err);
		} finally {
			tagBusy = false;
		}
	}
	/** @param {SubmitEvent} e */
	async function addTag(e) {
		e.preventDefault();
		const tag = tagDraft.trim().toLowerCase();
		if (!tag) return;
		await saveTags([...(finding.tags ?? []), tag]);
		tagDraft = '';
	}

	/** @param {SubmitEvent} e */
	async function postComment(e) {
		e.preventDefault();
		if (!draft.trim()) return;
		posting = true;
		try {
			await api.addFindingComment(finding.id, draft);
			draft = '';
			await loadAll(finding);
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			posting = false;
		}
	}

	/** @param {any} c */
	async function deleteComment(c) {
		if (!confirm($t('wf.confirmDeleteComment'))) return;
		try {
			await api.deleteFindingComment(finding.id, c.id);
			await loadAll(finding);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	async function upload() {
		const file = fileInput.files?.[0];
		if (!file) return;
		if (file.size > 10 * 1024 * 1024) {
			notify($t('wf.attachLimit'));
			fileInput.value = '';
			return;
		}
		uploading = true;
		try {
			await api.addFindingAttachment(finding.id, file);
			await loadAll(finding);
			notify($t('wf.attached', { name: file.name }), 'success');
		} catch (err) {
			notify(errorMessage(err));
		} finally {
			uploading = false;
			fileInput.value = '';
		}
	}

	/** @param {any} a */
	async function deleteAttachment(a) {
		if (!confirm($t('wf.confirmDeleteFile', { name: a.filename }))) return;
		try {
			await api.deleteFindingAttachment(finding.id, a.id);
			await loadAll(finding);
		} catch (err) {
			notify(errorMessage(err));
		}
	}

	/** @param {number} n */
	const fmtSize = (n) =>
		n < 1024 ? `${fmtNumber(n)} B` : n < 1048576 ? `${fmtNumber(n / 1024, { maximumFractionDigits: 1 })} KB` : `${fmtNumber(n / 1048576, { maximumFractionDigits: 1 })} MB`;
	/** @param {any} e */
	const who = (e) => (e.actor === 'system' ? 'Xila' : e.actor_name);
	/** @param {any} e */
	function describe(e) {
		switch (e.kind) {
			case 'created': return $t('wf.ev.created');
			case 'status': return `${$labelOf('status', e.from)} → ${$labelOf('status', e.to)}`;
			case 'severity': return $t('wf.ev.severity', { from: $labelOf('severity', e.from), to: $labelOf('severity', e.to) });
			case 'assignee': return e.to ? $t('wf.ev.assigned', { who: e.to }) : $t('wf.ev.unassigned', { who: e.from ?? '' });
			case 'attachment': return $t('wf.ev.attachment', { name: e.to });
			case 'tags': return e.to ? $t('wf.ev.tags', { tags: e.to }) : $t('wf.ev.tagsRemoved');
			case 'assessment':
				if (e.to === 'pending') return $t('wf.ev.requested', { what: e.from });
				if (e.to === 'approved') return $t('wf.ev.approved', { what: e.from });
				if (e.to === 'rejected') return $t('wf.ev.rejected', { what: e.from });
				return $t('wf.ev.decided', { verdict: e.to, what: e.from });
			default: return e.kind;
		}
	}
</script>

<div class="mt-6 grid gap-4 md:grid-cols-3">
	<!-- Activity: history + discussion, one timeline -->
	<div class="card bg-base-100 shadow-sm md:col-span-2">
		<div class="card-body">
			<h2 class="font-semibold">{$t('wf.activity')}</h2>
			<ul class="space-y-3">
				{#each events as e (e.id)}
					<li class="flex gap-3 text-sm">
						<span class="mt-1.5 h-2 w-2 shrink-0 rounded-full {e.actor === 'system' ? 'bg-base-300' : 'bg-primary'}"></span>
						<div class="min-w-0 flex-1">
							{#if e.kind === 'comment'}
								{@const c = commentById[e.to]}
								<div class="text-xs text-base-content/50">
									<span class="font-medium text-base-content">{who(e)}</span> {$t('wf.commented')} · {fmtDate(e.created_at)}
									{#if c && (c.author_id === me?.id || me?.is_admin)}
										<button class="link link-hover ml-2" onclick={() => deleteComment(c)}>{$t('wf.deleteLower')}</button>
									{/if}
								</div>
								{#if c}
									<p class="mt-1 whitespace-pre-wrap rounded-box bg-base-200 px-3 py-2">{c.body}</p>
								{:else}
									<p class="mt-1 text-xs italic text-base-content/40">{$t('wf.commentDeleted')}</p>
								{/if}
							{:else}
								<span class="font-medium">{who(e)}</span>
								<span class="text-base-content/70">{describe(e)}</span>
								<span class="text-xs text-base-content/40">· {fmtDate(e.created_at)}</span>
								{#if e.note}<div class="text-xs text-base-content/60">“{e.note}”</div>{/if}
							{/if}
						</div>
					</li>
				{/each}
			</ul>
			<form class="mt-2 flex flex-col gap-2" onsubmit={postComment}>
				<textarea class="textarea textarea-bordered text-sm" rows="2" maxlength="20000" placeholder={$t('wf.commentPlaceholder')} bind:value={draft}></textarea>
				<div class="flex justify-end">
					<button class="btn btn-primary btn-sm" disabled={posting || !draft.trim()}>{$t('wf.comment')}</button>
				</div>
			</form>
		</div>
	</div>

	<div class="flex flex-col gap-4">
		<!-- Owner -->
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<h3 class="text-sm font-semibold text-base-content/60">{$t('wf.assignee')}</h3>
				<select class="select select-bordered select-sm" value={finding.assignee_id ?? ''} onchange={assign}>
					<option value="">{$t('wf.unassigned')}</option>
					{#each assignees as a (a.user_id)}
						<option value={a.user_id}>{a.email}</option>
					{/each}
					{#if finding.assignee_id && !assignees.some((a) => a.user_id === finding.assignee_id)}
						<option value={finding.assignee_id}>{finding.assignee_email ?? finding.assignee_id}</option>
					{/if}
				</select>
				{#if me && finding.assignee_id !== me.id}
					<button class="btn btn-ghost btn-xs self-start" onclick={() => assign({ currentTarget: { value: me.id } })}>{$t('wf.assignMe')}</button>
				{/if}
			</div>
		</div>

		<!-- Labels -->
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body gap-2">
				<h3 class="text-sm font-semibold text-base-content/60">{$t('wf.tags')}</h3>
				{#if finding.tags?.length}
					<div class="flex flex-wrap gap-1">
						{#each finding.tags as tg (tg)}
							<span class="badge badge-outline gap-1">
								<a href="/findings?tag={encodeURIComponent(tg)}" class="link-hover" title={$t('wf.allTagged', { tag: tg })}>{tg}</a>
								<button class="opacity-60 hover:opacity-100" disabled={tagBusy} aria-label={$t('wf.removeTag', { tag: tg })}
									onclick={() => saveTags(finding.tags.filter((/** @type {string} */ x) => x !== tg))}>✕</button>
							</span>
						{/each}
					</div>
				{/if}
				<form class="flex gap-1" onsubmit={addTag}>
					<input bind:value={tagDraft} placeholder={$t('wf.tagPlaceholder')} maxlength="50"
						class="input input-bordered input-xs flex-1" aria-label={$t('wf.newTag')} />
					<button class="btn btn-ghost btn-xs" disabled={tagBusy || !tagDraft.trim()}>{$t('common.add')}</button>
				</form>
			</div>
		</div>

		<!-- Evidence -->
		<div class="card bg-base-100 shadow-sm">
			<div class="card-body">
				<div class="flex items-center justify-between">
					<h3 class="text-sm font-semibold text-base-content/60">{$t('wf.attachments')}</h3>
					<label class="btn btn-ghost btn-xs {uploading ? 'btn-disabled' : ''}">
						{#if uploading}<span class="loading loading-spinner loading-xs"></span>{:else}{$t('wf.addFile')}{/if}
						<input bind:this={fileInput} type="file" class="hidden" onchange={upload} />
					</label>
				</div>
				{#if attachments.length === 0}
					<p class="text-xs text-base-content/40">{$t('wf.attachHint')}</p>
				{:else}
					<ul class="space-y-1 text-sm">
						{#each attachments as a (a.id)}
							<li class="flex items-center gap-2">
								<button class="link link-hover min-w-0 flex-1 truncate text-left" title="{a.filename} · sha256 {a.sha256}" onclick={() => api.downloadFindingAttachment(finding.id, a).catch((err) => notify(err.message))}>{a.filename}</button>
								<span class="text-xs text-base-content/40">{fmtSize(a.size)}</span>
								{#if a.uploaded_by === me?.id || me?.is_admin}
									<button class="btn btn-ghost btn-xs" aria-label={$t('wf.deleteAttachment')} onclick={() => deleteAttachment(a)}>✕</button>
								{/if}
							</li>
						{/each}
					</ul>
				{/if}
			</div>
		</div>
	</div>
</div>
