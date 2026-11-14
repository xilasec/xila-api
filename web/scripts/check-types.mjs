// Type-check ratchet: runs svelte-check and fails when the error count rises
// above the recorded baseline (web/.svelte-check-baseline). A count below the
// baseline passes and asks you to lower the baseline, so it only ever goes down.
//
//   pnpm check            # gate (CI)
//   pnpm check --update   # rewrite the baseline to the current count
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const baselineFile = fileURLToPath(new URL('../.svelte-check-baseline', import.meta.url));
const update = process.argv.includes('--update');

// Windows can only start the .cmd shim through a shell; the command and its
// arguments are constants, never user input.
// nosemgrep: javascript.lang.security.audit.spawn-shell-true.spawn-shell-true
const run = spawnSync('svelte-check', ['--output', 'machine', '--threshold', 'error'], {
	encoding: 'utf8',
	shell: process.platform === 'win32',
	maxBuffer: 64 << 20
});
if (run.error) {
	console.error('could not run svelte-check:', run.error.message);
	process.exit(2);
}
const lines = (run.stdout || '').split('\n');
const errors = lines.filter((l) => / ERROR /.test(l));
const done = lines.find((l) => / COMPLETED /.test(l));
if (!done) {
	console.error(run.stdout, run.stderr);
	console.error('svelte-check did not complete');
	process.exit(2);
}

const count = errors.length;
if (update) {
	writeFileSync(baselineFile, `${count}\n`);
	console.log(`baseline set to ${count}`);
	process.exit(0);
}

let baseline;
try {
	baseline = Number.parseInt(readFileSync(baselineFile, 'utf8'), 10);
} catch {
	console.error(`missing ${baselineFile}; run: pnpm check --update`);
	process.exit(2);
}

if (count > baseline) {
	// Show the errors in files with any error so the new ones are easy to spot.
	for (const e of errors) console.error(e);
	console.error(`\nsvelte-check: ${count} errors > baseline ${baseline}. Fix the new ones (an undeclared variable here once shipped a blank page).`);
	process.exit(1);
}
if (count < baseline) {
	console.log(`svelte-check: ${count} errors < baseline ${baseline} — nice. Lower the baseline: pnpm check --update`);
} else {
	console.log(`svelte-check: ${count} errors (baseline ${baseline})`);
}
