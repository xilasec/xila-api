// Every locale's catalogue has exactly the English keys, the same {param}
// placeholders, and the same plural shape ("one|other"). svelte-check catches
// a missing key in a typed catalogue; this also catches an extra key, a
// dropped or misspelt placeholder, and a lost plural form. Run by pnpm check.
import { readdirSync } from 'node:fs';
import en from '../src/lib/i18n/en.js';

// Every catalogue next to en.js is checked — a new language needs no edit here.
const dir = new URL('../src/lib/i18n/', import.meta.url);
/** @type {Record<string, Record<string, string>>} */
const catalogues = {};
for (const file of readdirSync(dir).filter((f) => f.endsWith('.js') && f !== 'en.js')) {
	catalogues[file.replace(/\.js$/, '')] = (await import(new URL(file, dir).href)).default;
}

const placeholders = (/** @type {string} */ s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
const forms = (/** @type {string} */ s) => s.split('|').length;

let errors = 0;
for (const [name, cat] of Object.entries(catalogues)) {
	for (const key of Object.keys(en)) {
		if (!(key in cat)) {
			console.error(`${name}: missing ${key}`);
			errors++;
			continue;
		}
		const a = /** @type {Record<string, string>} */ (en)[key];
		const b = /** @type {Record<string, string>} */ (cat)[key];
		if (placeholders(a) !== placeholders(b)) {
			console.error(`${name}: ${key} placeholders {${placeholders(b)}} ≠ en {${placeholders(a)}}`);
			errors++;
		}
		if (forms(a) !== forms(b)) {
			console.error(`${name}: ${key} has ${forms(b)} plural form(s), en has ${forms(a)}`);
			errors++;
		}
	}
	for (const key of Object.keys(cat)) {
		if (!(key in en)) {
			console.error(`${name}: unknown key ${key}`);
			errors++;
		}
	}
}
if (errors) {
	console.error(`i18n: ${errors} problem(s)`);
	process.exit(1);
}
console.log(`i18n: ${Object.keys(en).length} keys, ${Object.keys(catalogues).join(', ')} consistent with en`);
