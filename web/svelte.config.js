import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
export default {
	preprocess: vitePreprocess(),
	kit: {
		// SPA: single-page app served as static files, talking to the Go API.
		adapter: adapter({ fallback: 'index.html' })
	}
};
