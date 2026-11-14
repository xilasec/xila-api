import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		port: 5173,
		// Proxy API calls to the Go server so `pnpm dev` works with no .env: the
		// SPA uses the relative "/api/v1" base and requests are forwarded here.
		proxy: {
			// Node global; the UI build has no @types/node.
			'/api': /** @type {any} */ (globalThis).process.env.VITE_API_PROXY || 'http://localhost:8080'
		}
	}
});
