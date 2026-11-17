<script>
	// Small stroke icons for the app shell (24x24 grid, currentColor), drawn
	// here rather than taken from a font or emoji so they render the same on
	// every system.
	/** @type {{ name: string, class?: string }} */
	let { name, class: cls = 'h-4 w-4' } = $props();

	/** @type {Record<string, string[]>} */
	const PATHS = {
		home: ['M3 11l9-7 9 7', 'M5 10v10h14V10', 'M10 20v-6h4v6'],
		inbox: ['M4 13l2-8h12l2 8', 'M4 13v6h16v-6', 'M4 13h5l1 2h4l1-2h5'],
		list: ['M9 6h11', 'M9 12h11', 'M9 18h11', 'M4 6h.01', 'M4 12h.01', 'M4 18h.01'],
		check: ['M20 6L9 17l-5-5'],
		hourglass: ['M6 3h12', 'M6 21h12', 'M7 3c0 5 10 5 10 9s-10 4-10 9', 'M17 3c0 5-10 5-10 9s10 4 10 9'],
		wrench: ['M14.5 6.5a4 4 0 0 0 5 5L21 13l-8 8-3-3 8-8-1.5-1.5a4 4 0 0 0-5-5z', 'M3 21l6-6'],
		clipboard: ['M9 4h6v3H9z', 'M7 5H5v16h14V5h-2', 'M8 12h8', 'M8 16h5'],
		branch: ['M6 3v12', 'M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M18 9c0 5-6 4-12 9'],
		package: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M4 7.5l8 4.5 8-4.5', 'M12 12v9'],
		scale: ['M12 3v18', 'M7 21h10', 'M5 7h14', 'M5 7l-3 7h6z', 'M19 7l-3 7h6z'],
		shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'],
		book: ['M4 5a2 2 0 0 1 2-2h14v16H6a2 2 0 0 0-2 2z', 'M4 19V5'],
		clock: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 7v5l3 3'],
		flag: ['M5 21V4', 'M5 4h12l-2 4 2 4H5'],
		settings: ['M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M12 2v3', 'M12 19v3', 'M2 12h3', 'M19 12h3', 'M4.9 4.9L7 7', 'M17 17l2.1 2.1', 'M4.9 19.1L7 17', 'M17 7l2.1-2.1'],
		search: ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'M21 21l-4.3-4.3'],
		sun: ['M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M12 2v2', 'M12 20v2', 'M2 12h2', 'M20 12h2', 'M5 5l1.4 1.4', 'M17.6 17.6L19 19', 'M5 19l1.4-1.4', 'M17.6 6.4L19 5'],
		moon: ['M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z'],
		bell: ['M6 16V11a6 6 0 1 1 12 0v5l2 2H4z', 'M10 21h4'],
		menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
		logout: ['M15 4h4v16h-4', 'M10 8l-4 4 4 4', 'M6 12h11'],
		user: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M4 21a8 8 0 0 1 16 0'],
		key: ['M8 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M11 11h10', 'M18 11v3', 'M21 11v2'],
		doc: ['M6 3h9l4 4v14H6z', 'M14 3v5h5', 'M9 13h7', 'M9 17h5'],
		globe: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3c3 3 3 15 0 18', 'M12 3c-3 3-3 15 0 18'],
		chevron: ['M9 6l6 6-6 6'],
		more: ['M5 12h.01', 'M12 12h.01', 'M19 12h.01'],
		filter: ['M4 5h16l-6 8v5l-4 2v-7z']
	};
</script>

<svg class={cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
	{#each PATHS[name] ?? [] as d}<path {d} />{/each}
</svg>
