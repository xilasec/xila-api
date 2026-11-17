// Links out to public vulnerability and package databases. Pure, so every
// page builds the same URLs.

/**
 * External pages for one advisory id: NVD for a CVE, GitHub Advisories for a
 * GHSA, OSV for both and for the ecosystem databases OSV aggregates (PYSEC,
 * GO, RUSTSEC, …). Unknown shapes (scanner rule ids) get none.
 * @param {string | null | undefined} id
 * @returns {{ label: string, href: string }[]}
 */
export function advisoryLinks(id) {
	const v = (id ?? '').trim();
	if (!v) return [];
	/** @type {{ label: string, href: string }[]} */
	const out = [];
	let canon = v;
	if (/^CVE-\d{4}-\d{4,}$/i.test(v)) {
		canon = v.toUpperCase();
		out.push({ label: 'NVD', href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(canon)}` });
	} else if (/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i.test(v)) {
		// GitHub's canonical form: upper-case prefix, lower-case body.
		canon = 'GHSA' + v.slice(4).toLowerCase();
		out.push({ label: 'GitHub', href: `https://github.com/advisories/${encodeURIComponent(canon)}` });
	} else if (!/^(PYSEC|GO|RUSTSEC|GSD|OSV|MAL|RSEC|DSA|DLA|USN|ALSA|ALBA|RHSA|SUSE-SU|BIT|CURL|UBUNTU|DEBIAN|ECHO|MGASA|OESA|PSF|CGA|MINI|HSEC|LBSEC|ROOT)-/i.test(v)) {
		return [];
	}
	out.push({ label: 'OSV', href: `https://osv.dev/vulnerability/${encodeURIComponent(canon)}` });
	return out;
}

// purl type → deps.dev system, for the ecosystems deps.dev covers.
const DEPS_DEV = /** @type {Record<string, string>} */ ({
	npm: 'npm',
	pypi: 'pypi',
	maven: 'maven',
	golang: 'go',
	cargo: 'cargo',
	nuget: 'nuget'
});

/**
 * The deps.dev page of a package version, from its package URL
 * (pkg:type/namespace/name@version); null for ecosystems deps.dev doesn't
 * cover or an unparseable purl.
 * @param {string | null | undefined} purl
 * @returns {string | null}
 */
export function depsDevURL(purl) {
	const m = /^pkg:([a-z0-9.+-]+)\/([^?#@]+)(?:@([^?#]+))?/i.exec((purl ?? '').trim());
	if (!m) return null;
	const system = DEPS_DEV[m[1].toLowerCase()];
	if (!system) return null;
	let segments;
	try {
		segments = m[2].split('/').filter(Boolean).map(decodeURIComponent);
	} catch {
		return null;
	}
	if (segments.length === 0) return null;
	const name = segments.pop() ?? '';
	const namespace = segments.join('/');
	/** @type {string} */
	let pkg;
	if (system === 'maven') {
		if (!namespace) return null;
		pkg = `${namespace}:${name}`;
	} else if (system === 'pypi') {
		pkg = name.toLowerCase();
	} else {
		pkg = namespace ? `${namespace}/${name}` : name;
	}
	let version = '';
	if (m[3]) {
		try {
			version = decodeURIComponent(m[3]);
		} catch {
			return null;
		}
	}
	const base = `https://deps.dev/${system}/${encodeURIComponent(pkg)}`;
	return version ? `${base}/${encodeURIComponent(version)}` : base;
}
