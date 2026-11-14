package pkgmeta

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"unicode"
)

// ---------------------------------------------------------------- npm

// npmRegistry reads the package document (GET /{package}) of the npm registry
// API (https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md#getpackage):
// "dist-tags".latest is the release `npm install` picks, "time" maps each
// version to its publish time, and "versions" holds the versions that still
// exist ("time" keeps unpublished ones too). The abbreviated install document
// has no "time", so the full one is read — decoding only these three fields.
type npmRegistry struct {
	base string
	g    *getter
}

func (r *npmRegistry) Ecosystem() string { return NPM }

func (r *npmRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	name := p.Name
	if p.Namespace != "" {
		ns := p.Namespace
		if !strings.HasPrefix(ns, "@") {
			ns = "@" + ns
		}
		// Scoped names are requested with the slash encoded, as the npm CLI does.
		name = url.PathEscape(ns) + "%2f" + url.PathEscape(p.Name)
	} else {
		name = url.PathEscape(name)
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Time     map[string]string `json:"time"`
		Versions map[string]struct {
			Dist struct {
				Integrity string `json:"integrity"` // SRI, usually sha512
				Shasum    string `json:"shasum"`    // sha1 hex
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := r.g.getJSON(ctx, r.base+"/"+name, &doc); err != nil {
		return Package{}, err
	}
	out := Package{Latest: doc.DistTags["latest"]}
	for v, d := range doc.Versions {
		h := map[string][]string{}
		addSRI(h, d.Dist.Integrity)
		addDigest(h, "sha1", d.Dist.Shasum)
		out.Versions = append(out.Versions, Version{Version: v, Published: parseTime(doc.Time[v]), Hashes: nonEmpty(h)})
	}
	return out, nil
}

// ---------------------------------------------------------------- PyPI

// pypiRegistry reads PyPI's JSON API (GET /pypi/<project>/json,
// https://docs.pypi.org/api/json/): info.version is the latest release, and
// releases maps each version to its files, each with upload_time_iso_8601 and
// yanked (PEP 592). A release whose every file is yanked is yanked; one with no
// files can't be installed and is skipped.
type pypiRegistry struct {
	base string
	g    *getter
}

func (r *pypiRegistry) Ecosystem() string { return PyPI }

func (r *pypiRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string            `json:"upload_time_iso_8601"`
			Yanked     bool              `json:"yanked"`
			Digests    map[string]string `json:"digests"` // sha256 (+ md5, blake2b_256)
		} `json:"releases"`
	}
	if err := r.g.getJSON(ctx, r.base+"/"+url.PathEscape(p.Name)+"/json", &doc); err != nil {
		return Package{}, err
	}
	out := Package{Latest: doc.Info.Version}
	for v, files := range doc.Releases {
		if len(files) == 0 {
			continue
		}
		ver := Version{Version: v, Yanked: true}
		h := map[string][]string{}
		for _, f := range files {
			if !f.Yanked {
				ver.Yanked = false
			}
			for alg, d := range f.Digests {
				addDigest(h, alg, d)
			}
			if t := parseTime(f.UploadTime); t != nil && (ver.Published == nil || t.Before(*ver.Published)) {
				ver.Published = t
			}
		}
		ver.Hashes = nonEmpty(h)
		out.Versions = append(out.Versions, ver)
	}
	return out, nil
}

// ---------------------------------------------------------------- Maven

// mavenRegistry reads the artifact-level repository metadata
// (<groupId as path>/<artifactId>/maven-metadata.xml,
// https://maven.apache.org/repositories/metadata.html): versioning/versions
// lists every deployed version and versioning/release the newest non-SNAPSHOT
// one. The metadata carries no per-version dates; Maven Central's search API
// does, but mirrors (Artifactory, Nexus) don't serve it and it is rate-limited,
// so Maven versions have no release date.
type mavenRegistry struct {
	base string
	g    *getter
}

func (r *mavenRegistry) Ecosystem() string { return Maven }

func (r *mavenRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	if p.Namespace == "" {
		return Package{}, fmt.Errorf("%w: maven purl without a group", ErrBadPurl)
	}
	var meta struct {
		Versioning struct {
			Release  string   `xml:"release"`
			Versions []string `xml:"versions>version"`
		} `xml:"versioning"`
	}
	path := strings.ReplaceAll(p.Namespace, ".", "/") + "/" + url.PathEscape(p.Name) + "/maven-metadata.xml"
	err := r.g.get(ctx, r.base+"/"+path, "application/xml", func(body io.Reader) error {
		return xml.NewDecoder(body).Decode(&meta)
	})
	if err != nil {
		return Package{}, err
	}
	out := Package{Latest: meta.Versioning.Release}
	for _, v := range meta.Versioning.Versions {
		if v = strings.TrimSpace(v); v != "" {
			out.Versions = append(out.Versions, Version{Version: v})
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- Go

// goRegistry speaks the GOPROXY protocol (https://go.dev/ref/mod#goproxy-protocol):
// $base/$module/@v/list lists the tagged versions (pseudo-versions excluded)
// and $base/$module/@latest returns {"Version","Time"} of the version `go get`
// would pick. Module paths are case-encoded ('!' + lowercase). Per-version
// times need one .info request each, so only the latest version is dated.
type goRegistry struct {
	base string
	g    *getter
}

func (r *goRegistry) Ecosystem() string { return Golang }

// goEscape is the module-path case encoding of golang.org/x/mod/module.EscapePath.
func goEscape(path string) string {
	var b strings.Builder
	for _, c := range path {
		if unicode.IsUpper(c) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(c))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (r *goRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	base := r.base + "/" + goEscape(p.fullName("/"))
	var out Package
	err := r.g.get(ctx, base+"/@v/list", "text/plain", func(body io.Reader) error {
		data, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if v := strings.TrimSpace(line); v != "" {
				out.Versions = append(out.Versions, Version{Version: v})
			}
		}
		return nil
	})
	if err != nil {
		return Package{}, err
	}
	var latest struct {
		Version string `json:"Version"`
		Time    string `json:"Time"`
	}
	if err := r.g.getJSON(ctx, base+"/@latest", &latest); err != nil {
		if len(out.Versions) == 0 {
			return Package{}, err
		}
		return out, nil // the list alone still orders the versions
	}
	out.Latest = latest.Version
	found := false
	for i := range out.Versions {
		if out.Versions[i].Version == latest.Version {
			out.Versions[i].Published, found = parseTime(latest.Time), true
		}
	}
	if !found && latest.Version != "" {
		out.Versions = append(out.Versions, Version{Version: latest.Version, Published: parseTime(latest.Time)})
	}
	return out, nil
}

// ---------------------------------------------------------------- Cargo

// cargoRegistry reads crates.io's crate endpoint (GET /api/v1/crates/{name},
// schema https://crates.io/api/openapi.json): crate.max_stable_version is the
// highest non-prerelease version, and versions[] carries num, created_at and
// yanked. crates.io rejects requests without a descriptive User-Agent
// (https://crates.io/data-access#api).
type cargoRegistry struct {
	base string
	g    *getter
}

func (r *cargoRegistry) Ecosystem() string { return Cargo }

func (r *cargoRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	var doc struct {
		Crate struct {
			MaxStableVersion *string `json:"max_stable_version"`
		} `json:"crate"`
		Versions []struct {
			Num       string `json:"num"`
			CreatedAt string `json:"created_at"`
			Yanked    bool   `json:"yanked"`
			Checksum  string `json:"checksum"` // sha256 of the .crate
		} `json:"versions"`
	}
	if err := r.g.getJSON(ctx, r.base+"/crates/"+url.PathEscape(p.Name), &doc); err != nil {
		return Package{}, err
	}
	var out Package
	if doc.Crate.MaxStableVersion != nil {
		out.Latest = *doc.Crate.MaxStableVersion
	}
	for _, v := range doc.Versions {
		h := map[string][]string{}
		addDigest(h, "sha256", v.Checksum)
		out.Versions = append(out.Versions, Version{Version: v.Num, Published: parseTime(v.CreatedAt), Yanked: v.Yanked, Hashes: nonEmpty(h)})
	}
	return out, nil
}

// ---------------------------------------------------------------- NuGet

// nugetRegistry speaks the NuGet V3 protocol, so any V3 feed (nuget.org,
// Artifactory, Nexus, Azure Artifacts) works from its service index
// (https://learn.microsoft.com/en-us/nuget/api/service-index). It reads the
// package's registration index (RegistrationsBaseUrl/3.6.0, which includes
// SemVer 2.0 packages; https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource):
// pages are inlined for smaller packages and fetched one request each
// otherwise; each catalogEntry has version, listed (false = unlisted, treated
// as yanked) and published (unlisted versions report the year 1900). A feed
// without registrations falls back to the flat container's version list
// (PackageBaseAddress/3.0.0 {id-lower}/index.json), undated.
type nugetRegistry struct {
	index string
	g     *getter

	mu       sync.Mutex
	resolved bool
	regBase  string
	flatBase string
}

func (r *nugetRegistry) Ecosystem() string { return NuGet }

// maxNugetPages bounds the registration pages fetched for one package.
const maxNugetPages = 50

func (r *nugetRegistry) resources(ctx context.Context) (regBase, flatBase string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resolved {
		return r.regBase, r.flatBase, nil
	}
	var idx struct {
		Resources []struct {
			ID   string `json:"@id"`
			Type string `json:"@type"`
		} `json:"resources"`
	}
	if err := r.g.getJSON(ctx, r.index, &idx); err != nil {
		return "", "", fmt.Errorf("nuget service index: %w", err)
	}
	rank := map[string]int{"RegistrationsBaseUrl/3.6.0": 3, "RegistrationsBaseUrl/3.4.0": 2, "RegistrationsBaseUrl": 1}
	best := 0
	for _, res := range idx.Resources {
		if n := rank[res.Type]; n > best {
			best, r.regBase = n, res.ID
		}
		if res.Type == "PackageBaseAddress/3.0.0" {
			r.flatBase = res.ID
		}
	}
	if r.regBase == "" && r.flatBase == "" {
		return "", "", errors.New("nuget service index advertises neither registrations nor a package base address")
	}
	r.resolved = true
	return r.regBase, r.flatBase, nil
}

type nugetLeaf struct {
	CatalogEntry struct {
		Version   string `json:"version"`
		Listed    *bool  `json:"listed"`
		Published string `json:"published"`
	} `json:"catalogEntry"`
}

type nugetPage struct {
	ID    string      `json:"@id"`
	Items []nugetLeaf `json:"items"`
}

func (r *nugetRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	regBase, flatBase, err := r.resources(ctx)
	if err != nil {
		return Package{}, err
	}
	id := url.PathEscape(strings.ToLower(p.Name))
	var out Package
	if regBase == "" {
		var flat struct {
			Versions []string `json:"versions"`
		}
		if err := r.g.getJSON(ctx, strings.TrimRight(flatBase, "/")+"/"+id+"/index.json", &flat); err != nil {
			return Package{}, err
		}
		for _, v := range flat.Versions {
			out.Versions = append(out.Versions, Version{Version: v})
		}
		return out, nil
	}
	var index struct {
		Items []nugetPage `json:"items"`
	}
	if err := r.g.getJSON(ctx, strings.TrimRight(regBase, "/")+"/"+id+"/index.json", &index); err != nil {
		return Package{}, err
	}
	for i, page := range index.Items {
		if page.Items == nil {
			if i >= maxNugetPages {
				break
			}
			var full nugetPage
			if err := r.g.getJSON(ctx, page.ID, &full); err != nil {
				return Package{}, err
			}
			page = full
		}
		for _, leaf := range page.Items {
			e := leaf.CatalogEntry
			v := Version{Version: e.Version, Yanked: e.Listed != nil && !*e.Listed}
			if t := parseTime(e.Published); t != nil && t.Year() > 1900 {
				v.Published = t
			}
			out.Versions = append(out.Versions, v)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- RubyGems

// gemRegistry reads GET /api/v1/versions/[GEM NAME].json
// (https://guides.rubygems.org/rubygems-org-api/#gem-version-methods): one
// entry per (number, platform) with created_at and prerelease. Yanked versions
// aren't listed. Platform builds of one number collapse to the earliest date.
type gemRegistry struct {
	base string
	g    *getter
}

func (r *gemRegistry) Ecosystem() string { return Gem }

func (r *gemRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	var doc []struct {
		Number    string `json:"number"`
		CreatedAt string `json:"created_at"`
		SHA       string `json:"sha"` // sha256 of the .gem (one per platform build)
	}
	if err := r.g.getJSON(ctx, r.base+"/api/v1/versions/"+url.PathEscape(p.Name)+".json", &doc); err != nil {
		return Package{}, err
	}
	var out Package
	at := map[string]int{}
	for _, d := range doc {
		t := parseTime(d.CreatedAt)
		if i, ok := at[d.Number]; ok {
			if t != nil && (out.Versions[i].Published == nil || t.Before(*out.Versions[i].Published)) {
				out.Versions[i].Published = t
			}
			if out.Versions[i].Hashes == nil {
				out.Versions[i].Hashes = map[string][]string{}
			}
			addDigest(out.Versions[i].Hashes, "sha256", d.SHA)
			out.Versions[i].Hashes = nonEmpty(out.Versions[i].Hashes)
			continue
		}
		at[d.Number] = len(out.Versions)
		h := map[string][]string{}
		addDigest(h, "sha256", d.SHA)
		out.Versions = append(out.Versions, Version{Version: d.Number, Published: t, Hashes: nonEmpty(h)})
	}
	return out, nil
}

// ---------------------------------------------------------------- Composer

// composerRegistry reads Packagist's Composer v2 metadata
// (GET /p2/[vendor]/[package].json, https://packagist.org/apidoc#get-package-data):
// tagged releases only (dev branches live in the separate ~dev file), each with
// version and time. The list is minified — every entry repeats only the keys
// that changed from the previous one, "__unset" removing a key
// (https://github.com/composer/metadata-minifier) — so it is expanded here.
type composerRegistry struct {
	base string
	g    *getter
}

func (r *composerRegistry) Ecosystem() string { return Composer }

func (r *composerRegistry) Fetch(ctx context.Context, p PURL) (Package, error) {
	if p.Namespace == "" {
		return Package{}, fmt.Errorf("%w: composer purl without a vendor", ErrBadPurl)
	}
	name := p.Namespace + "/" + p.Name
	var doc struct {
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := r.g.getJSON(ctx, r.base+"/p2/"+url.PathEscape(p.Namespace)+"/"+url.PathEscape(p.Name)+".json", &doc); err != nil {
		return Package{}, err
	}
	var out Package
	var version, published string
	for _, entry := range doc.Packages[name] {
		version = minifiedField(entry, "version", version)
		published = minifiedField(entry, "time", published)
		if version == "" {
			continue
		}
		out.Versions = append(out.Versions, Version{Version: version, Published: parseTime(published)})
	}
	return out, nil
}

// minifiedField expands one string key of a minified Composer entry: present
// replaces, "__unset" clears, absent inherits.
func minifiedField(entry map[string]json.RawMessage, key, prev string) string {
	raw, ok := entry[key]
	if !ok {
		return prev
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "__unset" {
		return ""
	}
	return s
}

// compile-time interface checks
var (
	_ Registry = (*npmRegistry)(nil)
	_ Registry = (*pypiRegistry)(nil)
	_ Registry = (*mavenRegistry)(nil)
	_ Registry = (*goRegistry)(nil)
	_ Registry = (*cargoRegistry)(nil)
	_ Registry = (*nugetRegistry)(nil)
	_ Registry = (*gemRegistry)(nil)
	_ Registry = (*composerRegistry)(nil)
)
