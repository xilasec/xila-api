package sbom

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// --- ScanCode.io project results (the JSON a project's "results" download
// or `scanpipe output --format json` writes; the subset we consume) ---
//
// A ScanCode.io project lists the packages it discovered and the dependencies
// their manifests and lockfiles declare. A dependency names the package that
// declares it (for_package_uid) and, once resolved, the package it resolved to
// (resolved_to_package_uid) — together the dependency graph. A pinned
// dependency nothing resolved (a requirements.txt pin) is inventory too; an
// unpinned, unresolved one ("pytest", no version) is only a declaration and is
// skipped.

type scancodeDoc struct {
	Headers []struct {
		ToolName    string `json:"tool_name"`
		ToolVersion string `json:"tool_version"`
		InputSource []struct {
			Filename string `json:"filename"`
		} `json:"input_sources"`
	} `json:"headers"`
	Packages     []scancodePackage    `json:"packages"`
	Dependencies []scancodeDependency `json:"dependencies"`
}

type scancodePackage struct {
	Purl                          string   `json:"purl"`
	Type                          string   `json:"type"`
	Namespace                     string   `json:"namespace"`
	Name                          string   `json:"name"`
	Version                       string   `json:"version"`
	PackageUID                    string   `json:"package_uid"`
	DeclaredLicenseExpressionSPDX string   `json:"declared_license_expression_spdx"`
	OtherLicenseExpressionSPDX    string   `json:"other_license_expression_spdx"`
	MD5                           string   `json:"md5"`
	SHA1                          string   `json:"sha1"`
	SHA256                        string   `json:"sha256"`
	SHA512                        string   `json:"sha512"`
	DatafilePaths                 []string `json:"datafile_paths"`
}

type scancodeDependency struct {
	Purl                 string `json:"purl"`
	Scope                string `json:"scope"`
	IsRuntime            *bool  `json:"is_runtime"`
	IsOptional           *bool  `json:"is_optional"`
	DependencyUID        string `json:"dependency_uid"`
	ForPackageUID        string `json:"for_package_uid"`
	ResolvedToPackageUID string `json:"resolved_to_package_uid"`
	DatafilePath         string `json:"datafile_path"`
}

// scancodeRoot is the synthetic graph root when a project has several
// top-level packages (or dependencies declared outside any package).
const scancodeRoot = "scancodeio:project"

// isScanCodeIO reports whether the probe's headers name ScanCode.io.
func isScanCodeIO(raw []byte) bool {
	var probe struct {
		Headers []struct {
			ToolName string `json:"tool_name"`
		} `json:"headers"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	return len(probe.Headers) > 0 && strings.EqualFold(probe.Headers[0].ToolName, "scanpipe")
}

// parseScanCodeIO decodes a ScanCode.io project's JSON results.
func parseScanCodeIO(r io.Reader) (Document, error) {
	var doc scancodeDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode scancode.io results: %w", err)
	}
	if len(doc.Headers) == 0 {
		return Document{}, fmt.Errorf("not a ScanCode.io project (missing headers)")
	}
	out := Document{
		Format:      "ScanCode.io",
		SpecVersion: doc.Headers[0].ToolVersion,
		Components:  []Component{},
	}
	if in := doc.Headers[0].InputSource; len(in) > 0 {
		out.Artifact = in[0].Filename
	}

	// ScanCode.io reports a package once per manifest it was found in (a
	// wheel and its METADATA): one component per purl, the others aliased.
	ref := map[string]string{} // package_uid / dependency_uid → component BomRef
	byPurl := map[string]int{}
	add := func(c Component, uid string) {
		if c.Purl != "" {
			if i, ok := byPurl[c.Purl]; ok {
				ref[uid] = out.Components[i].BomRef
				return
			}
			byPurl[c.Purl] = len(out.Components)
		}
		ref[uid] = c.BomRef
		out.Components = append(out.Components, c)
	}
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		c := Component{
			BomRef:  cmp.Or(p.PackageUID, p.Purl),
			Type:    "library",
			Group:   p.Namespace,
			Name:    p.Name,
			Version: p.Version,
			Purl:    p.Purl,
			Hashes:  map[string]string{},
		}
		if lic := cmp.Or(p.DeclaredLicenseExpressionSPDX, p.OtherLicenseExpressionSPDX); lic != "" {
			c.License, c.LicenseTerms = lic, []string{lic}
		}
		for alg, v := range map[string]string{"MD5": p.MD5, "SHA-1": p.SHA1, "SHA-256": p.SHA256, "SHA-512": p.SHA512} {
			if v != "" {
				c.Hashes[alg] = v
			}
		}
		if len(p.DatafilePaths) > 0 {
			c.FilePath = p.DatafilePaths[0]
		}
		add(c, cmp.Or(p.PackageUID, p.Purl))
	}
	// Pinned dependencies no package stands for.
	for _, d := range doc.Dependencies {
		if d.ResolvedToPackageUID != "" || d.DependencyUID == "" {
			continue
		}
		name, version, group, ok := purlParts(d.Purl)
		if !ok || version == "" {
			continue
		}
		add(Component{BomRef: d.DependencyUID, Type: "library", Group: group, Name: name, Version: version,
			Purl: d.Purl, FilePath: d.DatafilePath, Hashes: map[string]string{}}, d.DependencyUID)
	}

	// Edges: declaring package → resolved package (or the pinned dependency).
	var edges []Edge
	hasParent := map[string]bool{}
	scopes := map[string]domain.DepScope{}
	var orphans []string
	for _, d := range doc.Dependencies {
		child := ref[cmp.Or(d.ResolvedToPackageUID, d.DependencyUID)]
		if child == "" {
			continue
		}
		if s := scancodeScope(d); s != domain.DepScopeUnknown {
			// A package that ships through any declaration ships.
			if prev, ok := scopes[child]; !ok || prev != domain.DepScopeRuntime {
				scopes[child] = s
			}
		}
		parent := ref[d.ForPackageUID]
		if parent == "" {
			orphans = append(orphans, child)
			hasParent[child] = true
			continue
		}
		if parent == child {
			continue
		}
		e := Edge{Parent: parent, Child: child}
		if !slices.Contains(edges, e) {
			edges = append(edges, e)
		}
		hasParent[child] = true
	}

	// Root: the single top-level package (the project's own manifest), else
	// a synthetic root over every top-level package and orphan dependency.
	var tops []string
	for _, c := range out.Components {
		if !hasParent[c.BomRef] {
			tops = append(tops, c.BomRef)
		}
	}
	switch {
	case len(edges) == 0 && len(orphans) == 0:
		// No graph: reachability stays unknown.
	case len(tops) == 1 && len(orphans) == 0:
		out.RootRef = tops[0]
	default:
		out.RootRef = scancodeRoot
		for _, t := range append(tops, orphans...) {
			if e := (Edge{Parent: scancodeRoot, Child: t}); !slices.Contains(edges, e) {
				edges = append(edges, e)
			}
		}
	}
	out.Edges = edges

	depths := graphDepths(out.RootRef, edges)
	for i := range out.Components {
		c := &out.Components[i]
		c.Scope = scopes[c.BomRef]
		if d, ok := depths[c.BomRef]; ok {
			direct := d == 1
			c.Direct, c.Depth = &direct, &d
		}
	}
	return out, nil
}

// scancodeScope: a non-runtime dependency (tests, devDependencies) never
// ships; an optional one only with a feature enabled.
func scancodeScope(d scancodeDependency) domain.DepScope {
	switch {
	case d.IsRuntime != nil && !*d.IsRuntime:
		return domain.DepScopeDev
	case d.IsOptional != nil && *d.IsOptional:
		return domain.DepScopeOptional
	case d.IsRuntime != nil:
		return domain.DepScopeRuntime
	}
	return domain.DepScopeUnknown
}

// graphDepths is each node's shortest distance from root (root itself absent).
func graphDepths(root string, edges []Edge) map[string]int {
	if root == "" {
		return nil
	}
	children := map[string][]string{}
	for _, e := range edges {
		children[e.Parent] = append(children[e.Parent], e.Child)
	}
	depths := map[string]int{}
	seen := map[string]bool{root: true}
	queue := []string{root}
	for depth := 1; len(queue) > 0; depth++ {
		var next []string
		for _, id := range queue {
			for _, c := range children[id] {
				if !seen[c] {
					seen[c] = true
					depths[c] = depth
					next = append(next, c)
				}
			}
		}
		queue = next
	}
	return depths
}

// purlParts splits "pkg:type/ns/name@version?q#s" into name, version and
// namespace (unescaping is unnecessary for display here).
func purlParts(p string) (name, version, group string, ok bool) {
	rest, found := strings.CutPrefix(p, "pkg:")
	if !found {
		return "", "", "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	_, path, found := strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	if i := strings.LastIndexByte(path, '@'); i > 0 && path[i-1] != '/' {
		version, path = path[i+1:], path[:i]
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		group, path = path[:i], path[i+1:]
	}
	return path, version, group, path != ""
}
