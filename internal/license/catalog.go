package license

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"sync"
)

// The license catalog embedded in the binary, refreshed by `make licenses`
// (internal/license/gencatalog). It combines:
//
//   - the SPDX License List (https://github.com/spdx/license-list-data), released
//     under CC0-1.0 — every license and exception id with its name, OSI / FSF
//     status and deprecation flag (the list version is CatalogVersion());
//   - the license categories of the ScanCode LicenseDB
//     (https://scancode-licensedb.aboutcode.org), © nexB Inc. and others,
//     licensed CC-BY-4.0 — keyed by SPDX id, plus the LicenseRef-scancode-* keys
//     ScanCode assigns licenses the SPDX list doesn't have.
//
//go:generate go run ./gencatalog -o data/catalog.json
//go:embed data/catalog.json
var catalogJSON []byte

// ScanCode LicenseDB categories (https://scancode-licensedb.aboutcode.org).
// Info.Category is one of these, or "" when unknown.
const (
	CategoryPermissive      = "Permissive"
	CategoryCopyleft        = "Copyleft"
	CategoryCopyleftLimited = "Copyleft Limited"
	CategoryPublicDomain    = "Public Domain"
	CategoryProprietaryFree = "Proprietary Free"
	CategoryCommercial      = "Commercial"
	CategoryFreeRestricted  = "Free Restricted"
	CategorySourceAvailable = "Source-available"
	CategoryPatentLicense   = "Patent License"
	CategoryUnstated        = "Unstated License"
	CategoryCLA             = "CLA"
	CategoryNonCommercial   = "Non-Commercial"
)

// categories is every ScanCode category, in display order.
var categories = []string{
	CategoryPermissive, CategoryPublicDomain, CategoryCopyleftLimited, CategoryCopyleft,
	CategoryFreeRestricted, CategoryProprietaryFree, CategorySourceAvailable,
	CategoryNonCommercial, CategoryCommercial, CategoryPatentLicense, CategoryCLA, CategoryUnstated,
}

// Categories returns every ScanCode license category.
func Categories() []string { return slices.Clone(categories) }

// CanonicalCategory resolves a category case-insensitively; ok=false when it
// isn't one of Categories().
func CanonicalCategory(c string) (string, bool) {
	for _, k := range categories {
		if strings.EqualFold(k, strings.TrimSpace(c)) {
			return k, true
		}
	}
	return "", false
}

// Info describes one license of the catalog.
type Info struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OSIApproved bool   `json:"osi_approved"`
	FSFLibre    bool   `json:"fsf_libre"`
	Deprecated  bool   `json:"deprecated"`
	// Category is the ScanCode LicenseDB category, "" when ScanCode has none.
	Category string `json:"category"`
}

// catalogFile mirrors gencatalog's output.
type catalogFile struct {
	SPDXVersion  string `json:"spdx_version"`
	SPDXReleased string `json:"spdx_released"`
	Licenses     []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		OSI        bool   `json:"osi"`
		FSF        bool   `json:"fsf"`
		Deprecated bool   `json:"deprecated"`
	} `json:"licenses"`
	Exceptions []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Deprecated bool   `json:"deprecated"`
	} `json:"exceptions"`
	Categories map[string]string `json:"categories"`
}

// catalog is the decoded, indexed catalog.
type catalog struct {
	version    string
	licenses   []Info          // the SPDX list, sorted by id
	byLower    map[string]Info // SPDX licenses + LicenseRef-scancode-* keys
	exceptions map[string]Info // lower-case exception id → exception
	byName     map[string]string
	// members is every catalog id (SPDX and LicenseRef-scancode-*) per category.
	members map[string][]string
}

var loadCatalog = sync.OnceValue(func() *catalog {
	var f catalogFile
	if err := json.Unmarshal(catalogJSON, &f); err != nil {
		panic("license: embedded catalog is corrupt: " + err.Error())
	}
	c := &catalog{
		version:    f.SPDXVersion,
		byLower:    make(map[string]Info, len(f.Licenses)+len(f.Categories)),
		exceptions: make(map[string]Info, len(f.Exceptions)),
		byName:     make(map[string]string, len(f.Licenses)),
		members:    map[string][]string{},
	}
	for _, l := range f.Licenses {
		info := Info{ID: l.ID, Name: l.Name, OSIApproved: l.OSI, FSFLibre: l.FSF, Deprecated: l.Deprecated, Category: f.Categories[l.ID]}
		c.licenses = append(c.licenses, info)
		c.byLower[strings.ToLower(l.ID)] = info
		// A full name names one license unambiguously unless a deprecated id
		// shares it with its replacement; the current id wins.
		key := aliasKey(l.Name)
		if prev, dup := c.byName[key]; !dup || c.byLower[strings.ToLower(prev)].Deprecated {
			c.byName[key] = l.ID
		}
	}
	slices.SortFunc(c.licenses, func(a, b Info) int { return strings.Compare(a.ID, b.ID) })
	for _, e := range f.Exceptions {
		c.exceptions[strings.ToLower(e.ID)] = Info{ID: e.ID, Name: e.Name, Deprecated: e.Deprecated, Category: f.Categories[e.ID]}
	}
	for id, cat := range f.Categories {
		if _, isException := c.exceptions[strings.ToLower(id)]; isException {
			continue
		}
		if strings.HasPrefix(id, "LicenseRef-") {
			c.byLower[strings.ToLower(id)] = Info{ID: id, Category: cat}
		} else if _, inSPDX := c.byLower[strings.ToLower(id)]; !inSPDX {
			continue // an id ScanCode knows but the SPDX list doesn't (yet)
		}
		c.members[cat] = append(c.members[cat], id)
	}
	for _, ids := range c.members {
		slices.Sort(ids)
	}
	return c
})

// CatalogVersion is the version of the embedded SPDX License List.
func CatalogVersion() string { return loadCatalog().version }

// Lookup finds a license by id, case-insensitively: any SPDX License List id
// (deprecated ones included, flagged) or a ScanCode LicenseRef-scancode-* key.
// The returned Info carries the canonical-case id.
func Lookup(id string) (Info, bool) {
	info, ok := loadCatalog().byLower[strings.ToLower(strings.TrimSpace(id))]
	return info, ok
}

// LookupException finds an SPDX license exception (the right side of WITH) by
// id, case-insensitively.
func LookupException(id string) (Info, bool) {
	info, ok := loadCatalog().exceptions[strings.ToLower(strings.TrimSpace(id))]
	return info, ok
}

// CategoryMembers returns every catalog id in a ScanCode category (SPDX ids,
// deprecated ones included, plus LicenseRef-scancode-* keys), sorted; nil for
// an unknown category. The category is matched case-insensitively.
func CategoryMembers(category string) []string {
	cat, ok := CanonicalCategory(category)
	if !ok {
		return nil
	}
	return slices.Clone(loadCatalog().members[cat])
}

// CatalogFilter narrows Search. Zero fields are ignored.
type CatalogFilter struct {
	Query      string // case-insensitive substring of the id or name
	Category   string // exact ScanCode category (case-insensitive)
	OSI        *bool
	Deprecated *bool
}

// Search lists the SPDX License List entries matching f, sorted by id.
func Search(f CatalogFilter) []Info {
	q := strings.ToLower(strings.TrimSpace(f.Query))
	out := []Info{}
	for _, l := range loadCatalog().licenses {
		switch {
		case q != "" && !strings.Contains(strings.ToLower(l.ID), q) && !strings.Contains(strings.ToLower(l.Name), q):
		case f.Category != "" && !strings.EqualFold(l.Category, f.Category):
		case f.OSI != nil && l.OSIApproved != *f.OSI:
		case f.Deprecated != nil && l.Deprecated != *f.Deprecated:
		default:
			out = append(out, l)
		}
	}
	return out
}
