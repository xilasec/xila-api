// Command gencatalog refreshes the license catalog embedded in package license
// (internal/license/data/catalog.json) from its two upstream sources:
//
//   - the SPDX License List (https://github.com/spdx/license-list-data, CC0-1.0):
//     json/licenses.json and json/exceptions.json;
//   - the ScanCode LicenseDB index (https://scancode-licensedb.aboutcode.org,
//     data CC-BY-4.0, © nexB Inc. and others): each license's category, keyed by
//     its SPDX id (and by the LicenseRef-scancode-* key ScanCode assigns licenses
//     SPDX doesn't list).
//
// Only the fields Xila uses are kept, so the binary stays small. Run it with
// `make licenses` (or `go generate ./internal/license`); it is the only place
// that touches the network — tests read the committed file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	spdxBase    = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/"
	scancodeURL = "https://scancode-licensedb.aboutcode.org/index.json"
)

// catalogFile is the embedded format (mirrored by license.catalogFile).
type catalogFile struct {
	SPDXVersion  string           `json:"spdx_version"`
	SPDXReleased string           `json:"spdx_released"`
	Generated    string           `json:"generated"`
	Licenses     []catalogLicense `json:"licenses"`
	Exceptions   []catalogLicense `json:"exceptions"`
	// Categories maps a license id (SPDX id or LicenseRef-scancode-* key) to
	// its ScanCode category.
	Categories map[string]string `json:"categories"`
}

type catalogLicense struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	OSI        bool   `json:"osi,omitempty"`
	FSF        bool   `json:"fsf,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty"`
}

func main() {
	out := flag.String("o", "data/catalog.json", "output file")
	flag.Parse()

	var lic struct {
		Version  string `json:"licenseListVersion"`
		Released string `json:"releaseDate"`
		Licenses []struct {
			ID         string `json:"licenseId"`
			Name       string `json:"name"`
			OSI        bool   `json:"isOsiApproved"`
			FSF        bool   `json:"isFsfLibre"`
			Deprecated bool   `json:"isDeprecatedLicenseId"`
		} `json:"licenses"`
	}
	var exc struct {
		Exceptions []struct {
			ID         string `json:"licenseExceptionId"`
			Name       string `json:"name"`
			Deprecated bool   `json:"isDeprecatedLicenseId"`
		} `json:"exceptions"`
	}
	var sc []struct {
		Key        string   `json:"license_key"`
		Category   string   `json:"category"`
		SPDX       string   `json:"spdx_license_key"`
		OtherSPDX  []string `json:"other_spdx_license_keys"`
		Deprecated bool     `json:"is_deprecated"`
	}
	for _, src := range []struct {
		url  string
		into any
	}{{spdxBase + "licenses.json", &lic}, {spdxBase + "exceptions.json", &exc}, {scancodeURL, &sc}} {
		if err := fetch(src.url, src.into); err != nil {
			log.Fatal(err)
		}
	}

	f := catalogFile{
		SPDXVersion:  lic.Version,
		SPDXReleased: lic.Released,
		Generated:    time.Now().UTC().Format(time.DateOnly),
		Categories:   map[string]string{},
	}
	for _, l := range lic.Licenses {
		f.Licenses = append(f.Licenses, catalogLicense{ID: l.ID, Name: l.Name, OSI: l.OSI, FSF: l.FSF, Deprecated: l.Deprecated})
	}
	for _, e := range exc.Exceptions {
		f.Exceptions = append(f.Exceptions, catalogLicense{ID: e.ID, Name: e.Name, Deprecated: e.Deprecated})
	}
	sort.Slice(f.Licenses, func(i, j int) bool { return f.Licenses[i].ID < f.Licenses[j].ID })
	sort.Slice(f.Exceptions, func(i, j int) bool { return f.Exceptions[i].ID < f.Exceptions[j].ID })

	// A license's primary SPDX key wins over another entry listing it as an
	// alternative key; deprecated ScanCode entries only fill gaps.
	for pass := range 3 {
		for _, l := range sc {
			if l.Category == "" || (l.Deprecated != (pass == 2)) {
				continue
			}
			keys := []string{l.SPDX}
			if pass == 1 || pass == 2 {
				keys = append(keys, l.OtherSPDX...)
			}
			for _, k := range keys {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				if _, seen := f.Categories[k]; !seen {
					f.Categories[k] = l.Category
				}
			}
		}
	}

	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil { //nolint:gosec // G306: a generated file committed to the repository
		log.Fatal(err)
	}
	fmt.Printf("SPDX %s: %d licenses, %d exceptions; %d ScanCode categories → %s\n",
		f.SPDXVersion, len(f.Licenses), len(f.Exceptions), len(f.Categories), *out)
}

// fetchClient bounds each catalog download; the default client never times out.
var fetchClient = &http.Client{Timeout: 2 * time.Minute}

func fetch(url string, into any) error {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: %s %s", url, resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}
