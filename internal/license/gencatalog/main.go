// Command gencatalog refreshes the license catalog embedded in package license
// (internal/license/data/catalog.json) from its two upstream sources:
//
//   - the SPDX License List (https://github.com/spdx/license-list-data, CC0-1.0):
//     json/licenses.json and json/exceptions.json;
//   - the ScanCode LicenseDB index (https://scancode-licensedb.aboutcode.org,
//     data CC-BY-4.0, © nexB Inc. and others): each license's category, keyed by
//     its SPDX id (and by the LicenseRef-scancode-* key ScanCode assigns licenses
//     SPDX doesn't list);
//   - choosealicense.com (https://github.com/github/choosealicense.com, MIT,
//     © GitHub, Inc. and contributors): the permissions, conditions and
//     limitations of the licenses it describes, from each _licenses/*.txt
//     front matter.
//
// Only the fields Xila uses are kept, so the binary stays small. Run it with
// `make licenses` (or `go generate ./internal/license`); it is the only place
// that touches the network — tests read the committed file.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// spdxRepo's latest release is read, not main: main carries unreleased
	// changes and reports a commit hash as its version.
	spdxRepo    = "https://raw.githubusercontent.com/spdx/license-list-data/"
	spdxLatest  = "https://api.github.com/repos/spdx/license-list-data/releases/latest"
	scancodeURL = "https://scancode-licensedb.aboutcode.org/index.json"
	// chooseALicenseDir lists the license files (one GitHub API call; the
	// files themselves come from raw.githubusercontent.com).
	chooseALicenseDir = "https://api.github.com/repos/github/choosealicense.com/contents/_licenses"
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
	// Terms maps an SPDX id to what the license permits, requires and
	// limits (choosealicense.com's tags, e.g. commercial-use, include-copyright,
	// liability).
	Terms map[string]catalogTerms `json:"terms"`
}

type catalogTerms struct {
	Permissions []string `json:"permissions" yaml:"permissions"`
	Conditions  []string `json:"conditions" yaml:"conditions"`
	Limitations []string `json:"limitations" yaml:"limitations"`
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
	var release struct {
		Tag string `json:"tag_name"`
	}
	if err := fetch(spdxLatest, &release); err != nil || release.Tag == "" {
		log.Fatalf("latest SPDX License List release: %v (tag %q)", err, release.Tag)
	}
	spdxBase := spdxRepo + release.Tag + "/json/"
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

	terms, err := chooseALicenseTerms()
	if err != nil {
		log.Fatal(err)
	}
	f.Terms = map[string]catalogTerms{}
	ids := map[string]bool{}
	for _, l := range f.Licenses {
		ids[l.ID] = true
	}
	// choosealicense.com names some licenses by their deprecated SPDX id
	// (GPL-3.0); the text and terms are those of both -only and -or-later.
	for id, t := range terms {
		for _, k := range []string{id, id + "-only", id + "-or-later"} {
			if ids[k] {
				f.Terms[k] = t
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
	fmt.Printf("SPDX %s: %d licenses, %d exceptions; %d ScanCode categories; %d license terms → %s\n",
		f.SPDXVersion, len(f.Licenses), len(f.Exceptions), len(f.Categories), len(f.Terms), *out)
}

// chooseALicenseTerms reads every choosealicense.com license file's front
// matter, keyed by its spdx-id.
func chooseALicenseTerms() (map[string]catalogTerms, error) {
	var files []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
	}
	if err := fetch(chooseALicenseDir, &files); err != nil {
		return nil, err
	}
	out := map[string]catalogTerms{}
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".txt") {
			continue
		}
		body, err := fetchBytes(f.DownloadURL)
		if err != nil {
			return nil, err
		}
		front, ok := frontMatter(body)
		if !ok {
			return nil, fmt.Errorf("%s: no front matter", f.Name)
		}
		var meta struct {
			SPDXID       string `yaml:"spdx-id"`
			catalogTerms `yaml:",inline"`
		}
		if err := yaml.Unmarshal(front, &meta); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if meta.SPDXID == "" {
			continue
		}
		out[meta.SPDXID] = meta.catalogTerms
	}
	if len(out) == 0 {
		return nil, errors.New("choosealicense.com: no license terms read")
	}
	return out, nil
}

// frontMatter is the YAML between a file's leading "---" lines.
func frontMatter(b []byte) ([]byte, bool) {
	rest, ok := bytes.CutPrefix(b, []byte("---\n"))
	if !ok {
		return nil, false
	}
	front, _, ok := bytes.Cut(rest, []byte("\n---"))
	return front, ok
}

// fetchClient bounds each catalog download; the default client never times out.
var fetchClient = &http.Client{Timeout: 2 * time.Minute}

func fetchBytes(url string) ([]byte, error) {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

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
