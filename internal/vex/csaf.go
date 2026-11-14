package vex

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// --- CSAF 2.0 VEX (category csaf_vex) ---
//
// A CSAF VEX document names products by id; the product tree resolves an id
// to what it is. Branches carry products directly; a relationship
// ("default_component_of" …) makes a new product id for "component X as part
// of product Y" — for Xila the component is the product a finding is on, so a
// relationship resolves to its component.

type csafInHelper struct {
	PURL string `json:"purl"`
	CPE  string `json:"cpe"`
}

type csafInProduct struct {
	ProductID string       `json:"product_id"`
	Name      string       `json:"name"`
	Helper    csafInHelper `json:"product_identification_helper"`
}

type csafInBranch struct {
	Product  *csafInProduct `json:"product"`
	Branches []csafInBranch `json:"branches"`
}

type csafInDoc struct {
	Document struct {
		Category string `json:"category"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafInBranch  `json:"branches"`
		FullProductNames []csafInProduct `json:"full_product_names"`
		Relationships    []struct {
			FullProductName  csafInProduct `json:"full_product_name"`
			ProductReference string        `json:"product_reference"`
		} `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE string `json:"cve"`
		IDs []struct {
			Text string `json:"text"`
		} `json:"ids"`
		ProductStatus map[string][]string `json:"product_status"`
		Flags         []struct {
			Label      string   `json:"label"`
			ProductIDs []string `json:"product_ids"`
		} `json:"flags"`
		Threats []struct {
			Category   string   `json:"category"`
			Details    string   `json:"details"`
			ProductIDs []string `json:"product_ids"`
		} `json:"threats"`
		Remediations []struct {
			Details    string   `json:"details"`
			ProductIDs []string `json:"product_ids"`
		} `json:"remediations"`
	} `json:"vulnerabilities"`
}

// csafStatus maps a CSAF product_status list to a VEX status. "recommended"
// isn't a verdict; anything else unknown is dropped, never guessed.
func csafStatus(list string) Status {
	switch list {
	case "known_not_affected":
		return StatusNotAffected
	case "known_affected", "first_affected", "last_affected":
		return StatusAffected
	case "fixed", "first_fixed":
		return StatusFixed
	case "under_investigation":
		return StatusUnderInvestigation
	}
	return ""
}

func parseCSAF(data []byte) ([]Statement, error) {
	var doc csafInDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode csaf: %w", err)
	}
	if !strings.EqualFold(doc.Document.Category, "csaf_vex") {
		return nil, fmt.Errorf("CSAF document category %q is not csaf_vex", doc.Document.Category)
	}

	// Product id → identity: purl, else CPE, else its name.
	products := map[string]csafInProduct{}
	var walk func([]csafInBranch)
	walk = func(bs []csafInBranch) {
		for _, b := range bs {
			if b.Product != nil {
				products[b.Product.ProductID] = *b.Product
			}
			walk(b.Branches)
		}
	}
	walk(doc.ProductTree.Branches)
	for _, p := range doc.ProductTree.FullProductNames {
		products[p.ProductID] = p
	}
	ident := func(p csafInProduct) string {
		switch {
		case p.Helper.PURL != "":
			return p.Helper.PURL
		case p.Helper.CPE != "":
			return p.Helper.CPE
		}
		return p.Name
	}
	resolved := map[string]string{}
	for id, p := range products {
		resolved[id] = ident(p)
	}
	for _, r := range doc.ProductTree.Relationships {
		// The relationship's own helper wins; else the component's identity.
		id := ident(csafInProduct{Helper: r.FullProductName.Helper})
		if id == "" {
			id = resolved[r.ProductReference]
		}
		if id == "" {
			id = r.FullProductName.Name
		}
		resolved[r.FullProductName.ProductID] = id
	}

	var out []Statement
	for _, v := range doc.Vulnerabilities {
		vuln := v.CVE
		if vuln == "" && len(v.IDs) > 0 {
			vuln = v.IDs[0].Text
		}
		if vuln == "" {
			continue
		}
		justification := func(pid string) string {
			for _, f := range v.Flags {
				if slices.Contains(f.ProductIDs, pid) {
					return f.Label
				}
			}
			return ""
		}
		detail := func(pid string, status Status) string {
			if status == StatusNotAffected {
				// The "impact" threat is the profile's impact statement (some
				// publishers put a severity rating there; it is kept as given).
				for _, t := range v.Threats {
					if t.Category == "impact" && slices.Contains(t.ProductIDs, pid) {
						return t.Details
					}
				}
				return ""
			}
			for _, r := range v.Remediations {
				if slices.Contains(r.ProductIDs, pid) {
					return r.Details
				}
			}
			return ""
		}
		// One statement per (product identity, status): CSAF often lists the
		// same component in several product contexts (src and binary rpms).
		seen := map[string]bool{}
		lists := make([]string, 0, len(v.ProductStatus))
		for list := range v.ProductStatus {
			lists = append(lists, list)
		}
		slices.Sort(lists)
		for _, list := range lists {
			status := csafStatus(list)
			if status == "" {
				continue
			}
			for _, pid := range v.ProductStatus[list] {
				product := resolved[pid]
				if product == "" {
					product = pid // not in the tree: the id is all we know
				}
				key := product + "\x00" + string(status)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Statement{VulnID: vuln, Product: product, Status: status,
					Justification: justification(pid), Detail: detail(pid, status), Source: "csaf"})
			}
		}
	}
	return out, nil
}
