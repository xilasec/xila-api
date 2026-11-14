package psirt

import (
	"errors"
	"math"
	"strings"
)

// cvss3 is a parsed CVSS v3.0 / v3.1 base vector with its base score — CSAF's
// cvss_v3 object needs the score and severity next to the vector.
type cvss3 struct {
	Version  string
	Vector   string
	Score    float64
	Severity string // NONE, LOW, MEDIUM, HIGH, CRITICAL
}

var errCVSS = errors.New("cvss_vector must be a complete CVSS v3.0 or v3.1 base vector (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")

// parseCVSS3 parses a base vector and computes its score per the CVSS v3.1
// specification §7 (v3.0 uses the same base equations; only its rounding
// helper differs in floating-point edge cases).
func parseCVSS3(vector string) (cvss3, error) {
	vector = strings.TrimSpace(vector)
	parts := strings.Split(vector, "/")
	if len(parts) < 9 {
		return cvss3{}, errCVSS
	}
	var version string
	switch parts[0] {
	case "CVSS:3.0":
		version = "3.0"
	case "CVSS:3.1":
		version = "3.1"
	default:
		return cvss3{}, errCVSS
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return cvss3{}, errCVSS
		}
		if _, dup := m[k]; dup {
			return cvss3{}, errCVSS
		}
		m[k] = v
	}
	weight := func(metric string, table map[string]float64) (float64, bool) {
		w, ok := table[m[metric]]
		return w, ok
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return cvss3{}, errCVSS
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prw, ok3 := weight("PR", pr)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", cia)
	i, ok6 := weight("I", cia)
	a, ok7 := weight("A", cia)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return cvss3{}, errCVSS
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * prw * ui
	var score float64
	switch {
	case impact <= 0:
		score = 0
	case scope == "U":
		score = roundup(math.Min(impact+exploitability, 10))
	default:
		score = roundup(math.Min(1.08*(impact+exploitability), 10))
	}
	return cvss3{Version: version, Vector: vector, Score: score, Severity: cvssSeverity(score)}, nil
}

// roundup is CVSS v3.1's Roundup: the smallest one-decimal number >= x,
// computed on integers to avoid floating-point surprises.
func roundup(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

func cvssSeverity(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	}
	return "CRITICAL"
}
