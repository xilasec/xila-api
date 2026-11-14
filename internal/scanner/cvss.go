package scanner

import (
	"math"
	"strings"
)

// cvss3BaseScore computes the CVSS v3.0/v3.1 base score of a vector string
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8), using the
// specification's formula and v3.1 round-up. Several advisory databases
// (RustSec, DefectDojo exports) carry only the vector; the score is fully
// determined by it, so deriving it is not guessing. ok is false for anything
// that is not a complete v3 base vector — including v2 and v4 vectors, whose
// scoring is different.
func cvss3BaseScore(vector string) (score float64, ok bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || (parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, found := strings.Cut(p, ":")
		if !found {
			return 0, false
		}
		m[k] = v
	}

	weight := func(metric string, table map[string]float64) (float64, bool) {
		w, ok := table[m[metric]]
		return w, ok
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	ui, ok3 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok4 := weight("C", cia)
	i, ok5 := weight("I", cia)
	a, ok6 := weight("A", cia)
	scope := m["S"]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || (scope != "U" && scope != "C") {
		return 0, false
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := weight("PR", prTable)
	if !ok {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	if scope == "C" {
		return cvssRoundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return cvssRoundUp(math.Min(impact+exploitability, 10)), true
}

// cvssRoundUp is the CVSS v3.1 Roundup: the smallest one-decimal number >= x,
// computed on integers so floating-point noise can't push 4.0 to 4.1.
func cvssRoundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
