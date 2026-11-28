package domain

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Weights are the factors of a finding's priority. A project can override
// them (projects.priority_weights, M12 12.15); every field it leaves out keeps
// its default. The shape of the formula stays fixed, and Validate keeps the
// invariants that make it trustworthy: discounts only discount, uplifts only
// raise, severities keep their order, and an exploited critical in the most
// discounted place still outranks a quiet medium in the least discounted one.
type Weights struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
	Info     float64 `json:"info"`
	// KEV is the multiplier of a finding on a KEV catalog (the ceiling of
	// the exploitability factor).
	KEV float64 `json:"kev"`
	// EPSSSlope scales EPSS: the factor is 1 + slope × p.
	EPSSSlope float64 `json:"epss_slope"`
	// Weaponized / PoC are the floors a known exploit sets.
	Weaponized float64 `json:"weaponized"`
	PoC        float64 `json:"poc"`
	// Transitive / Dev / Optional are the reachability discounts.
	Transitive float64 `json:"transitive"`
	Dev        float64 `json:"dev"`
	Optional   float64 `json:"optional"`
	// Internet / Isolated are the exposure factors (internal and unknown are 1).
	Internet float64 `json:"internet"`
	Isolated float64 `json:"isolated"`
}

// DefaultWeights are the factors when a project sets none (see Priority).
var DefaultWeights = Weights{
	Critical: 15, High: 7, Medium: 3, Low: 1, Info: 0,
	KEV: 3, EPSSSlope: 2, Weaponized: 2.5, PoC: 1.5,
	Transitive: 0.8, Dev: 0.25, Optional: 0.5,
	Internet: 1.25, Isolated: 0.75,
}

// WeightsFromJSON reads a stored override (nil or empty = the defaults);
// fields it leaves out keep their default. A value that no longer validates
// falls back to the defaults as a whole rather than computing nonsense.
func WeightsFromJSON(raw []byte) Weights {
	w := DefaultWeights
	if len(raw) == 0 || string(raw) == "null" {
		return w
	}
	if err := json.Unmarshal(raw, &w); err != nil || w.Validate() != nil {
		return DefaultWeights
	}
	return w
}

// Validate checks the invariants an override must keep.
func (w Weights) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !(w.Critical >= w.High && w.High >= w.Medium && w.Medium >= w.Low && w.Low >= w.Info && w.Info >= 0) {
		bad("severity weights must keep their order: critical ≥ high ≥ medium ≥ low ≥ info ≥ 0")
	}
	if w.Critical <= 0 || w.Critical > 1000 {
		bad("critical must be above 0 and at most 1000")
	}
	if w.KEV < 1 || w.KEV > 10 {
		bad("kev must be between 1 and 10 (exploitation only raises a priority)")
	}
	if w.EPSSSlope < 0 || w.EPSSSlope > 10 {
		bad("epss_slope must be between 0 and 10")
	}
	if !(1 <= w.PoC && w.PoC <= w.Weaponized && w.Weaponized <= w.KEV) {
		bad("exploit floors must keep 1 ≤ poc ≤ weaponized ≤ kev")
	}
	for name, v := range map[string]float64{"transitive": w.Transitive, "dev": w.Dev, "optional": w.Optional, "isolated": w.Isolated} {
		if v <= 0 || v > 1 {
			bad("%s must be above 0 and at most 1 (a discount never raises, never zeroes)", name)
		}
	}
	if w.Internet < 1 || w.Internet > 3 {
		bad("internet must be between 1 and 3")
	}
	if len(errs) == 0 {
		// Discount, never bury: the most discounted exploited critical still
		// outranks the least discounted quiet medium.
		direct := true
		buried := w.Priority(SeverityCritical, Exploitability{KEV: true},
			Reachability{Direct: new(bool), Scope: DepScopeDev}, ExposureIsolated)
		quiet := w.Priority(SeverityMedium, Exploitability{},
			Reachability{Direct: &direct, Scope: DepScopeRuntime}, ExposureInternet)
		if buried <= quiet {
			bad("an exploited critical in a transitive dev dependency on an isolated asset (%.4g) must still outrank a quiet medium on an internet-facing asset (%.4g)", buried, quiet)
		}
	}
	return errors.Join(errs...)
}

// SeverityWeight is a severity's base weight under w.
func (w Weights) SeverityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return w.Critical
	case SeverityHigh:
		return w.High
	case SeverityMedium:
		return w.Medium
	case SeverityLow:
		return w.Low
	}
	return w.Info
}

// Exploitability is x's factor under w (see Exploitability.Multiplier).
func (w Weights) Exploitability(x Exploitability) float64 {
	if x.KEV || x.Malicious {
		return w.KEV
	}
	m := 1.0 + w.EPSSSlope*x.EPSS
	switch x.Maturity {
	case ExploitWeaponized:
		m = max(m, w.Weaponized)
	case ExploitPoC:
		m = max(m, w.PoC)
	}
	return m
}

// Reachability is r's factor under w (see Reachability.Multiplier).
func (w Weights) Reachability(r Reachability) float64 {
	m := 1.0
	if r.Direct != nil && !*r.Direct {
		m = w.Transitive
	}
	switch r.Scope {
	case DepScopeDev:
		m *= w.Dev
	case DepScopeOptional:
		m *= w.Optional
	}
	return m
}

// Exposure is e's factor under w (see Exposure.Multiplier).
func (w Weights) Exposure(e Exposure) float64 {
	switch e {
	case ExposureInternet:
		return w.Internet
	case ExposureIsolated:
		return w.Isolated
	}
	return 1.0
}

// Priority is the priority formula under w. The zero Weights (nothing
// loaded) means the defaults, never a priority of 0.
//
// A malicious package is never discounted: it runs on every machine that
// installs it (install scripts run for dev and transitive dependencies too),
// whether or not that machine is reachable from outside. An exposure uplift
// still applies.
func (w Weights) Priority(sev Severity, x Exploitability, reach Reachability, exp Exposure) float64 {
	if w == (Weights{}) {
		w = DefaultWeights
	}
	if x.Malicious {
		return w.SeverityWeight(sev) * w.Exploitability(x) * max(1, w.Exposure(exp))
	}
	return w.SeverityWeight(sev) * w.Exploitability(x) * w.Reachability(reach) * w.Exposure(exp)
}
