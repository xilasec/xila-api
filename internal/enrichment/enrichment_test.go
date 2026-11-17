package enrichment

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
)

func TestPriority(t *testing.T) {
	direct, transitive := true, false
	runtimeDirect := domain.Reachability{Direct: &direct, Scope: domain.DepScopeRuntime}
	unknown := domain.Reachability{} // no SBOM graph: never discounted

	cases := []struct {
		name  string
		sev   domain.Severity
		epss  float64
		kev   bool
		reach domain.Reachability
		want  float64
	}{
		{"critical + KEV", domain.SeverityCritical, 0, true, runtimeDirect, 45},  // 15 × 3 × 1
		{"critical quiet", domain.SeverityCritical, 0, false, runtimeDirect, 15}, // 15 × 1 × 1
		{"critical, EPSS 1.0", domain.SeverityCritical, 1, false, runtimeDirect, 45},
		{"medium + KEV", domain.SeverityMedium, 0, true, runtimeDirect, 9},
		{"low, EPSS 0.5", domain.SeverityLow, 0.5, false, runtimeDirect, 2},
		{"high quiet", domain.SeverityHigh, 0, false, runtimeDirect, 7},
		{"info is never a priority", domain.SeverityInfo, 0.9, true, runtimeDirect, 0},

		// Unknown reachability must never discount — an SBOM that carries no
		// dependency graph cannot be allowed to quietly demote real findings.
		{"no SBOM data", domain.SeverityCritical, 0, true, unknown, 45},

		// The noise: build-only and transitive dependencies.
		{"critical, dev dependency", domain.SeverityCritical, 0, false,
			domain.Reachability{Direct: &direct, Scope: domain.DepScopeDev}, 3.75}, // 15 × 1 × 0.25
		{"critical, transitive runtime", domain.SeverityCritical, 0, false,
			domain.Reachability{Direct: &transitive, Scope: domain.DepScopeRuntime}, 12}, // 15 × 1 × 0.8
		{"critical, optional", domain.SeverityCritical, 0, false,
			domain.Reachability{Direct: &direct, Scope: domain.DepScopeOptional}, 7.5},
		{"critical + KEV, transitive dev", domain.SeverityCritical, 0, true,
			domain.Reachability{Direct: &transitive, Scope: domain.DepScopeDev}, 9}, // 15 × 3 × 0.2
	}
	for _, c := range cases {
		if got := domain.Priority(c.sev, domain.Exploitability{EPSS: c.epss, KEV: c.kev}, c.reach, domain.ExposureUnknown); got != c.want {
			t.Errorf("%s: Priority = %v, want %v", c.name, got, c.want)
		}
	}

	// The load-bearing property: reachability discounts noise, it never buries an
	// emergency. An exploited critical in a build-only transitive dependency must
	// still outrank a quiet medium that ships.
	buriedEmergency := domain.Priority(domain.SeverityCritical, domain.Exploitability{KEV: true},
		domain.Reachability{Direct: &transitive, Scope: domain.DepScopeDev}, domain.ExposureUnknown)
	quietShipped := domain.Priority(domain.SeverityMedium, domain.Exploitability{}, runtimeDirect, domain.ExposureUnknown)
	if buriedEmergency <= quietShipped {
		t.Errorf("a KEV critical in a dev dependency (%v) must still outrank a quiet shipped medium (%v)",
			buriedEmergency, quietShipped)
	}
}

// Public exploits raise priority, but never above a KEV listing and never by
// stacking with EPSS; no known exploit never lowers anything.
func TestPriorityExploitMaturity(t *testing.T) {
	direct := true
	reach := domain.Reachability{Direct: &direct, Scope: domain.DepScopeRuntime}
	crit := func(x domain.Exploitability) float64 {
		return domain.Priority(domain.SeverityCritical, x, reach, domain.ExposureUnknown)
	}
	cases := []struct {
		name string
		x    domain.Exploitability
		want float64
	}{
		{"weaponized", domain.Exploitability{Maturity: domain.ExploitWeaponized}, 37.5}, // 15 × 2.5
		{"poc", domain.Exploitability{Maturity: domain.ExploitPoC}, 22.5},               // 15 × 1.5
		{"poc but EPSS 0.6 is stronger", domain.Exploitability{EPSS: 0.6, Maturity: domain.ExploitPoC}, 33},
		{"weaponized + EPSS 0.9: the stronger, not the sum", domain.Exploitability{EPSS: 0.9, Maturity: domain.ExploitWeaponized}, 42},
		{"KEV is the ceiling", domain.Exploitability{KEV: true, Maturity: domain.ExploitWeaponized}, 45},
		{"no exploit known", domain.Exploitability{}, 15},
	}
	for _, c := range cases {
		if got := crit(c.x); got != c.want {
			t.Errorf("%s: Priority = %v, want %v", c.name, got, c.want)
		}
	}
	if crit(domain.Exploitability{Maturity: domain.ExploitWeaponized}) <= crit(domain.Exploitability{EPSS: 0.5}) {
		t.Error("a weaponized exploit must rank at least like a high EPSS")
	}
}

// Asset exposure is the fourth input: internet raises moderately, internal and
// unknown leave the number alone, isolated discounts — but never so far that an
// exploited critical drops below a quiet medium, wherever each one sits.
func TestPriorityExposure(t *testing.T) {
	direct, transitive := true, false
	runtimeDirect := domain.Reachability{Direct: &direct, Scope: domain.DepScopeRuntime}
	devTransitive := domain.Reachability{Direct: &transitive, Scope: domain.DepScopeDev}
	kev := domain.Exploitability{KEV: true}

	cases := []struct {
		name  string
		sev   domain.Severity
		x     domain.Exploitability
		reach domain.Reachability
		exp   domain.Exposure
		want  float64
	}{
		{"critical + KEV, internet", domain.SeverityCritical, kev, runtimeDirect, domain.ExposureInternet, 56.25}, // 15 × 3 × 1 × 1.25
		{"critical + KEV, internal", domain.SeverityCritical, kev, runtimeDirect, domain.ExposureInternal, 45},
		{"critical + KEV, isolated", domain.SeverityCritical, kev, runtimeDirect, domain.ExposureIsolated, 33.75}, // 15 × 3 × 1 × 0.75
		{"high quiet, internet", domain.SeverityHigh, domain.Exploitability{}, runtimeDirect, domain.ExposureInternet, 8.75},
		{"medium quiet, internet", domain.SeverityMedium, domain.Exploitability{}, runtimeDirect, domain.ExposureInternet, 3.75},
		{"critical + KEV, transitive dev, isolated", domain.SeverityCritical, kev, devTransitive, domain.ExposureIsolated, 6.75}, // 15 × 3 × 0.2 × 0.75
		{"info stays zero on the internet", domain.SeverityInfo, kev, runtimeDirect, domain.ExposureInternet, 0},
		// Unknown exposure — an asset nobody classified, or no asset at all — is
		// exactly the pre-exposure number: absence of evidence never discounts.
		{"critical + KEV, unknown", domain.SeverityCritical, kev, runtimeDirect, domain.ExposureUnknown, 45},
		{"critical + KEV, transitive dev, unknown", domain.SeverityCritical, kev, devTransitive, domain.ExposureUnknown, 9},
	}
	for _, c := range cases {
		if got := domain.Priority(c.sev, c.x, c.reach, c.exp); got != c.want {
			t.Errorf("%s: Priority = %v, want %v", c.name, got, c.want)
		}
	}

	// Internet is never a discount, unknown never one either.
	for _, sev := range []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical} {
		base := domain.Priority(sev, domain.Exploitability{}, runtimeDirect, domain.ExposureUnknown)
		if got := domain.Priority(sev, domain.Exploitability{}, runtimeDirect, domain.ExposureInternet); got <= base {
			t.Errorf("%s on the internet = %v, must exceed unknown %v", sev, got, base)
		}
		if got := domain.Priority(sev, domain.Exploitability{}, runtimeDirect, domain.ExposureInternal); got != base {
			t.Errorf("%s internal = %v, want unknown's %v", sev, got, base)
		}
	}

	// The bound on the isolated discount: the most discounted emergency still
	// outranks the most raised quiet medium.
	buried := domain.Priority(domain.SeverityCritical, kev, devTransitive, domain.ExposureIsolated)
	loudMedium := domain.Priority(domain.SeverityMedium, domain.Exploitability{}, runtimeDirect, domain.ExposureInternet)
	if buried <= loudMedium {
		t.Errorf("isolated KEV critical in a dev dependency (%v) must outrank an internet-facing quiet medium (%v)", buried, loudMedium)
	}
}

// --- fakes ---

type fakeEPSS map[string]float64

func (f fakeEPSS) Scores(context.Context, []string) (map[string]float64, error) { return f, nil }

// fakeCatalog is a KEV catalog listing ids (or failing with err).
type fakeCatalog struct {
	name       string
	ids        []string
	ransomware []string
	err        error
}

func (f fakeCatalog) Name() string { return f.name }
func (f fakeCatalog) Fetch(context.Context) (KEVList, error) {
	l := KEVList{IDs: f.ids, Ransomware: map[string]bool{}}
	for _, id := range f.ransomware {
		l.Ransomware[id] = true
	}
	return l, f.err
}

// fakeKEVStore keeps catalogs' lists in memory like KEVRepository.
type fakeKEVStore struct {
	lists  map[string]KEVList
	failed map[string]string
}

func (s *fakeKEVStore) Replace(_ context.Context, source string, list KEVList) error {
	if s.lists == nil {
		s.lists = map[string]KEVList{}
	}
	s.lists[source] = list
	return nil
}
func (s *fakeKEVStore) Failed(_ context.Context, source string, cause error) error {
	if s.failed == nil {
		s.failed = map[string]string{}
	}
	s.failed[source] = cause.Error()
	return nil
}
func (s *fakeKEVStore) Assertions(_ context.Context, sources []string) (KEVAssertions, error) {
	out := KEVAssertions{Sources: map[string][]string{}, Ransomware: map[string]bool{}}
	for _, src := range sources {
		for _, id := range s.lists[src].IDs {
			out.Sources[id] = append(out.Sources[id], src)
			if s.lists[src].Ransomware[id] {
				out.Ransomware[id] = true
			}
		}
	}
	return out, nil
}
func (s *fakeKEVStore) Status(context.Context) ([]KEVCatalogStatus, error) { return nil, nil }

// cisa is a one-catalog setup asserting ids.
func cisa(ids ...string) []KEVCatalog { return []KEVCatalog{fakeCatalog{name: "cisa", ids: ids}} }

type fakeStore struct {
	items []finding.Enrichable
	set   map[string]struct {
		epss       *float64
		kev        bool
		sources    []string
		ransomware bool
		priority   float64
	}
}

func (s *fakeStore) ListEnrichable(context.Context) ([]finding.Enrichable, error) {
	return s.items, nil
}
func (s *fakeStore) SetEnrichment(_ context.Context, id string, epss *float64, kevSources []string, ransomware bool, priority float64) error {
	if s.set == nil {
		s.set = map[string]struct {
			epss       *float64
			kev        bool
			sources    []string
			ransomware bool
			priority   float64
		}{}
	}
	s.set[id] = struct {
		epss       *float64
		kev        bool
		sources    []string
		ransomware bool
		priority   float64
	}{epss, len(kevSources) > 0, kevSources, ransomware, priority}
	return nil
}

func TestEnrichAppliesSignals(t *testing.T) {
	store := &fakeStore{items: []finding.Enrichable{
		{ID: "a", Severity: domain.SeverityCritical, CVE: []string{"CVE-1", "CVE-2"}, IDs: []string{"CVE-1", "CVE-2"}}, // CVE-1 KEV, CVE-2 higher epss
		{ID: "b", Severity: domain.SeverityHigh, CVE: []string{"CVE-3"}, IDs: []string{"CVE-3"}},                       // no intel
	}}
	epss := fakeEPSS{"CVE-1": 0.2, "CVE-2": 0.7}

	svc := NewService(store, epss, cisa("CVE-1"), &fakeKEVStore{}, nil)
	res, err := svc.Enrich(context.Background())
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if res.Findings != 2 {
		t.Fatalf("enriched %d, want 2", res.Findings)
	}

	a := store.set["a"]
	if !a.kev || a.epss == nil || *a.epss != 0.7 { // max EPSS across its CVEs
		t.Errorf("a = %+v, want kev + epss 0.7", a)
	}
	if a.priority != 45 { // critical × KEV
		t.Errorf("a priority = %v, want 45", a.priority)
	}

	b := store.set["b"]
	if b.kev || b.epss != nil || b.priority != 7 { // no intel -> base
		t.Errorf("b = %+v, want no intel, priority 7", b)
	}
}

type fakeNotifier struct{ events chan notify.Event }

func (f *fakeNotifier) Notify(_ context.Context, e notify.Event) { f.events <- e }

func TestEnrichNotifiesNewlyExploitable(t *testing.T) {
	store := &fakeStore{items: []finding.Enrichable{
		// "a" is not yet KEV -> becomes KEV this run (should alert).
		{ID: "a", Severity: domain.SeverityHigh, CVE: []string{"CVE-1"}, IDs: []string{"CVE-1"}, Title: "vuln A", KEV: false},
		// "b" was already KEV -> no transition, no alert.
		{ID: "b", Severity: domain.SeverityHigh, CVE: []string{"CVE-1"}, IDs: []string{"CVE-1"}, Title: "vuln B", KEV: true},
	}}
	fn := &fakeNotifier{events: make(chan notify.Event, 1)}
	svc := NewService(store, fakeEPSS{}, cisa("CVE-1"), &fakeKEVStore{}, fn)

	if _, err := svc.Enrich(context.Background()); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	select {
	case e := <-fn.events:
		if e.Type != notify.EventExploitable || e.Fields["count"] != "1" {
			t.Errorf("event = %+v, want exploitable with count 1 (only 'a' transitioned)", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a newly-exploitable notification")
	}
}
