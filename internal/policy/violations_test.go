package policy

import "testing"

// One package version in two artifacts of a version, with different facts:
// the policy must judge each copy and report the package once. It used to keep
// the first copy by row order, so a tampered artifact could go unreported.
func TestViolationsJudgeEveryOccurrence(t *testing.T) {
	p := Draft()
	p.ID, p.Name = "22222222-2222-4222-8222-222222222222", "tampered artifacts"
	p.Conditions = []Condition{cond(SubjectIntegrity, OpIs, `"mismatch"`)}
	cp, err := validate(&p, groups, ComponentSchema)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	express := func(artifact, integrity string) *Component {
		return comp(t, "MIT", func(c *Component) {
			c.Name, c.Version, c.Purl = "express", "4.18.2", "pkg:npm/express@4.18.2"
			c.Integrity = integrity
			c.SbomID = artifact
		})
	}
	web, cdn := express("web", "verified"), express("cdn", "mismatch")

	for name, comps := range map[string][]*Component{
		"tampered copy last":  {web, cdn},
		"tampered copy first": {cdn, web},
	} {
		got := violations([]compiledPolicy{cp}, comps, true, now)
		if len(got) != 1 || got[0].PackageName != "express" {
			t.Errorf("%s: violations = %d, want the tampered express once", name, len(got))
		}
	}

	// Both copies violate: still one finding (its fingerprint is per package).
	if got := violations([]compiledPolicy{cp}, []*Component{cdn, express("cdn2", "mismatch")}, true, now); len(got) != 1 {
		t.Errorf("two violating copies = %d findings, want 1", len(got))
	}
	// No copy violates: nothing.
	if got := violations([]compiledPolicy{cp}, []*Component{web, express("web2", "verified")}, true, now); len(got) != 0 {
		t.Errorf("no violating copy = %d findings, want 0", len(got))
	}

	// A default-versions policy never judges another version.
	p.Versions = VersionsDefault
	cpDefault, err := validate(&p, groups, ComponentSchema)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := violations([]compiledPolicy{cpDefault}, []*Component{cdn}, false, now); len(got) != 0 {
		t.Errorf("default-versions policy on a branch = %d findings, want 0", len(got))
	}

	// Each policy reports the package once.
	other := Draft()
	other.ID, other.Name = "33333333-3333-4333-8333-333333333333", "any express"
	other.Conditions = []Condition{cond(SubjectIntegrity, OpIs, `"verified"`)}
	cpOther, err := validate(&other, groups, ComponentSchema)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	got := violations([]compiledPolicy{cp, cpOther}, []*Component{web, cdn}, true, now)
	if len(got) != 2 || got[0].Fingerprint == got[1].Fingerprint {
		t.Errorf("two policies = %d findings, want one per policy", len(got))
	}
}
