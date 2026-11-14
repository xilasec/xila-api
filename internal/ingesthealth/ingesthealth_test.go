package ingesthealth

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	// daily builds the scans of a stream uploading every day, newest first,
	// the newest `ago` before now, with the given totals.
	daily := func(ago time.Duration, totals ...int) []Point {
		var ps []Point
		for i, n := range totals {
			ps = append(ps, Point{At: now.Add(-ago - time.Duration(i)*24*time.Hour), Total: n})
		}
		return ps
	}
	kinds := func(as []Anomaly) []string {
		out := []string{}
		for _, a := range as {
			out = append(out, a.Kind)
		}
		return out
	}
	cases := []struct {
		name  string
		scans []Point
		want  []string
	}{
		{"healthy daily stream", daily(2*time.Hour, 40, 42, 41, 39, 40), []string{}},
		{"daily stream silent for 4 days", daily(4*24*time.Hour, 40, 42, 41), []string{KindStale}},
		{"silent 2.5 days — under 3 gaps", daily(60*time.Hour, 40, 42, 41), []string{}},
		{"weekly stream silent 10 days is fine", []Point{
			{At: now.Add(-10 * 24 * time.Hour), Total: 5}, {At: now.Add(-17 * 24 * time.Hour), Total: 5}, {At: now.Add(-24 * 24 * time.Hour), Total: 5},
		}, []string{}},
		{"too little history to judge cadence", daily(30*24*time.Hour, 40, 41), []string{}},
		{"sudden zero findings", daily(time.Hour, 0, 38, 40, 41, 39), []string{KindVolumeDrop}},
		{"halved findings", daily(time.Hour, 15, 38, 40, 41), []string{KindVolumeDrop}},
		{"small project fluctuating", daily(time.Hour, 1, 6, 5, 7), []string{}}, // baseline under 10
		{"findings fixed gradually is not a drop", daily(time.Hour, 30, 34, 38, 40), []string{}},
		{"latest scan failed", append([]Point{{At: now.Add(-time.Hour), Failed: true, Error: "parse error"}}, daily(25*time.Hour, 40, 41, 39)...), []string{KindFailedScan}},
		{"failed, then the good scan before it dropped", append([]Point{{At: now.Add(-time.Hour), Failed: true}}, daily(25*time.Hour, 2, 41, 39, 40)...),
			[]string{KindFailedScan, KindVolumeDrop}},
	}
	for _, c := range cases {
		got := kinds(Evaluate(Stream{ProjectID: "p", Scanner: "trivy", Scans: c.scans}, now))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	a := Evaluate(Stream{ProjectID: "p", Scanner: "trivy", Scans: daily(4*24*time.Hour, 40, 42, 41)}, now)[0]
	if !strings.Contains(a.Detail, "no trivy upload for 4 days (usually every 24 hours)") {
		t.Errorf("stale detail = %q", a.Detail)
	}
}
