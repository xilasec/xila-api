package badge

import (
	"encoding/xml"
	"strconv"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func TestRenderIsWellFormedAndEscaped(t *testing.T) {
	out := Render(Badge{Label: `a<b>&"c"`, Message: "</text><script>x</script>", Color: `red"/><script>`})
	if err := xml.Unmarshal([]byte(out), new(struct{})); err != nil {
		t.Fatalf("not well-formed XML: %v\n%s", err, out)
	}
	if strings.Contains(out, "<script") || strings.Contains(out, `fill="red`) {
		t.Errorf("unescaped input or colour in SVG: %s", out)
	}
	if !strings.Contains(out, `fill="`+ColorGrey+`"`) {
		t.Error("an unknown colour should fall back to grey")
	}
}

func TestRenderWidthGrowsWithText(t *testing.T) {
	width := func(msg string) int {
		out := Render(Badge{Label: "vulnerabilities", Message: msg, Color: ColorRed})
		n, err := strconv.Atoi(out[strings.Index(out, `width="`)+7 : strings.Index(out, `" height`)])
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if short, long := width("none"), width("12 critical · 340 high"); long <= short+60 {
		t.Errorf("width %d for a long message, %d for a short one", long, short)
	}
}

func TestFindingsBadge(t *testing.T) {
	cases := []struct {
		open      map[domain.Severity]int
		msg, want string
	}{
		{map[domain.Severity]int{}, "none", ColorGreen},
		{map[domain.Severity]int{domain.SeverityInfo: 4}, "none", ColorGreen},
		{map[domain.Severity]int{domain.SeverityLow: 3, domain.SeverityMedium: 1}, "1 medium · 3 low", ColorYellow},
		{map[domain.Severity]int{domain.SeverityCritical: 2, domain.SeverityHigh: 5, domain.SeverityLow: 9}, "2 critical · 5 high", ColorRed},
		{map[domain.Severity]int{domain.SeverityHigh: 1}, "1 high", ColorOrange},
	}
	for _, c := range cases {
		b := findingsBadge(c.open)
		if b.Message != c.msg || b.Color != c.want {
			t.Errorf("findingsBadge(%v) = %q %s, want %q %s", c.open, b.Message, b.Color, c.msg, c.want)
		}
	}
}

func TestSLABadge(t *testing.T) {
	pct := func(f float64) *float64 { return &f }
	cases := []struct {
		s         finding.SLAStats
		msg, want string
	}{
		{finding.SLAStats{Breached: 3, Compliance: pct(1)}, "3 breached", ColorRed},
		{finding.SLAStats{}, "on track", ColorGreen},
		{finding.SLAStats{Compliance: pct(0.97)}, "97% on time", ColorGreen},
		{finding.SLAStats{Compliance: pct(0.9)}, "90% on time", ColorYellow},
		{finding.SLAStats{Compliance: pct(0.5)}, "50% on time", ColorOrange},
	}
	for _, c := range cases {
		if b := slaBadge(c.s); b.Message != c.msg || b.Color != c.want {
			t.Errorf("slaBadge = %q %s, want %q %s", b.Message, b.Color, c.msg, c.want)
		}
	}
}
