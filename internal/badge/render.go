package badge

import (
	"fmt"
	"html"

	"github.com/xilasec/xila-api/internal/domain"
)

// Badge colours (shields.io's palette).
const (
	ColorGreen  = "#4c1"
	ColorYellow = "#dfb317"
	ColorOrange = "#fe7d37"
	ColorRed    = "#e05d44"
	ColorGrey   = "#9f9f9f"
	colorLabel  = "#555"
)

var severityColor = map[domain.Severity]string{
	domain.SeverityCritical: ColorRed,
	domain.SeverityHigh:     ColorOrange,
	domain.SeverityMedium:   ColorYellow,
	domain.SeverityLow:      "#a4a61d",
}

// Badge is one rendered badge: a grey label and a coloured message.
type Badge struct {
	Label   string
	Message string
	Color   string
}

// verdana11 approximates Verdana 11px advance widths (px) — what shields
// lays badges out with — for the characters badges use; others get the
// average. Close enough that the text never overflows its box.
var verdana11 = map[rune]float64{
	' ': 3.9, '·': 4.3, '%': 12.2, '-': 4.8, '.': 3.9, ':': 4.6,
	'0': 7, '1': 7, '2': 7, '3': 7, '4': 7, '5': 7, '6': 7, '7': 7, '8': 7, '9': 7,
	'a': 6.7, 'b': 6.9, 'c': 5.8, 'd': 6.9, 'e': 6.6, 'f': 3.9, 'g': 6.9, 'h': 7, 'i': 3, 'j': 3.8,
	'k': 6.5, 'l': 3, 'm': 10.7, 'n': 7, 'o': 6.7, 'p': 6.9, 'q': 6.9, 'r': 4.7, 's': 5.7, 't': 4.4,
	'u': 7, 'v': 6.5, 'w': 9, 'x': 6.5, 'y': 6.5, 'z': 5.8,
}

func textWidth(s string) float64 {
	w := 0.0
	for _, r := range s {
		if v, ok := verdana11[r]; ok {
			w += v
		} else {
			w += 7.5
		}
	}
	return w
}

// Render draws b as a self-contained flat SVG. Every text is XML-escaped and
// the colour is one of the package's constants, so nothing a caller passes
// can inject markup.
func Render(b Badge) string {
	color := b.Color
	switch color {
	case ColorGreen, ColorYellow, ColorOrange, ColorRed, ColorGrey, severityColor[domain.SeverityLow]:
	default:
		color = ColorGrey
	}
	lw := int(textWidth(b.Label)) + 10
	mw := int(textWidth(b.Message)) + 10
	label, msg := html.EscapeString(b.Label), html.EscapeString(b.Message)
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%[1]d" height="20" role="img" aria-label="%[4]s: %[5]s">`+
		`<title>%[4]s: %[5]s</title>`+
		`<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
		`<clipPath id="r"><rect width="%[1]d" height="20" rx="3" fill="#fff"/></clipPath>`+
		`<g clip-path="url(#r)"><rect width="%[2]d" height="20" fill="%[6]s"/><rect x="%[2]d" width="%[3]d" height="20" fill="%[7]s"/><rect width="%[1]d" height="20" fill="url(#s)"/></g>`+
		`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">`+
		`<text x="%[8]d" y="15" fill="#010101" fill-opacity=".3">%[4]s</text><text x="%[8]d" y="14">%[4]s</text>`+
		`<text x="%[9]d" y="15" fill="#010101" fill-opacity=".3">%[5]s</text><text x="%[9]d" y="14">%[5]s</text></g></svg>`,
		lw+mw, lw, mw, label, msg, colorLabel, color, lw/2, lw+mw/2)
}
