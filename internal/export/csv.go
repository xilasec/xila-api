package export

import (
	"encoding/csv"
	"io"
	"strings"
)

// csvTable writes RFC 4180 CSV.
type csvTable struct {
	w   *csv.Writer
	buf []string
}

func newCSV(w io.Writer) *csvTable {
	return &csvTable{w: csv.NewWriter(w)}
}

func (t *csvTable) Row(cells ...any) error {
	t.buf = t.buf[:0]
	for _, c := range cells {
		s, isText := text(c)
		if isText {
			s = EscapeFormula(s)
		}
		t.buf = append(t.buf, s)
	}
	return t.w.Write(t.buf)
}

func (t *csvTable) Close() error {
	t.w.Flush()
	return t.w.Error()
}

// EscapeFormula neutralizes CSV formula injection: a spreadsheet evaluates a
// cell starting with = + - @ (or a tab / carriage return that it trims first)
// as a formula, so a finding titled `=HYPERLINK(...)` would run in whoever opens
// the export. A leading ' makes the cell literal text. Only text cells are
// escaped; the numbers this package formats itself never need it.
func EscapeFormula(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
