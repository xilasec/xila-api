// Package export writes tabular downloads — CSV and Excel (XLSX) — of any
// listing. Callers stream rows from a database cursor into a Table one at a
// time, so an export never materializes the whole result set as Go values.
package export

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

// MaxRows caps one export. Past it the download is cut short and flagged with
// an `X-Truncated: true` header, so a huge filter can't tie up the server.
const MaxRows = 100_000

// Format is an export file format.
type Format string

const (
	CSV  Format = "csv"
	XLSX Format = "xlsx"
)

// ErrFormat is returned for an unknown ?format=.
var ErrFormat = errors.New("format must be csv or xlsx")

// ParseFormat reads a ?format= value; empty means CSV.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case "", CSV:
		return CSV, nil
	case XLSX:
		return XLSX, nil
	}
	return "", ErrFormat
}

// ContentType is the media type a format is served as.
func (f Format) ContentType() string {
	if f == XLSX {
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}
	return "text/csv; charset=utf-8"
}

// Table receives an export's rows. Cells may be string, int, float64, bool,
// time.Time, a pointer to any of those, or nil (an empty cell).
type Table interface {
	Row(cells ...any) error
	// Close finishes the file; nothing may be written after it.
	Close() error
}

// New starts a table in format f on w, writing the header row. sheet names the
// XLSX worksheet (at most 31 characters, none of []:*?/\).
func New(f Format, w io.Writer, sheet string, header []string) (Table, error) {
	cells := make([]any, len(header))
	for i, h := range header {
		cells[i] = h
	}
	var t Table
	if f == XLSX {
		x, err := newXLSX(w, sheet)
		if err != nil {
			return nil, err
		}
		t = x
	} else {
		t = newCSV(w)
	}
	if err := t.Row(cells...); err != nil {
		return nil, err
	}
	return t, nil
}

// Respond serves an export as the response. It reads ?format=, lets fill write
// the rows (fill reports whether it stopped at MaxRows), and names the download
// "<name>-<date>.<ext>". The rows go straight from fill's cursor into the
// response body; a failure part-way discards the partial file and returns the
// error, so a client never saves half an export as if it were whole.
func Respond(c *fiber.Ctx, name, sheet string, header []string, fill func(Table) (truncated bool, err error)) error {
	format, err := ParseFormat(c.Query("format"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	t, err := New(format, c.Response().BodyWriter(), sheet, header)
	if err != nil {
		return err
	}
	truncated, err := fill(t)
	if err == nil {
		err = t.Close()
	}
	if err != nil {
		c.Response().ResetBody()
		return err
	}
	c.Set(fiber.HeaderContentType, format.ContentType())
	c.Set(fiber.HeaderContentDisposition,
		fmt.Sprintf(`attachment; filename="%s-%s.%s"`, name, time.Now().UTC().Format(time.DateOnly), format))
	c.Set(fiber.HeaderCacheControl, "no-store")
	if truncated {
		c.Set("X-Truncated", "true")
	}
	return nil
}

// Rows is a helper for fill functions: it counts rows, writes the first MaxRows
// and reports truncation once a further row arrives. Query MaxRows+1 rows so
// the extra one tells a full export from a truncated one.
type Rows struct {
	T         Table
	n         int
	Truncated bool
}

// Add writes one row unless the cap is already reached.
func (r *Rows) Add(cells ...any) error {
	if r.n >= MaxRows {
		r.Truncated = true
		return nil
	}
	r.n++
	return r.T.Row(cells...)
}

// text renders a cell as plain text (CSV, and the strings XLSX stores).
func text(v any) (s string, isText bool) {
	switch x := deref(v).(type) {
	case nil:
		return "", false
	case string:
		return x, true
	case int:
		return fmt.Sprint(x), false
	case int64:
		return fmt.Sprint(x), false
	case float64:
		return formatFloat(x), false
	case bool:
		if x {
			return "true", false
		}
		return "false", false
	case time.Time:
		return x.UTC().Format(time.RFC3339), false
	default:
		return fmt.Sprint(x), true
	}
}

// deref unwraps the pointer cell types (nil pointer → nil).
func deref(v any) any {
	switch x := v.(type) {
	case *string:
		if x == nil {
			return nil
		}
		return *x
	case *int:
		if x == nil {
			return nil
		}
		return *x
	case *float64:
		if x == nil {
			return nil
		}
		return *x
	case *bool:
		if x == nil {
			return nil
		}
		return *x
	case *time.Time:
		if x == nil {
			return nil
		}
		return *x
	}
	return v
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64) // plain notation: spreadsheets misread 1e-05 as text
}
