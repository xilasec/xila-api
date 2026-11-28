package export

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"
	"unicode/utf16"
)

// A minimal Office Open XML workbook: one worksheet, inline strings (so rows
// stream — no shared-string table to collect first), a bold frozen header and a
// date format. Strings are stored as inlineStr cells, which a spreadsheet never
// evaluates, so XLSX needs no formula escaping.
const (
	nsMain = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
	nsRel  = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	nsPkg  = "http://schemas.openxmlformats.org/package/2006/relationships"

	// maxCellChars is Excel's per-cell limit; a longer cell makes Excel declare
	// the whole file corrupt.
	maxCellChars = 32767

	// Cell style indexes into styles.xml cellXfs.
	styleHeader = 1
	styleDate   = 2
)

const contentTypesXML = xml.Header + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
	`</Types>`

const rootRelsXML = xml.Header + `<Relationships xmlns="` + nsPkg + `">` +
	`<Relationship Id="rId1" Type="` + nsRel + `/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const workbookRelsXML = xml.Header + `<Relationships xmlns="` + nsPkg + `">` +
	`<Relationship Id="rId1" Type="` + nsRel + `/worksheet" Target="worksheets/sheet1.xml"/>` +
	`<Relationship Id="rId2" Type="` + nsRel + `/styles" Target="styles.xml"/>` +
	`</Relationships>`

const stylesXML = xml.Header + `<styleSheet xmlns="` + nsMain + `">` +
	`<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>` +
	`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
	`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
	`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="3">` +
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +
	`<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>` +
	`</cellXfs>` +
	`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>` +
	`</styleSheet>`

const sheetHead = xml.Header + `<worksheet xmlns="` + nsMain + `" xmlns:r="` + nsRel + `">` +
	`<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>` +
	`<sheetFormatPr baseColWidth="10" defaultColWidth="20" defaultRowHeight="15"/>` +
	`<sheetData>`

const sheetTail = `</sheetData></worksheet>`

// excelEpoch is day 0 of Excel's 1900 date system (the 1900 leap-year bug is
// why it's the 30th, not the 31st).
var excelEpoch = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)

type xlsxTable struct {
	zw  *zip.Writer
	w   *bufio.Writer
	row int
}

func newXLSX(w io.Writer, sheet string) (*xlsxTable, error) {
	zw := zip.NewWriter(w)
	var name bytes.Buffer
	if err := xml.EscapeText(&name, []byte(sheet)); err != nil {
		return nil, err
	}
	workbook := xml.Header + `<workbook xmlns="` + nsMain + `" xmlns:r="` + nsRel + `">` +
		`<sheets><sheet name="` + name.String() + `" sheetId="1" r:id="rId1"/></sheets></workbook>`
	for _, part := range []struct{ name, body string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"xl/workbook.xml", workbook},
		{"xl/_rels/workbook.xml.rels", workbookRelsXML},
		{"xl/styles.xml", stylesXML},
	} {
		f, err := zw.Create(part.name)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(f, part.body); err != nil {
			return nil, err
		}
	}
	f, err := zw.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		return nil, err
	}
	t := &xlsxTable{zw: zw, w: bufio.NewWriter(f)}
	_, err = t.w.WriteString(sheetHead)
	return t, err
}

func (t *xlsxTable) Row(cells ...any) error {
	t.row++
	header := t.row == 1
	fmt.Fprintf(t.w, `<row r="%d">`, t.row)
	for i, c := range cells {
		ref := columnName(i) + strconv.Itoa(t.row)
		v := deref(c)
		if v == nil {
			continue // an absent <c> is an empty cell
		}
		switch x := v.(type) {
		case int:
			fmt.Fprintf(t.w, `<c r="%s"><v>%d</v></c>`, ref, x)
		case int64:
			fmt.Fprintf(t.w, `<c r="%s"><v>%d</v></c>`, ref, x)
		case float64:
			if math.IsNaN(x) || math.IsInf(x, 0) {
				continue
			}
			fmt.Fprintf(t.w, `<c r="%s"><v>%s</v></c>`, ref, formatFloat(x))
		case bool:
			b := 0
			if x {
				b = 1
			}
			fmt.Fprintf(t.w, `<c r="%s" t="b"><v>%d</v></c>`, ref, b)
		case time.Time:
			serial := x.UTC().Sub(excelEpoch).Hours() / 24
			fmt.Fprintf(t.w, `<c r="%s" s="%d"><v>%s</v></c>`, ref, styleDate, formatFloat(serial))
		default:
			s, _ := text(v)
			if s == "" {
				continue
			}
			style := ""
			if header {
				style = fmt.Sprintf(` s="%d"`, styleHeader)
			}
			fmt.Fprintf(t.w, `<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">`, ref, style)
			if err := xml.EscapeText(t.w, []byte(truncateCell(s))); err != nil {
				return err
			}
			if _, err := t.w.WriteString(`</t></is></c>`); err != nil {
				return err
			}
		}
	}
	_, err := t.w.WriteString(`</row>`)
	return err
}

func (t *xlsxTable) Close() error {
	if _, err := t.w.WriteString(sheetTail); err != nil {
		return err
	}
	if err := t.w.Flush(); err != nil {
		return err
	}
	return t.zw.Close()
}

// columnName is the spreadsheet letter for a zero-based column (0 → A, 26 → AA).
func columnName(i int) string {
	name := ""
	for i++; i > 0; i = (i - 1) / 26 {
		name = string(rune('A'+(i-1)%26)) + name
	}
	return name
}

// truncateCell cuts s to Excel's cell limit, counted (as Excel does) in UTF-16
// code units, without splitting a character.
func truncateCell(s string) string {
	units := 0
	for i, r := range s {
		units += utf16.RuneLen(r)
		if units > maxCellChars {
			return s[:i]
		}
	}
	return s
}
