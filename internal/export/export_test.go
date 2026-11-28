package export

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"strings"
	"testing"
	"time"
)

func TestEscapeFormula(t *testing.T) {
	cases := map[string]string{
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"+1":                       "'+1",
		"-2+3":                     "'-2+3",
		"@SUM(A1)":                 "'@SUM(A1)",
		"\t=1":                     "'\t=1",
		"\r=1":                     "'\r=1",
		"plain":                    "plain",
		"a=b":                      "a=b",
		"":                         "",
		"CVE-2024-1":               "CVE-2024-1",
	}
	for in, want := range cases {
		if got := EscapeFormula(in); got != want {
			t.Errorf("EscapeFormula(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCSVEscapesTextButNotNumbers(t *testing.T) {
	var buf bytes.Buffer
	tbl, err := New(CSV, &buf, "x", []string{"title", "epss", "seen", "kev", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	var nilTime *time.Time
	if err := tbl.Row("=cmd|' /C calc'!A0", new(0.00001), seen, true, nilTime); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Row("line1\nline2, \"quoted\"", -1.5, nil, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"title", "epss", "seen", "kev", "missing"},
		{"'=cmd|' /C calc'!A0", "0.00001", "2026-01-02T02:04:05Z", "true", ""},
		{"line1\nline2, \"quoted\"", "-1.5", "", "false", ""},
	}
	if len(recs) != len(want) {
		t.Fatalf("got %d records, want %d: %q", len(recs), len(want), recs)
	}
	for i := range want {
		if strings.Join(recs[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("row %d = %q, want %q", i, recs[i], want[i])
		}
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": CSV, "csv": CSV, "xlsx": XLSX} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Error("ParseFormat(pdf) accepted")
	}
}

func TestRowsCap(t *testing.T) {
	var buf bytes.Buffer
	tbl, _ := New(CSV, &buf, "x", []string{"n"})
	rows := Rows{T: tbl}
	for i := range MaxRows + 1 {
		if err := rows.Add(i); err != nil {
			t.Fatal(err)
		}
	}
	tbl.Close()
	if !rows.Truncated {
		t.Error("an extra row past MaxRows must mark the export truncated")
	}
	if n := strings.Count(buf.String(), "\n"); n != MaxRows+1 { // header + MaxRows
		t.Errorf("wrote %d lines, want %d", n, MaxRows+1)
	}

	buf.Reset()
	tbl, _ = New(CSV, &buf, "x", []string{"n"})
	rows = Rows{T: tbl}
	for i := range MaxRows {
		if err := rows.Add(i); err != nil {
			t.Fatal(err)
		}
	}
	if rows.Truncated {
		t.Error("exactly MaxRows rows is a complete export, not a truncated one")
	}
}

func TestColumnName(t *testing.T) {
	for i, want := range map[int]string{0: "A", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"} {
		if got := columnName(i); got != want {
			t.Errorf("columnName(%d) = %q, want %q", i, got, want)
		}
	}
}

func TestTruncateCell(t *testing.T) {
	long := strings.Repeat("a", maxCellChars-1) + "😀" // emoji = 2 UTF-16 units
	if got := truncateCell(long); got != strings.Repeat("a", maxCellChars-1) {
		t.Errorf("truncation split or kept an over-limit character (len %d)", len(got))
	}
	if s := strings.Repeat("é", maxCellChars); truncateCell(s) != s {
		t.Error("a cell exactly at the limit must be kept whole")
	}
}

// TestXLSXStructure re-reads a generated workbook the way a spreadsheet does:
// content types cover every part, relationships resolve, every part is
// well-formed XML, and cells carry the right types.
func TestXLSXStructure(t *testing.T) {
	var buf bytes.Buffer
	tbl, err := New(XLSX, &buf, "Findings & <more>", []string{"Title", "Priority", "KEV", "Seen", "Empty"})
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	rows := [][]any{
		{"=1+1 <script>&\x01", 15.5, true, seen, nil},
		{"plain", 3, false, (*time.Time)(nil), ""},
	}
	for _, r := range rows {
		if err := tbl.Row(r...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tbl.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	parts := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = b
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			assertWellFormed(t, f.Name, b)
		}
	}
	if zr.File[0].Name != "[Content_Types].xml" {
		t.Errorf("first part = %q; [Content_Types].xml should lead", zr.File[0].Name)
	}

	// Every non-rels part needs a content type (override or by extension).
	var types struct {
		Defaults []struct {
			Extension string `xml:"Extension,attr"`
		} `xml:"Default"`
		Overrides []struct {
			PartName    string `xml:"PartName,attr"`
			ContentType string `xml:"ContentType,attr"`
		} `xml:"Override"`
	}
	mustUnmarshal(t, parts["[Content_Types].xml"], &types)
	overrides := map[string]string{}
	for _, o := range types.Overrides {
		overrides[o.PartName] = o.ContentType
		if _, ok := parts[strings.TrimPrefix(o.PartName, "/")]; !ok {
			t.Errorf("content type override for missing part %s", o.PartName)
		}
	}
	if overrides["/xl/workbook.xml"] != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml" {
		t.Errorf("workbook content type = %q", overrides["/xl/workbook.xml"])
	}
	if overrides["/xl/worksheets/sheet1.xml"] != "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml" {
		t.Errorf("sheet content type = %q", overrides["/xl/worksheets/sheet1.xml"])
	}

	// Relationships resolve to parts that exist.
	type rels struct {
		Rel []struct {
			ID     string `xml:"Id,attr"`
			Type   string `xml:"Type,attr"`
			Target string `xml:"Target,attr"`
		} `xml:"Relationship"`
	}
	var root, wbRels rels
	mustUnmarshal(t, parts["_rels/.rels"], &root)
	if len(root.Rel) != 1 || root.Rel[0].Target != "xl/workbook.xml" || !strings.HasSuffix(root.Rel[0].Type, "/officeDocument") {
		t.Fatalf("root rels = %+v", root.Rel)
	}
	mustUnmarshal(t, parts["xl/_rels/workbook.xml.rels"], &wbRels)
	relByID := map[string]string{}
	for _, r := range wbRels.Rel {
		target := path.Join("xl", r.Target)
		if _, ok := parts[target]; !ok {
			t.Errorf("workbook rel %s → missing %s", r.ID, target)
		}
		relByID[r.ID] = target
	}

	var wb struct {
		Sheets []struct {
			Name string `xml:"name,attr"`
			RID  string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
		} `xml:"sheets>sheet"`
	}
	mustUnmarshal(t, parts["xl/workbook.xml"], &wb)
	if len(wb.Sheets) != 1 || wb.Sheets[0].Name != "Findings & <more>" || relByID[wb.Sheets[0].RID] != "xl/worksheets/sheet1.xml" {
		t.Fatalf("workbook sheets = %+v (rels %v)", wb.Sheets, relByID)
	}

	type cell struct {
		Ref    string `xml:"r,attr"`
		Type   string `xml:"t,attr"`
		Style  string `xml:"s,attr"`
		V      string `xml:"v"`
		F      string `xml:"f"`
		Inline string `xml:"is>t"`
	}
	var sheet struct {
		Pane struct {
			State string `xml:"state,attr"`
		} `xml:"sheetViews>sheetView>pane"`
		Rows []struct {
			R     string `xml:"r,attr"`
			Cells []cell `xml:"c"`
		} `xml:"sheetData>row"`
	}
	mustUnmarshal(t, parts["xl/worksheets/sheet1.xml"], &sheet)
	if sheet.Pane.State != "frozen" {
		t.Error("header row should be frozen")
	}
	if len(sheet.Rows) != 3 {
		t.Fatalf("got %d rows, want header + 2", len(sheet.Rows))
	}
	header := sheet.Rows[0].Cells
	if len(header) != 5 || header[0].Inline != "Title" || header[0].Style != "1" || header[4].Ref != "E1" {
		t.Errorf("header = %+v", header)
	}
	r1 := map[string]cell{}
	for _, c := range sheet.Rows[1].Cells {
		r1[c.Ref] = c
	}
	// Text is an inline string — never a formula — with control chars replaced
	// so the XML stays valid.
	if c := r1["A2"]; c.Type != "inlineStr" || c.F != "" || c.Inline != "=1+1 <script>&\uFFFD" {
		t.Errorf("A2 = %+v", c)
	}
	if c := r1["B2"]; c.Type != "" || c.V != "15.5" {
		t.Errorf("B2 = %+v, want number 15.5", c)
	}
	if c := r1["C2"]; c.Type != "b" || c.V != "1" {
		t.Errorf("C2 = %+v, want boolean true", c)
	}
	// 2026-03-01 12:00 is Excel serial 46082.5, shown with the date style.
	if c := r1["D2"]; c.V != "46082.5" || c.Style != "2" {
		t.Errorf("D2 = %+v, want date serial 46082.5 style 2", c)
	}
	if _, ok := r1["E2"]; ok {
		t.Error("nil cell should be omitted")
	}
	if n := len(sheet.Rows[2].Cells); n != 3 { // "plain", 3, false; nil time + "" omitted
		t.Errorf("row 3 has %d cells, want 3: %+v", n, sheet.Rows[2].Cells)
	}
}

func assertWellFormed(t *testing.T, name string, b []byte) {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("%s is not well-formed XML: %v", name, err)
		}
	}
}

func mustUnmarshal(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := xml.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, b)
	}
}
