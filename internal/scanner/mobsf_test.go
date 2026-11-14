package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures: DefectDojo unittests/scans/mobsf (BSD-3-Clause)
//   mobsf_android_report.json  ← mobsf/report1.json (DIVA APK, report_json)
//   mobsf_ios_3_7_9.json       ← mobsf/mobsf_3_7_9.json (IPA, MobSF 3.7.9)
//   mobsf_mobsfscan_many.json  ← mobsf/many_findings.json (mobsfscan)
//   mobsf_mobsfscan_empty.json ← mobsf/no_findings.json (mobsfscan)

func TestMobSFAndroidReport(t *testing.T) {
	fs := parseFixture(t, NewMobSF(), "mobsf_android_report.json")
	// 5 manifest + 5 code (3 high rules; android_logging is info) + 32
	// non-info hardening checks over 7 native libraries.
	if len(fs) != 42 {
		t.Fatalf("got %d findings, want 42", len(fs))
	}
	var manifest, code, binary int
	for _, f := range fs {
		switch f.Metadata["section"] {
		case "manifest":
			manifest++
		case "code":
			code++
		case "binary":
			binary++
		}
		if f.Severity == domain.SeverityInfo {
			t.Errorf("info item mapped: %s %s", f.RuleID, f.FilePath)
		}
		if f.RuleID == "android_logging" || f.RuleID == "pie" && f.FilePath == "lib/armeabi-v7a/libdivajni.so" {
			t.Errorf("info-rated check %s on %s should be skipped", f.RuleID, f.FilePath)
		}
	}
	if manifest != 5 || code != 5 || binary != 32 {
		t.Errorf("sections manifest=%d code=%d binary=%d, want 5/5/32", manifest, code, binary)
	}

	debug := findRule(t, fs, "Debug Enabled For App [android:debuggable=true]")
	if debug.Severity != domain.SeverityHigh || debug.FilePath != "AndroidManifest.xml" ||
		debug.Title != "Debug Enabled For App [android:debuggable=true]" {
		t.Errorf("debuggable = %+v", debug)
	}

	var tmp, sqlNotes, nx bool
	for _, f := range fs {
		switch {
		case f.RuleID == "android_temp_file":
			tmp = true
			if f.Severity != domain.SeverityHigh || f.CWE == nil || *f.CWE != 276 ||
				f.FilePath != "jakhar/aseem/diva/InsecureDataStorage3Activity.java" || f.Line == nil || *f.Line != 24 ||
				f.Title != "App creates temp file" {
				t.Errorf("temp file = %+v", f)
			}
		case f.RuleID == "android_sql_raw_query" && f.FilePath == "jakhar/aseem/diva/NotesProvider.java":
			sqlNotes = true
			if f.CWE == nil || *f.CWE != 89 || f.Line == nil || *f.Line != 10 {
				t.Errorf("sql raw query = %+v", f)
			}
		case f.RuleID == "nx" && f.FilePath == "lib/armeabi-v7a/libdivajni.so":
			nx = true
			if f.Severity != domain.SeverityHigh || f.Title != "The shared object does not have NX bit set" {
				t.Errorf("nx = %+v", f)
			}
		case f.RuleID == "fortify" && f.FilePath == "lib/armeabi-v7a/libdivajni.so":
			if f.Severity != domain.SeverityMedium {
				t.Errorf("fortify (warning) severity = %s", f.Severity)
			}
		}
	}
	if !tmp || !sqlNotes || !nx {
		t.Errorf("missing findings: temp=%v sql=%v nx=%v", tmp, sqlNotes, nx)
	}
}

func TestMobSFIOSReport(t *testing.T) {
	fs := parseFixture(t, NewMobSF(), "mobsf_ios_3_7_9.json")
	// binary_analysis: 2 high findings; macho_analysis: arc + encrypted
	// (warning); every other Mach-O check is info.
	if len(fs) != 4 {
		t.Fatalf("got %d findings, want 4: %v", len(fs), ruleIDs(fs))
	}
	api := findRule(t, fs, "Binary makes use of insecure API(s)")
	if api.Severity != domain.SeverityHigh || api.CWE == nil || *api.CWE != 676 ||
		api.FilePath != "bitbar-ios-sample.ipa" || api.Metadata["masvs"] != "MSTG-CODE-8" {
		t.Errorf("insecure API = %+v", api)
	}
	enc := findRule(t, fs, "encrypted")
	if enc.Severity != domain.SeverityMedium || enc.FilePath != "BitbarIOSSample" || enc.Title != "This binary is not encrypted" {
		t.Errorf("encrypted = %+v", enc)
	}
}

func TestMobSFScan(t *testing.T) {
	fs := parseFixture(t, NewMobSF(), "mobsf_mobsfscan_many.json")
	// 6 file-less INFO rules + android_kotlin_hardcoded in two files.
	if len(fs) != 8 {
		t.Fatalf("got %d findings, want 8: %v", len(fs), ruleIDs(fs))
	}
	var hard []ParsedFinding
	for _, f := range fs {
		if f.RuleID == "android_kotlin_hardcoded" {
			hard = append(hard, f)
		}
	}
	if len(hard) != 2 {
		t.Fatalf("hardcoded findings = %d, want 2", len(hard))
	}
	h := hard[0]
	if h.Severity != domain.SeverityMedium || h.CWE == nil || *h.CWE != 798 ||
		h.FilePath != "app/src/main/java/com/routes/domain/analytics/event/Signatures.kt" ||
		h.Line == nil || *h.Line != 10 {
		t.Errorf("hardcoded = %+v", h)
	}
	if hard[1].FilePath != "app/src/main/java/com/routes/domain/analytics/event/Signatures2.kt" || *hard[1].Line != 20 {
		t.Errorf("second hardcoded = %+v", hard[1])
	}
	ct := findRule(t, fs, "android_certificate_transparency")
	if ct.Severity != domain.SeverityLow || ct.CWE == nil || *ct.CWE != 295 {
		t.Errorf("certificate transparency = %+v", ct)
	}

	empty := parseFixture(t, NewMobSF(), "mobsf_mobsfscan_empty.json")
	if empty == nil || len(empty) != 0 {
		t.Fatalf("no_findings = %v, want empty slice", empty)
	}
	for _, bad := range []string{`[]`, `{}`, `{"foo": 1}`, `nope`} {
		if _, err := NewMobSF().Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted non-MobSF input", bad)
		}
	}
}
