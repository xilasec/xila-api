package main

import "fmt"

// checkRunName is the name of the GitHub check run xila creates. The Checks API
// matches an existing run to update by (name, head_sha), so this name must stay
// stable across runs or every push creates a new check instead of updating one.
const checkRunName = "Xila security gate"

// maxAnnotationsPerRequest is the Checks API's hard limit on annotations per
// create/update call. Posting more means further PATCH calls — the API appends
// annotations rather than replacing them, so each call only ever carries its
// own batch.
const maxAnnotationsPerRequest = 50

// maxAnnotations caps the total annotations a run ever carries. The Checks API
// itself has no total limit, but a check with thousands of inline comments is
// unusable in the "Files changed" tab and costs one extra HTTP round trip per
// 50 — worth it up to a point, not unconditionally.
const maxAnnotations = 200

// checkAnnotation is one Checks API annotation: a finding pinned to a file and
// line. Field names/json tags match the API body exactly.
type checkAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // notice | warning | failure
	Title           string `json:"title,omitempty"`
	Message         string `json:"message"`
}

// hasLocation reports whether a finding can be pinned to a line at all. Most
// SCA findings (a CVE in a dependency) have no source line — only SAST/secrets
// findings (file_path + line) do.
func hasLocation(f prFinding) bool {
	return f.FilePath != "" && f.Line != nil && *f.Line > 0
}

// annotationLevel maps a finding to a Checks API annotation level. KEV and
// critical/high get "failure" — the same things that would fail the gate — so
// the inline annotation draws the same attention as the merge-blocking verdict;
// everything else is a quieter "warning".
func annotationLevel(f prFinding) string {
	if f.KEV || f.Severity == "critical" || f.Severity == "high" {
		return "failure"
	}
	return "warning"
}

// annotationTitle prefixes the finding's CVE, same as the PR comment table.
func annotationTitle(f prFinding) string {
	if len(f.CVE) > 0 {
		return f.CVE[0] + ": " + f.Title
	}
	return f.Title
}

// annotationMessage is the annotation body: the same actionable facts as the PR
// comment's flags/package/fix cells, inline where the code change needs them.
func annotationMessage(f prFinding) string {
	msg := f.Title
	switch {
	case f.KEV:
		msg += " — actively exploited (CISA KEV)."
	case f.EPSS != nil && *f.EPSS >= 0.1:
		msg += fmt.Sprintf(" — %.0f%% EPSS.", *f.EPSS*100)
	}
	if f.Package != "" {
		msg += " Package: " + f.Package
		if f.PackageVersion != "" {
			msg += "@" + f.PackageVersion
		}
		if f.FixedVersion != "" {
			msg += " (fix: " + f.FixedVersion + ")"
		}
	}
	return msg
}

// buildAnnotations turns findings with a known file+line into Checks API
// annotations, in the given (worst-first) order, capped at maxAnnotations.
// Findings without a location are skipped here — they still appear in the PR
// comment table, just not inline.
func buildAnnotations(findings []prFinding) []checkAnnotation {
	var out []checkAnnotation
	for _, f := range findings {
		if !hasLocation(f) {
			continue
		}
		if len(out) >= maxAnnotations {
			break
		}
		out = append(out, checkAnnotation{
			Path:            f.FilePath,
			StartLine:       *f.Line,
			EndLine:         *f.Line,
			AnnotationLevel: annotationLevel(f),
			Title:           annotationTitle(f),
			Message:         annotationMessage(f),
		})
	}
	return out
}

// countLocatable counts findings that have a file+line, i.e. how many could
// have become an annotation before the maxAnnotations cap applied.
func countLocatable(findings []prFinding) int {
	n := 0
	for _, f := range findings {
		if hasLocation(f) {
			n++
		}
	}
	return n
}

// batchAnnotations splits annotations into the batch used on create/the first
// update (first, at most maxAnnotationsPerRequest) and the further batches that
// each need their own PATCH call (rest). Each batch is at most
// maxAnnotationsPerRequest — the Checks API's hard per-request limit.
func batchAnnotations(annotations []checkAnnotation) (first []checkAnnotation, rest [][]checkAnnotation) {
	if len(annotations) == 0 {
		return nil, nil
	}
	n := len(annotations)
	if n > maxAnnotationsPerRequest {
		n = maxAnnotationsPerRequest
	}
	first = annotations[:n]
	for i := n; i < len(annotations); i += maxAnnotationsPerRequest {
		end := i + maxAnnotationsPerRequest
		if end > len(annotations) {
			end = len(annotations)
		}
		rest = append(rest, annotations[i:end])
	}
	return first, rest
}

// checkConclusion maps the gate result to a Checks API conclusion. A check run
// always needs one: "neutral" when there was no gate at all (an upload without
// --gate, or `gate --check` run before a verdict exists) — it shouldn't paint an
// ungated upload green or red.
func checkConclusion(gate *gateResult) string {
	switch {
	case gate == nil:
		return "neutral"
	case gate.Passed:
		return "success"
	default:
		return "failure"
	}
}
