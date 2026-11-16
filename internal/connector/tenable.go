package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Tenable Vulnerability Management (formerly Tenable.io), per its API
// reference (https://developer.tenable.com/reference/exports-vulns-request-export,
// https://developer.tenable.com/reference/exports-vulns-export-status and
// https://developer.tenable.com/reference/exports-vulns-download-chunk):
//
//   - POST /vulns/export — starts an export job; `{"export_uuid": "..."}`.
//     `filters.state` defaults to `["OPEN", "REOPENED"]` when omitted (not
//     `FIXED`, so a fixed vulnerability isn't fetched and the next pull
//     auto-closes it); `filters.tag.<category>` narrows to an asset tag.
//   - GET /vulns/export/{export_uuid}/status — polled until `status` is
//     `FINISHED` (or `ERROR`/`CANCELLED`, which fail the pull); reports
//     `chunks_available`.
//   - GET /vulns/export/{export_uuid}/chunks/{chunk_id} — one chunk's
//     `application/octet-stream` body, a JSON array of vulnerability records.
//   - Auth: `X-ApiKeys: accessKey=<access>;secretKey=<secret>`.
//
// A vulnerability's own `finding_id` (stable across exports) is the
// fingerprint identity; `severity_modification_type: "ACCEPTED"` (a user
// accept-risk rule) carries over as a risk-accepted remote triage verdict.
const (
	tenableExportAssetsPerChunk = 1000
	tenablePollInterval         = 2 * time.Second
	tenableMaxPolls             = 150 // ~5 minutes at the default poll interval
)

type tenable struct {
	base, scope, accessKey, secretKey string
	hc                                *http.Client
	pollInterval                      time.Duration
}

type tenableCredentials struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func parseTenableCredentials(token string) (tenableCredentials, error) {
	var c tenableCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.AccessKey == "" || c.SecretKey == "" {
		return tenableCredentials{}, invalid(`token must be JSON {"access_key": "...", "secret_key": "..."}`)
	}
	return c, nil
}

func (t *tenable) headers() map[string]string {
	return map[string]string{"X-ApiKeys": "accessKey=" + t.accessKey + ";secretKey=" + t.secretKey}
}

func (t *tenable) get(ctx context.Context, path string, dst any) error {
	_, err := httpJSON(ctx, t.hc, http.MethodGet, t.base+path, t.headers(), nil, dst)
	return err
}

// Check lists the instance's networks (a Can View-only, inexpensive call) and
// names the connection by their count, since Tenable Vulnerability Management
// has no separate "project" to name.
func (t *tenable) Check(ctx context.Context) (string, error) {
	var nets struct {
		Networks []struct {
			Name string `json:"name"`
		} `json:"networks"`
	}
	if err := t.get(ctx, "/networks", &nets); err != nil {
		return "", err
	}
	return fmt.Sprintf("Tenable Vulnerability Management (%d network(s))", len(nets.Networks)), nil
}

// tagFilter splits the scope's optional "<category>=<value>" asset tag
// filter.
func (t *tenable) tagFilter() (category, value string, ok bool) {
	category, value, ok = strings.Cut(t.scope, "=")
	return strings.TrimSpace(category), strings.TrimSpace(value), ok && category != "" && value != ""
}

func (t *tenable) startExport(ctx context.Context) (string, error) {
	filters := map[string]any{"state": []string{"OPEN", "REOPENED"}}
	if cat, val, ok := t.tagFilter(); ok {
		filters["tag."+cat] = []string{val}
	}
	body, err := json.Marshal(map[string]any{"num_assets": tenableExportAssetsPerChunk, "filters": filters})
	if err != nil {
		return "", remoteErr("tenable: encode export request: %v", err)
	}
	headers := t.headers()
	headers["Content-Type"] = "application/json"
	var resp struct {
		ExportUUID string `json:"export_uuid"`
	}
	if _, err := httpJSON(ctx, t.hc, http.MethodPost, t.base+"/vulns/export", headers, body, &resp); err != nil {
		return "", err
	}
	if resp.ExportUUID == "" {
		return "", remoteErr("tenable: export request returned no export_uuid")
	}
	return resp.ExportUUID, nil
}

// awaitExport polls the export's status until it is FINISHED, returning the
// available chunk ids in order. ERROR/CANCELLED fail the pull; a request that
// never finishes within tenableMaxPolls does too, rather than hanging it.
func (t *tenable) awaitExport(ctx context.Context, exportUUID string) ([]int, error) {
	for poll := 0; ; poll++ {
		if poll >= tenableMaxPolls {
			return nil, remoteErr("tenable: export %s did not finish after %d polls", exportUUID, tenableMaxPolls)
		}
		var status struct {
			Status          string `json:"status"`
			Reason          string `json:"reason"`
			ChunksAvailable []int  `json:"chunks_available"`
		}
		if err := t.get(ctx, "/vulns/export/"+exportUUID+"/status", &status); err != nil {
			return nil, err
		}
		switch status.Status {
		case "FINISHED":
			sort.Ints(status.ChunksAvailable)
			return status.ChunksAvailable, nil
		case "ERROR", "CANCELLED":
			return nil, remoteErr("tenable: export %s %s: %s", exportUUID, strings.ToLower(status.Status), status.Reason)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.pollInterval):
		}
	}
}

type tenableVuln struct {
	Asset struct {
		Hostname string `json:"hostname"`
		FQDN     string `json:"fqdn"`
		IPv4     string `json:"ipv4"`
	} `json:"asset"`
	Plugin struct {
		ID             int      `json:"id"`
		Name           string   `json:"name"`
		Synopsis       string   `json:"synopsis"`
		Description    string   `json:"description"`
		Solution       string   `json:"solution"`
		CVSSBaseScore  *float64 `json:"cvss_base_score"`
		CVSS3BaseScore *float64 `json:"cvss3_base_score"`
		RiskFactor     string   `json:"risk_factor"`
		CVE            []string `json:"cve"`
	} `json:"plugin"`
	Port struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	} `json:"port"`
	Severity                 string `json:"severity"`
	State                    string `json:"state"`
	FindingID                string `json:"finding_id"`
	SeverityModificationType string `json:"severity_modification_type"`
}

func (t *tenable) downloadChunk(ctx context.Context, exportUUID string, chunk int) ([]tenableVuln, error) {
	var items []tenableVuln
	if err := t.get(ctx, "/vulns/export/"+exportUUID+"/chunks/"+strconv.Itoa(chunk), &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (t *tenable) Fetch(ctx context.Context) ([]finding.Finding, error) {
	exportUUID, err := t.startExport(ctx)
	if err != nil {
		return nil, err
	}
	chunks, err := t.awaitExport(ctx, exportUUID)
	if err != nil {
		return nil, err
	}
	if len(chunks) > maxPages {
		return nil, remoteErr("tenable: export %s has more than %d chunks", exportUUID, maxPages)
	}
	out := []finding.Finding{}
	for _, chunk := range chunks {
		items, err := t.downloadChunk(ctx, exportUUID, chunk)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, t.toFinding(it))
		}
	}
	return uniqueByFingerprint(out), nil
}

// Category is DAST: Tenable's vulnerability export is host/network scanning,
// like the Nessus report parser.
func (t *tenable) Category([]finding.Finding) domain.Category { return domain.CategoryDAST }

func tenableFirstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (t *tenable) toFinding(v tenableVuln) finding.Finding {
	host := tenableFirstNonEmpty(v.Asset.Hostname, v.Asset.FQDN, v.Asset.IPv4)
	loc := host
	if v.Port.Port > 0 {
		loc = fmt.Sprintf("%s:%d/%s", host, v.Port.Port, strings.ToLower(v.Port.Protocol))
	}
	sev, ok := mapSeverity(v.Severity)
	if !ok {
		sev = domain.SeverityInfo
	}
	cvss := v.Plugin.CVSS3BaseScore
	if cvss == nil {
		cvss = v.Plugin.CVSSBaseScore
	}
	cves := []string{}
	for _, c := range v.Plugin.CVE {
		cves = addCVE(cves, c)
	}
	desc := withSection(v.Plugin.Synopsis, "Description", v.Plugin.Description)
	desc = withSection(desc, "Solution", v.Plugin.Solution)

	meta := map[string]any{"source": "tenable", "host": host, "state": v.State}
	if v.Plugin.RiskFactor != "" {
		meta["risk_factor"] = v.Plugin.RiskFactor
	}
	if v.Asset.IPv4 != "" {
		meta["ip"] = v.Asset.IPv4
	}
	if v.Asset.FQDN != "" {
		meta["fqdn"] = v.Asset.FQDN
	}
	if v.Port.Port > 0 {
		meta["port"] = v.Port.Port
		meta["protocol"] = v.Port.Protocol
		meta["service"] = v.Port.Service
	}
	if strings.EqualFold(v.SeverityModificationType, "ACCEPTED") {
		meta["remote_triage"] = string(domain.FindingRiskAccepted)
		meta["remote_triage_reason"] = "Tenable: risk accepted (severity override)"
	}

	identity := v.FindingID
	if identity == "" {
		identity = fmt.Sprintf("%d|%s|%d", v.Plugin.ID, host, v.Port.Port)
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindTenable, identity),
		Category:    domain.CategoryDAST,
		RuleID:      strconv.Itoa(v.Plugin.ID),
		Title:       v.Plugin.Name,
		Description: desc,
		Severity:    sev,
		CVE:         cves,
		FilePath:    loc,
		CVSS:        cvss,
		Metadata:    meta,
	}
}
