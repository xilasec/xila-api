package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/netguard"
)

// Trivy Operator reads its own scan results back from the Kubernetes API as
// custom resources, per its documented CRDs
// (https://aquasecurity.github.io/trivy-operator/latest/docs/crds/vulnerability-report/,
// .../config-audit-report/, .../exposed-secret-report/,
// .../rbac-assessment-report/): VulnerabilityReport (OS/app package CVEs in a
// container image), ConfigAuditReport and RbacAssessmentReport (Kubernetes
// posture checks against a workload), ExposedSecretReport (secrets found in an
// image layer). Every kind lists via the standard Kubernetes API
// (`GET {server}/apis/aquasecurity.github.io/v1alpha1/[namespaces/{ns}/]{resource}`,
// `?limit=…` paged by the API server's own `metadata.continue` token, like any
// Kubernetes list) and carries the scanned workload's identity in its
// `trivy-operator.resource.{kind,name,namespace}` / `.container.name` labels.
//
// Auth is either an explicit base_url (a kubeconfig's cluster server URL) with
// a sealed bearer token (+ optional CA, bundled in the same sealed JSON, like
// Wiz/Tenable's paired secrets) — a real, operator-chosen destination, so it
// goes through netguard like every other connector — or, when base_url is
// left empty, the connector's own pod's in-cluster service account
// (`KUBERNETES_SERVICE_HOST`/`_PORT` + the projected token and CA Kubernetes
// mounts into every pod). That destination is the cluster's own API server,
// not something an operator typed in, so it is not a netguard-checked URL;
// the production default policy blocks private-network destinations, which
// the in-cluster apiserver's ClusterIP always is.
//
// These CRDs carry no dismissal/ignore state of their own (an ignored finding
// is filtered out by Trivy itself before the report is written), so there is
// no remote triage mapping for this kind.
const (
	trivyGroupVersion      = "apis/aquasecurity.github.io/v1alpha1"
	trivyPageLimit         = 500
	trivyInClusterToken    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	trivyInClusterCA       = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	labelResourceKind      = "trivy-operator.resource.kind"
	labelResourceName      = "trivy-operator.resource.name"
	labelResourceNamespace = "trivy-operator.resource.namespace"
	labelContainerName     = "trivy-operator.container.name"
)

type trivyOperator struct {
	base, namespace, bearerToken string
	hc                           *http.Client
	// tokenPath/caPath are the in-cluster service account files used when
	// base == ""; overridden by tests, the real mounted paths in production.
	tokenPath, caPath string
}

type trivyCredentials struct {
	BearerToken string `json:"bearer_token"`
	CAPEM       string `json:"ca_pem"`
}

func parseTrivyCredentials(token string) (trivyCredentials, error) {
	var c trivyCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.BearerToken == "" {
		return trivyCredentials{}, invalid(`token must be JSON {"bearer_token": "...", "ca_pem": "..." (optional)}`)
	}
	return c, nil
}

// trivyTLSClient builds a netguard-wrapped client trusting an additional CA,
// for an explicit base_url whose Kubernetes API server presents a
// certificate signed by a private CA.
func trivyTLSClient(caPEM string) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, invalid("token's ca_pem is not a valid PEM certificate")
	}
	t := netguard.Transport()
	t.TLSClientConfig = &tls.Config{RootCAs: pool}
	return netguard.WrapTransport(t, clientTimeout), nil
}

// inClusterClient trusts the service account's own CA when present, else the
// system pool.
func inClusterClient(caPath string) *http.Client {
	var cfg tls.Config
	if ca, err := os.ReadFile(caPath); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(ca) {
			cfg.RootCAs = pool
		}
	}
	return &http.Client{Timeout: clientTimeout, Transport: &http.Transport{TLSClientConfig: &cfg}}
}

// resolve returns the API server, bearer token and client to use: the
// explicit config if base_url was set, else the pod's in-cluster service
// account.
func (t *trivyOperator) resolve() (apiServer, token string, hc *http.Client, err error) {
	if t.base != "" {
		return t.base, t.bearerToken, t.hc, nil
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	if host == "" {
		return "", "", nil, remoteErr("trivy-operator: not running in-cluster (KUBERNETES_SERVICE_HOST unset) and no base_url configured")
	}
	tok, err := os.ReadFile(t.tokenPath)
	if err != nil {
		return "", "", nil, remoteErr("trivy-operator: read in-cluster service account token: %v", err)
	}
	return "https://" + host + ":" + port, strings.TrimSpace(string(tok)), inClusterClient(t.caPath), nil
}

func (t *trivyOperator) listURL(apiServer, resource, cont string) string {
	ns := ""
	if t.namespace != "" {
		ns = "namespaces/" + t.namespace + "/"
	}
	u := fmt.Sprintf("%s/%s/%s%s?limit=%d", apiServer, trivyGroupVersion, ns, resource, trivyPageLimit)
	if cont != "" {
		u += "&continue=" + url.QueryEscape(cont)
	}
	return u
}

type trivyListMeta struct {
	Continue string `json:"continue"`
}

type trivyList[T any] struct {
	Metadata trivyListMeta `json:"metadata"`
	Items    []T           `json:"items"`
}

type trivyObjMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// trivyFetchAll pages one resource kind to completion; a failed page fails
// the whole call, like every other connector's Fetch.
func trivyFetchAll[T any](ctx context.Context, hc *http.Client, apiServer, token, resource string, t *trivyOperator) ([]T, error) {
	var out []T
	cont := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, remoteErr("trivy-operator: more than %d pages of %s", maxPages, resource)
		}
		var resp trivyList[T]
		if _, err := getJSON(ctx, hc, t.listURL(apiServer, resource, cont), "Authorization", "Bearer "+token, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Items...)
		if resp.Metadata.Continue == "" {
			break
		}
		cont = resp.Metadata.Continue
	}
	return out, nil
}

func (t *trivyOperator) Check(ctx context.Context) (string, error) {
	apiServer, token, hc, err := t.resolve()
	if err != nil {
		return "", err
	}
	var resp trivyList[trivyObjMeta]
	u := t.listURL(apiServer, "vulnerabilityreports", "") + "&limit=1"
	if _, err := getJSON(ctx, hc, u, "Authorization", "Bearer "+token, &resp); err != nil {
		return "", err
	}
	return "Trivy Operator", nil
}

type trivyVulnReport struct {
	Metadata trivyObjMeta `json:"metadata"`
	Report   struct {
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
			Digest     string `json:"digest"`
		} `json:"artifact"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"vulnerabilityID"`
			Resource         string   `json:"resource"`
			InstalledVersion string   `json:"installedVersion"`
			FixedVersion     string   `json:"fixedVersion"`
			Severity         string   `json:"severity"`
			Title            string   `json:"title"`
			PrimaryLink      string   `json:"primaryLink"`
			Score            *float64 `json:"score"`
		} `json:"vulnerabilities"`
	} `json:"report"`
}

type trivyConfigAuditReport struct {
	Metadata trivyObjMeta `json:"metadata"`
	Report   struct {
		Checks []struct {
			CheckID     string `json:"checkID"`
			Severity    string `json:"severity"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Category    string `json:"category"`
			Success     bool   `json:"success"`
			Remediation string `json:"remediation"`
		} `json:"checks"`
	} `json:"report"`
}

type trivyExposedSecretReport struct {
	Metadata trivyObjMeta `json:"metadata"`
	Report   struct {
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"artifact"`
		Secrets []struct {
			RuleID   string `json:"ruleID"`
			Category string `json:"category"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Target   string `json:"target"`
		} `json:"secrets"`
	} `json:"report"`
}

type trivyRbacAssessmentReport struct {
	Metadata trivyObjMeta `json:"metadata"`
	Report   struct {
		Checks []struct {
			CheckID     string `json:"checkID"`
			Severity    string `json:"severity"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Category    string `json:"category"`
			Success     bool   `json:"success"`
		} `json:"checks"`
	} `json:"report"`
}

// trivyWorkload resolves the scanned workload's location ("namespace/kind/name
// [/container]") and the matching metadata from a report's labels.
func trivyWorkload(labels map[string]string, namespace string) (string, map[string]any) {
	ns := labels[labelResourceNamespace]
	if ns == "" {
		ns = namespace
	}
	kind, name := labels[labelResourceKind], labels[labelResourceName]
	loc := strings.Join(trivyNonEmpty(ns, kind, name), "/")
	meta := map[string]any{"namespace": ns}
	if kind != "" {
		meta["workload_kind"] = kind
	}
	if name != "" {
		meta["workload_name"] = name
	}
	if container := labels[labelContainerName]; container != "" {
		meta["container"] = container
		loc += "/" + container
	}
	return loc, meta
}

func trivyNonEmpty(ss ...string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func trivyVulnFindings(r trivyVulnReport) []finding.Finding {
	loc, meta := trivyWorkload(r.Metadata.Labels, r.Metadata.Namespace)
	meta["source"] = "trivy-operator"
	meta["report"] = "vulnerability"
	if r.Report.Artifact.Repository != "" {
		meta["image"] = r.Report.Artifact.Repository + ":" + r.Report.Artifact.Tag
	}
	out := make([]finding.Finding, 0, len(r.Report.Vulnerabilities))
	for _, v := range r.Report.Vulnerabilities {
		sev, ok := mapSeverity(v.Severity)
		if !ok {
			sev = domain.SeverityInfo
		}
		out = append(out, finding.Finding{
			Fingerprint:    fingerprint(KindTrivyOperator, "vuln|"+r.Metadata.Namespace+"|"+r.Metadata.Name+"|"+v.VulnerabilityID+"|"+v.Resource),
			Category:       domain.CategoryContainer,
			RuleID:         v.VulnerabilityID,
			Title:          cmp(v.Title, v.VulnerabilityID),
			Severity:       sev,
			CVE:            addCVE(nil, v.VulnerabilityID),
			PackageName:    v.Resource,
			PackageVersion: v.InstalledVersion,
			FixedVersion:   v.FixedVersion,
			CVSS:           v.Score,
			URL:            v.PrimaryLink,
			FilePath:       loc,
			Metadata:       cloneMeta(meta),
		})
	}
	return out
}

func trivyConfigFindings(r trivyConfigAuditReport) []finding.Finding {
	loc, meta := trivyWorkload(r.Metadata.Labels, r.Metadata.Namespace)
	meta["source"] = "trivy-operator"
	meta["report"] = "config-audit"
	out := make([]finding.Finding, 0, len(r.Report.Checks))
	for _, c := range r.Report.Checks {
		if c.Success {
			continue
		}
		sev, ok := mapSeverity(c.Severity)
		if !ok {
			sev = domain.SeverityInfo
		}
		out = append(out, finding.Finding{
			Fingerprint: fingerprint(KindTrivyOperator, "conf|"+r.Metadata.Namespace+"|"+r.Metadata.Name+"|"+c.CheckID),
			Category:    domain.CategoryKubernetes,
			RuleID:      c.CheckID,
			Title:       c.Title,
			Description: withSection(c.Description, "Remediation", c.Remediation),
			Severity:    sev,
			FilePath:    loc,
			Metadata:    cloneMeta(meta),
		})
	}
	return out
}

func trivySecretFindings(r trivyExposedSecretReport) []finding.Finding {
	loc, meta := trivyWorkload(r.Metadata.Labels, r.Metadata.Namespace)
	meta["source"] = "trivy-operator"
	meta["report"] = "exposed-secret"
	if r.Report.Artifact.Repository != "" {
		meta["image"] = r.Report.Artifact.Repository + ":" + r.Report.Artifact.Tag
	}
	out := make([]finding.Finding, 0, len(r.Report.Secrets))
	for _, s := range r.Report.Secrets {
		sev, ok := mapSeverity(s.Severity)
		if !ok {
			sev = domain.SeverityInfo
		}
		out = append(out, finding.Finding{
			Fingerprint: fingerprint(KindTrivyOperator, "secret|"+r.Metadata.Namespace+"|"+r.Metadata.Name+"|"+s.RuleID+"|"+s.Target),
			Category:    domain.CategorySecret,
			RuleID:      s.RuleID,
			Title:       s.Title,
			Description: "Category: " + s.Category,
			Severity:    sev,
			FilePath:    strings.TrimPrefix(loc+"/"+s.Target, "/"),
			Metadata:    cloneMeta(meta),
		})
	}
	return out
}

func trivyRbacFindings(r trivyRbacAssessmentReport) []finding.Finding {
	loc, meta := trivyWorkload(r.Metadata.Labels, r.Metadata.Namespace)
	meta["source"] = "trivy-operator"
	meta["report"] = "rbac-assessment"
	out := make([]finding.Finding, 0, len(r.Report.Checks))
	for _, c := range r.Report.Checks {
		if c.Success {
			continue
		}
		sev, ok := mapSeverity(c.Severity)
		if !ok {
			sev = domain.SeverityInfo
		}
		out = append(out, finding.Finding{
			Fingerprint: fingerprint(KindTrivyOperator, "rbac|"+r.Metadata.Namespace+"|"+r.Metadata.Name+"|"+c.CheckID),
			Category:    domain.CategoryKubernetes,
			RuleID:      c.CheckID,
			Title:       c.Title,
			Description: c.Description,
			Severity:    sev,
			FilePath:    loc,
			Metadata:    cloneMeta(meta),
		})
	}
	return out
}

func (t *trivyOperator) Fetch(ctx context.Context) ([]finding.Finding, error) {
	apiServer, token, hc, err := t.resolve()
	if err != nil {
		return nil, err
	}
	vulns, err := trivyFetchAll[trivyVulnReport](ctx, hc, apiServer, token, "vulnerabilityreports", t)
	if err != nil {
		return nil, err
	}
	configs, err := trivyFetchAll[trivyConfigAuditReport](ctx, hc, apiServer, token, "configauditreports", t)
	if err != nil {
		return nil, err
	}
	secrets, err := trivyFetchAll[trivyExposedSecretReport](ctx, hc, apiServer, token, "exposedsecretreports", t)
	if err != nil {
		return nil, err
	}
	rbac, err := trivyFetchAll[trivyRbacAssessmentReport](ctx, hc, apiServer, token, "rbacassessmentreports", t)
	if err != nil {
		return nil, err
	}

	out := []finding.Finding{}
	for _, r := range vulns {
		out = append(out, trivyVulnFindings(r)...)
	}
	for _, r := range configs {
		out = append(out, trivyConfigFindings(r)...)
	}
	for _, r := range secrets {
		out = append(out, trivySecretFindings(r)...)
	}
	for _, r := range rbac {
		out = append(out, trivyRbacFindings(r)...)
	}
	return uniqueByFingerprint(out), nil
}

// Category is Kubernetes (KSPM) by default — config-audit and RBAC checks are
// posture, the bulk of what a cluster-wide pull reports — with image
// vulnerabilities and exposed secrets narrowing per finding.
func (t *trivyOperator) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategoryKubernetes)
}

func cmp(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func cloneMeta(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
