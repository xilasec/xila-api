package sbom

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrVersionNotFound is returned when a named project version (branch or
// release) does not exist.
var ErrVersionNotFound = errors.New("project version not found")

// BomService is one service a CycloneDX BOM declares (`services`, spec 1.2+): an
// API, queue or data store the software talks to. Nested services are
// flattened; ParentRef is the enclosing service's bom-ref ("" at top level).
// Service dependency edges live in the snapshot's graph (Edges), keyed by
// BomRef like components'.
type BomService struct {
	ID        string `json:"id"`
	SbomID    string `json:"sbom_id"`
	ProjectID string `json:"project_id"`
	// Artifact is the snapshot's subject (read back only).
	Artifact    string   `json:"artifact"`
	BomRef      string   `json:"bom_ref"`
	ParentRef   string   `json:"parent_ref"`
	Group       string   `json:"group"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Provider    string   `json:"provider"` // provider organization name
	ProviderURL []string `json:"provider_urls"`
	Endpoints   []string `json:"endpoints"`
	// Authenticated and TrustBoundary (x-trust-boundary) are nil when the
	// document doesn't say — unknown, never assumed either way.
	Authenticated *bool         `json:"authenticated"`
	TrustBoundary *bool         `json:"trust_boundary"`
	TrustZone     string        `json:"trust_zone"` // trustZone (1.5+)
	License       string        `json:"license"`
	Data          []DataFlow    `json:"data"`
	ExternalRefs  []ExternalRef `json:"external_references"`
	Properties    []Property    `json:"properties"`
	CreatedAt     time.Time     `json:"created_at"`

	// Computed over the whole snapshot by FlagServices (not stored).
	//
	// CrossesTrustBoundary: the document says the service crosses a trust
	// boundary (x-trust-boundary), or one of its data flows reaches a service
	// in a different trust zone.
	CrossesTrustBoundary bool `json:"crosses_trust_boundary"`
	// UnauthenticatedExternal: explicitly unauthenticated (authenticated=false)
	// and reachable over an http(s) endpoint.
	UnauthenticatedExternal bool `json:"unauthenticated_external"`
}

// DataFlow is one data classification flowing through a service. CycloneDX ≤1.4
// carries only Flow + Classification; 1.5+ adds the rest. Flow is relative to
// the service: inbound, outbound, bi-directional or unknown.
type DataFlow struct {
	Flow           string          `json:"flow"`
	Classification string          `json:"classification"`
	Name           string          `json:"name,omitempty"`
	Description    string          `json:"description,omitempty"`
	Governance     json.RawMessage `json:"governance,omitempty"`
	// Source/Destination are URLs or BOM-Links (urn:cdx:serial/version#bom-ref).
	Source      []string `json:"source,omitempty"`
	Destination []string `json:"destination,omitempty"`
	// CrossesTrustZone (computed): a source or destination resolves to a
	// service of this snapshot in a different trust zone than this one.
	CrossesTrustZone bool `json:"crosses_trust_zone"`
}

// storedDataFlow is DataFlow as stored (and exported): CycloneDX's serviceData
// shape, without the computed flag.
type storedDataFlow struct {
	Flow           string          `json:"flow"`
	Classification string          `json:"classification"`
	Name           string          `json:"name,omitempty"`
	Description    string          `json:"description,omitempty"`
	Governance     json.RawMessage `json:"governance,omitempty"`
	Source         []string        `json:"source,omitempty"`
	Destination    []string        `json:"destination,omitempty"`
}

func storedFlows(fs []DataFlow) []storedDataFlow {
	out := make([]storedDataFlow, 0, len(fs))
	for _, f := range fs {
		out = append(out, storedDataFlow{Flow: f.Flow, Classification: f.Classification, Name: f.Name,
			Description: f.Description, Governance: f.Governance, Source: f.Source, Destination: f.Destination})
	}
	return out
}

// ExternalRef is a CycloneDX external reference (documentation, website, …).
type ExternalRef struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// Property is a CycloneDX name/value property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// --- CycloneDX parsing ---

type cycloneServiceProvider struct {
	Name string   `json:"name"`
	URL  []string `json:"url"`
}

type cycloneService struct {
	BomRef             string                  `json:"bom-ref"`
	Provider           *cycloneServiceProvider `json:"provider"`
	Group              string                  `json:"group"`
	Name               string                  `json:"name"`
	Version            string                  `json:"version"`
	Description        string                  `json:"description"`
	Endpoints          []string                `json:"endpoints"`
	Authenticated      *bool                   `json:"authenticated"`
	TrustBoundary      *bool                   `json:"x-trust-boundary"`
	TrustZone          string                  `json:"trustZone"`
	Data               []cycloneServiceData    `json:"data"`
	Licenses           []cycloneLicense        `json:"licenses"`
	ExternalReferences []ExternalRef           `json:"externalReferences"`
	Properties         []Property              `json:"properties"`
	Services           []cycloneService        `json:"services"`
}

// cycloneServiceData reads both data shapes: ≤1.4 dataClassification
// {flow, classification} and 1.5+ serviceData, a superset of it.
type cycloneServiceData struct {
	Flow           string          `json:"flow"`
	Classification string          `json:"classification"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Governance     json.RawMessage `json:"governance"`
	Source         []string        `json:"source"`
	Destination    []string        `json:"destination"`
}

// flattenServices walks the (possibly nested) services in document order,
// recording each nested service's parent bom-ref. A parent without a bom-ref
// gets a synthetic one so its children stay attached to it.
func flattenServices(svcs []cycloneService) []BomService {
	var out []BomService
	var walk func(list []cycloneService, parent string)
	walk = func(list []cycloneService, parent string) {
		for _, cs := range list {
			if cs.Name == "" {
				continue // name is the one required field; nothing to show without it
			}
			ref := cs.BomRef
			if ref == "" && len(cs.Services) > 0 {
				ref = "xila:service:" + strconv.Itoa(len(out))
			}
			s := BomService{
				BomRef: ref, ParentRef: parent, Group: cs.Group, Name: cs.Name, Version: cs.Version,
				Description: cs.Description, Endpoints: nonNil(cs.Endpoints),
				Authenticated: cs.Authenticated, TrustBoundary: cs.TrustBoundary, TrustZone: cs.TrustZone,
				License: licenseString(cs.Licenses), Data: []DataFlow{},
				ExternalRefs: nonNil(cs.ExternalReferences), Properties: nonNil(cs.Properties),
				ProviderURL: []string{},
			}
			if cs.Provider != nil {
				s.Provider, s.ProviderURL = cs.Provider.Name, nonNil(cs.Provider.URL)
			}
			for _, d := range cs.Data {
				s.Data = append(s.Data, DataFlow{Flow: normalizeFlow(d.Flow), Classification: d.Classification,
					Name: d.Name, Description: d.Description, Governance: d.Governance,
					Source: d.Source, Destination: d.Destination})
			}
			out = append(out, s)
			walk(cs.Services, ref)
		}
	}
	walk(svcs, "")
	return out
}

// normalizeFlow maps a data flow direction onto CycloneDX's enumeration; an
// unrecognized one is "unknown" rather than guessed.
func normalizeFlow(f string) string {
	switch f = strings.ToLower(strings.TrimSpace(f)); f {
	case "inbound", "outbound", "bi-directional":
		return f
	case "bidirectional", "bi_directional", "both":
		return "bi-directional"
	}
	return "unknown"
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// --- computed flags ---

// FlagServices computes CrossesTrustBoundary and UnauthenticatedExternal (and
// each flow's CrossesTrustZone) for one snapshot's services. A flow's peer
// resolves to a service of the snapshot by BOM-Link fragment, bare bom-ref or
// endpoint URL; a peer that resolves to nothing (an outside URL) has no known
// zone and never counts as a crossing. Pure.
func FlagServices(svcs []BomService) {
	byRef, byEndpoint := map[string]string{}, map[string]string{}
	for _, s := range svcs {
		if s.TrustZone == "" {
			continue
		}
		if s.BomRef != "" {
			byRef[s.BomRef] = s.TrustZone
		}
		for _, e := range s.Endpoints {
			byEndpoint[endpointKey(e)] = s.TrustZone
		}
	}
	zoneOf := func(peer string) (string, bool) {
		if ref, ok := bomLinkRef(peer); ok {
			z, ok := byRef[ref]
			return z, ok
		}
		if z, ok := byRef[peer]; ok {
			return z, true
		}
		z, ok := byEndpoint[endpointKey(peer)]
		return z, ok
	}
	for i := range svcs {
		s := &svcs[i]
		s.UnauthenticatedExternal = s.Authenticated != nil && !*s.Authenticated && slices.ContainsFunc(s.Endpoints, isHTTPEndpoint)
		s.CrossesTrustBoundary = s.TrustBoundary != nil && *s.TrustBoundary
		for j := range s.Data {
			d := &s.Data[j]
			d.CrossesTrustZone = false
			if s.TrustZone == "" {
				continue
			}
			for _, peer := range slices.Concat(d.Source, d.Destination) {
				if z, ok := zoneOf(peer); ok && z != s.TrustZone {
					d.CrossesTrustZone = true
					break
				}
			}
			s.CrossesTrustBoundary = s.CrossesTrustBoundary || d.CrossesTrustZone
		}
	}
}

// bomLinkRef extracts the bom-ref a CycloneDX BOM-Link element
// (urn:cdx:<serial>/<version>#<bom-ref>) points at.
func bomLinkRef(s string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(s), "urn:cdx:") {
		return "", false
	}
	_, frag, ok := strings.Cut(s, "#")
	if !ok || frag == "" {
		return "", false
	}
	if u, err := url.PathUnescape(frag); err == nil {
		frag = u
	}
	return frag, true
}

func endpointKey(e string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(e)), "/")
}

func isHTTPEndpoint(e string) bool {
	e = strings.ToLower(strings.TrimSpace(e))
	return strings.HasPrefix(e, "http://") || strings.HasPrefix(e, "https://")
}

// --- storage ---

// insertServices bulk-loads a snapshot's services inside its ingest transaction.
func insertServices(ctx context.Context, tx pgx.Tx, sbomID, projectID string, svcs []BomService) error {
	if len(svcs) == 0 {
		return nil
	}
	rows := make([][]any, len(svcs))
	for i, s := range svcs {
		rows[i] = []any{sbomID, projectID, i, s.BomRef, s.ParentRef, s.Group, s.Name, s.Version, s.Description,
			s.Provider, nonNil(s.ProviderURL), nonNil(s.Endpoints), s.Authenticated, s.TrustBoundary, s.TrustZone,
			s.License, storedFlows(s.Data), nonNil(s.ExternalRefs), nonNil(s.Properties)}
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"sbom_services"},
		[]string{"sbom_id", "project_id", "position", "bom_ref", "parent_ref", "group", "name", "version", "description",
			"provider", "provider_urls", "endpoints", "authenticated", "trust_boundary", "trust_zone",
			"license", "data", "external_refs", "properties"},
		pgx.CopyFromRows(rows))
	if err != nil {
		return fmt.Errorf("copy services: %w", err)
	}
	return nil
}

const serviceColumns = `sv.id, sv.sbom_id, sv.project_id, s.artifact, sv.bom_ref, sv.parent_ref, sv."group",
	sv.name, sv.version, sv.description, sv.provider, sv.provider_urls, sv.endpoints, sv.authenticated,
	sv.trust_boundary, sv.trust_zone, sv.license, sv.data, sv.external_refs, sv.properties, sv.created_at`

func (r *Repository) queryServices(ctx context.Context, q string, args ...any) ([]BomService, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	defer rows.Close()
	out := []BomService{}
	for rows.Next() {
		var s BomService
		if err := rows.Scan(&s.ID, &s.SbomID, &s.ProjectID, &s.Artifact, &s.BomRef, &s.ParentRef, &s.Group,
			&s.Name, &s.Version, &s.Description, &s.Provider, &s.ProviderURL, &s.Endpoints, &s.Authenticated,
			&s.TrustBoundary, &s.TrustZone, &s.License, &s.Data, &s.ExternalRefs, &s.Properties, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		s.Data, s.ExternalRefs, s.Properties = nonNil(s.Data), nonNil(s.ExternalRefs), nonNil(s.Properties)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Flags are judged per snapshot: trust zones are the document's own names.
	for start := 0; start < len(out); {
		end := start + 1
		for end < len(out) && out[end].SbomID == out[start].SbomID {
			end++
		}
		FlagServices(out[start:end])
		start = end
	}
	return out, nil
}

// SnapshotServices returns one snapshot's services in document order, flagged.
func (r *Repository) SnapshotServices(ctx context.Context, sbomID string) ([]BomService, error) {
	return r.queryServices(ctx, `SELECT `+serviceColumns+` FROM sbom_services sv JOIN sboms s ON s.id = sv.sbom_id
		WHERE sv.sbom_id = $1 ORDER BY sv.position`, sbomID)
}

// ProjectServices returns the services of a project version's current
// snapshots (the newest per artifact), flagged. versionName "" is the default
// version; a named version that doesn't exist is ErrVersionNotFound.
func (r *Repository) ProjectServices(ctx context.Context, projectID, versionName string) ([]BomService, error) {
	var versionID string
	err := r.db.QueryRow(ctx, `SELECT id FROM project_versions WHERE project_id = $1
		AND (($2 = '' AND is_default) OR ($2 <> '' AND name = $2))`, projectID, versionName).Scan(&versionID)
	switch {
	case errors.Is(err, pgx.ErrNoRows) && versionName == "":
		return []BomService{}, nil // nothing uploaded yet
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrVersionNotFound
	case err != nil:
		return nil, fmt.Errorf("resolve version: %w", err)
	}
	return r.queryServices(ctx, `SELECT `+serviceColumns+` FROM sbom_services sv JOIN sboms s ON s.id = sv.sbom_id
		WHERE sv.sbom_id IN (
			SELECT DISTINCT ON (artifact) id FROM sboms WHERE project_id = $1 AND version_id = $2
			ORDER BY artifact, created_at DESC, id DESC)
		ORDER BY s.artifact, sv.sbom_id, sv.position`, projectID, versionID)
}

// ServiceSummary counts a service list and its warnings.
type ServiceSummary struct {
	Total                   int `json:"total"`
	UnauthenticatedExternal int `json:"unauthenticated_external"`
	CrossesTrustBoundary    int `json:"crosses_trust_boundary"`
}

// SummarizeServices counts flagged services. Pure.
func SummarizeServices(svcs []BomService) ServiceSummary {
	sum := ServiceSummary{Total: len(svcs)}
	for _, s := range svcs {
		if s.UnauthenticatedExternal {
			sum.UnauthenticatedExternal++
		}
		if s.CrossesTrustBoundary {
			sum.CrossesTrustBoundary++
		}
	}
	return sum
}

// --- diff ---

// DataClass is a data classification and the direction it flows in.
type DataClass struct {
	Flow           string `json:"flow"`
	Classification string `json:"classification"`
}

// ServiceDiff is one service that differs between base and head. A service is
// identified by group/name (bom-refs are often per-document UUIDs). For an
// added service the *To/…Added fields describe it; for a removed one the
// *From/…Removed fields. Fields lists what changed on a changed one: version,
// endpoints, authenticated, trust_boundary, trust_zone, data.
type ServiceDiff struct {
	Key               string      `json:"key"`
	Name              string      `json:"name"`
	Group             string      `json:"group"`
	Change            Change      `json:"change"` // added, removed or changed
	Fields            []string    `json:"fields"`
	VersionFrom       string      `json:"version_from"`
	VersionTo         string      `json:"version_to"`
	EndpointsAdded    []string    `json:"endpoints_added"`
	EndpointsRemoved  []string    `json:"endpoints_removed"`
	AuthenticatedFrom *bool       `json:"authenticated_from"`
	AuthenticatedTo   *bool       `json:"authenticated_to"`
	TrustBoundaryFrom *bool       `json:"trust_boundary_from"`
	TrustBoundaryTo   *bool       `json:"trust_boundary_to"`
	TrustZoneFrom     string      `json:"trust_zone_from"`
	TrustZoneTo       string      `json:"trust_zone_to"`
	DataAdded         []DataClass `json:"data_added"`
	DataRemoved       []DataClass `json:"data_removed"`
}

func serviceKeys(svcs []BomService) (map[string]BomService, []string) {
	out := make(map[string]BomService, len(svcs))
	keys := make([]string, 0, len(svcs))
	for _, s := range svcs {
		k := strings.ToLower(s.Group + "/" + s.Name)
		if _, dup := out[k]; dup {
			// Two services of one name (e.g. one per parent): tell them apart by ref.
			k += "#" + s.BomRef
		}
		if _, dup := out[k]; dup {
			continue
		}
		out[k] = s
		keys = append(keys, k)
	}
	return out, keys
}

func dataClasses(fs []DataFlow) []DataClass {
	out := []DataClass{}
	for _, f := range fs {
		c := DataClass{Flow: f.Flow, Classification: f.Classification}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b DataClass) int {
		return cmp.Or(strings.Compare(a.Classification, b.Classification), strings.Compare(a.Flow, b.Flow))
	})
	return out
}

func minusClasses(a, b []DataClass) []DataClass {
	out := []DataClass{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func sameBool(a, b *bool) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// DiffServices compares two snapshots' services. Changes come sorted by key.
// Pure.
func DiffServices(base, head []BomService) []ServiceDiff {
	b, bKeys := serviceKeys(base)
	h, hKeys := serviceKeys(head)
	keys := slices.Clone(bKeys)
	for _, k := range hKeys {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	out := []ServiceDiff{}
	for _, k := range keys {
		bs, inBase := b[k]
		hs, inHead := h[k]
		sample := hs
		if !inHead {
			sample = bs
		}
		d := ServiceDiff{Key: k, Name: sample.Name, Group: sample.Group, Fields: []string{},
			EndpointsAdded: []string{}, EndpointsRemoved: []string{}, DataAdded: []DataClass{}, DataRemoved: []DataClass{}}
		if inBase {
			d.VersionFrom, d.AuthenticatedFrom, d.TrustBoundaryFrom, d.TrustZoneFrom =
				bs.Version, bs.Authenticated, bs.TrustBoundary, bs.TrustZone
		}
		if inHead {
			d.VersionTo, d.AuthenticatedTo, d.TrustBoundaryTo, d.TrustZoneTo =
				hs.Version, hs.Authenticated, hs.TrustBoundary, hs.TrustZone
		}
		d.EndpointsAdded, d.EndpointsRemoved = minus(nonNil(hs.Endpoints), nonNil(bs.Endpoints)), minus(nonNil(bs.Endpoints), nonNil(hs.Endpoints))
		bc, hc := dataClasses(bs.Data), dataClasses(hs.Data)
		d.DataAdded, d.DataRemoved = minusClasses(hc, bc), minusClasses(bc, hc)
		switch {
		case !inBase:
			d.Change = ChangeAdded
		case !inHead:
			d.Change = ChangeRemoved
		default:
			d.Change = ChangeChanged
			if bs.Version != hs.Version {
				d.Fields = append(d.Fields, "version")
			}
			if len(d.EndpointsAdded)+len(d.EndpointsRemoved) > 0 {
				d.Fields = append(d.Fields, "endpoints")
			}
			if !sameBool(bs.Authenticated, hs.Authenticated) {
				d.Fields = append(d.Fields, "authenticated")
			}
			if !sameBool(bs.TrustBoundary, hs.TrustBoundary) {
				d.Fields = append(d.Fields, "trust_boundary")
			}
			if bs.TrustZone != hs.TrustZone {
				d.Fields = append(d.Fields, "trust_zone")
			}
			if len(d.DataAdded)+len(d.DataRemoved) > 0 {
				d.Fields = append(d.Fields, "data")
			}
			if len(d.Fields) == 0 {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

// countServices adds the service changes to the summary.
func (sum *DiffSummary) countServices(ds []ServiceDiff) {
	for _, d := range ds {
		switch d.Change {
		case ChangeAdded:
			sum.ServicesAdded++
		case ChangeRemoved:
			sum.ServicesRemoved++
		default:
			sum.ServicesChanged++
		}
	}
}
