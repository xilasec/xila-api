package sbom_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

// aiInventory is a snapshot's AI components by name, without per-snapshot
// identity.
func aiInventory(t *testing.T, repo *sbom.Repository, id string) map[string]sbom.Component {
	t.Helper()
	comps, err := repo.SnapshotComponents(context.Background(), id)
	if err != nil {
		t.Fatalf("components: %v", err)
	}
	out := map[string]sbom.Component{}
	for _, c := range comps {
		if !sbom.IsAIKind(c.Kind) {
			continue
		}
		k := c.Component
		k.ID, k.SbomID, k.ProjectID, k.CreatedAt = "", "", "", time.Time{}
		out[c.Name] = k
	}
	return out
}

// TestMLBOMStoredFilteredAndRoundTripped: an ML-BOM upload stores each
// component's kind and model card; ?kind= lists the AI inventory; the BOM
// export writes models with their model cards and AI services only as
// services, and re-uploads to the same AI inventory.
func TestMLBOMStoredFilteredAndRoundTripped(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	svc := sbom.NewService(repo, project.NewRepository(pool), nil, nil)
	source := seedProject(t, pool, "ml")
	snap := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: source}, "mlbom-app.cdx.json")
	if snap.ComponentCount != 5 {
		t.Errorf("component_count = %d, want 5 (3 components + 2 AI services)", snap.ComponentCount)
	}

	app := fiber.New()
	sbom.NewHandler(repo, svc).Register(app)
	get := func(path string) (int, []byte) {
		t.Helper()
		res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), -1)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, body
	}
	list := func(query string) map[string]sbom.ComponentHit {
		t.Helper()
		code, body := get("/sboms/" + snap.ID + "/components?" + query)
		if code != 200 {
			t.Fatalf("list ?%s = %d: %s", query, code, body)
		}
		var resp struct{ Components []sbom.ComponentHit }
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		out := map[string]sbom.ComponentHit{}
		for _, c := range resp.Components {
			out[c.Name] = c
		}
		return out
	}
	ai := list("kind=ai")
	if len(ai) != 4 || ai["transformers"].Name != "" {
		t.Fatalf("AI inventory = %v, want model, dataset and two AI services", keys(ai))
	}
	model := ai["Mistral-7B-Instruct-v0.2"]
	if model.Kind != sbom.KindModel || model.ML == nil || model.ML.Task != "text-generation" ||
		model.ML.Supplier != "Hugging Face" || len(model.ML.Datasets) != 2 || model.ML.ExternalRefs[0].URL != "https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.2" ||
		model.License != "Apache-2.0" {
		t.Errorf("stored model = %+v / %+v", model, model.ML)
	}
	if got := list("kind=ai-service"); len(got) != 2 || got["OpenAI Chat Completions"].ML.Supplier != "OpenAI" {
		t.Errorf("AI services = %v", keys(got))
	}
	if got := list("kind=software"); len(got) != 1 || got["transformers"].ML != nil {
		t.Errorf("software = %v, want transformers without ML facts", keys(got))
	}
	if code, _ := get("/sboms/" + snap.ID + "/components?kind=llm"); code != 400 {
		t.Errorf("unknown kind = %d, want 400", code)
	}

	// The graph shows each AI service once, as the service.
	code, body := get("/sboms/" + snap.ID + "/graph")
	if code != 200 {
		t.Fatalf("graph = %d: %s", code, body)
	}
	var g sbom.Graph
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	for _, n := range g.Nodes {
		if n.Ref == "openai-api" && n.Kind != "service" {
			t.Errorf("openai-api node kind = %q, want service", n.Kind)
		}
	}

	code, body = get("/sboms/" + snap.ID + "/export?vulnerabilities=false")
	if code != 200 {
		t.Fatalf("export = %d: %s", code, body)
	}
	var doc struct {
		Components []struct {
			BomRef    string `json:"bom-ref"`
			Type      string
			Supplier  *struct{ Name string }
			ModelCard *struct {
				ModelParameters struct {
					Task     string
					Datasets []map[string]any
				}
			}
		}
		Services []struct {
			BomRef string `json:"bom-ref"`
		}
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(doc.Components) != 3 || len(doc.Services) != 3 {
		t.Fatalf("export = %d components / %d services, want 3 / 3 (AI services only as services)", len(doc.Components), len(doc.Services))
	}
	for _, c := range doc.Components {
		if c.BomRef != "mistral-7b-instruct" {
			continue
		}
		if c.Type != "machine-learning-model" || c.Supplier == nil || c.Supplier.Name != "Hugging Face" || c.ModelCard == nil ||
			c.ModelCard.ModelParameters.Task != "text-generation" ||
			!reflect.DeepEqual(c.ModelCard.ModelParameters.Datasets[0], map[string]any{"ref": "support-tickets"}) {
			t.Errorf("exported model = %+v", c)
		}
	}

	target := seedProject(t, pool, "ml-copy")
	again, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: target}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	want, got := aiInventory(t, repo, snap.ID), aiInventory(t, repo, again.ID)
	if len(want) != 4 {
		t.Fatalf("source AI inventory = %d, want 4", len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AI inventory differs after round trip:\n got %+v\nwant %+v", got, want)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
