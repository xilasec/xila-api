package sbom_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

// invalidCycloneDX has a component type outside the schema's enum
// ("not-a-real-type"), invalid under strict validation but accepted
// leniently (this package never reads component.type against an enum).
const invalidCycloneDX = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
	"version": 1,
	"metadata": {"component": {"type": "application", "name": "demo"}},
	"components": [{"type": "not-a-real-type", "name": "left-pad", "version": "1.0.0"}]
}`

func TestIngestStrictRejectsInvalidDocument(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	projects := project.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "strict-web")

	svc := sbom.NewService(repo, projects, nil, nil)

	// Lenient (default): the document is still stored.
	if _, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(invalidCycloneDX)); err != nil {
		t.Fatalf("lenient upload: %v", err)
	}

	// Opt-in strict (?strict=true): rejected, with a field error pointing at
	// the exact bad component.
	_, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID, Strict: true}, strings.NewReader(invalidCycloneDX))
	var strictErr *sbom.StrictValidationError
	if !errors.As(err, &strictErr) {
		t.Fatalf("expected a *StrictValidationError, got %v", err)
	}
	if len(strictErr.Fields) == 0 {
		t.Fatal("expected at least one field error")
	}
	var sawPath bool
	for _, f := range strictErr.Fields {
		if f.Path == "/components/0/type" {
			sawPath = true
		}
	}
	if !sawPath {
		t.Errorf("expected a field error at /components/0/type, got %+v", strictErr.Fields)
	}
}

func TestIngestStrictDefaultRejectsEvenWithoutQueryParam(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	projects := project.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "strict-default")

	// SBOM_STRICT_VALIDATION=true: every upload is strict, even without
	// ?strict=true on the request.
	svc := sbom.NewService(repo, projects, nil, nil).WithStrictValidation(true)

	_, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(invalidCycloneDX))
	if _, ok := errors.AsType[*sbom.StrictValidationError](err); !ok {
		t.Fatalf("expected a *StrictValidationError, got %v", err)
	}
}

func TestIngestStrictAcceptsValidDocument(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	projects := project.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "strict-valid")

	svc := sbom.NewService(repo, projects, nil, nil).WithStrictValidation(true)
	valid := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"metadata": {"component": {"type": "application", "name": "demo"}},
		"components": [{"type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}]
	}`
	if _, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(valid)); err != nil {
		t.Fatalf("strict upload of a valid document: %v", err)
	}
}

// CycloneDX XML ingests like JSON, but the schema validator only checks JSON:
// strict mode, asked for per request or instance-wide, refuses XML with a
// clear error and stores nothing rather than skipping validation.
func TestIngestXML(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	projects := project.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "xml")
	xml := `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>
		<component type="library"><name>left-pad</name><version>1.0.0</version><purl>pkg:npm/left-pad@1.0.0</purl></component>
	</components></bom>`

	lenient := sbom.NewService(repo, projects, nil, nil)
	if _, err := lenient.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID, Strict: true}, strings.NewReader(xml)); !errors.Is(err, sbom.ErrStrictXMLUnsupported) {
		t.Errorf("?strict=true with XML = %v, want ErrStrictXMLUnsupported", err)
	}
	strict := sbom.NewService(repo, projects, nil, nil).WithStrictValidation(true)
	if _, err := strict.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(xml)); !errors.Is(err, sbom.ErrStrictXMLUnsupported) {
		t.Errorf("SBOM_STRICT_VALIDATION with XML = %v, want ErrStrictXMLUnsupported", err)
	}
	if got, err := repo.ListByProject(ctx, projectID, ""); err != nil || len(got) != 0 {
		t.Fatalf("a refused upload stored %d snapshots (err %v)", len(got), err)
	}

	stored, err := lenient.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(xml))
	if err != nil {
		t.Fatalf("lenient XML upload: %v", err)
	}
	if stored.ComponentCount != 1 {
		t.Errorf("components = %d, want 1", stored.ComponentCount)
	}
}
