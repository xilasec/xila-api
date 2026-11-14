package sbom

import (
	"reflect"
	"slices"
	"testing"
)

// ML-BOM fixtures in testdata:
//
//   - machine-learning-1.6.cdx.json, machine-learning-env-1.6.cdx.json,
//     component-data-1.6.cdx.json: real, unmodified CycloneDX documents from the
//     specification repository (https://github.com/CycloneDX/specification,
//     Apache-2.0), tools/src/test/resources/1.6/valid-machine-learning-1.6.json,
//     valid-machine-learning-considerations-env-1.6.json and
//     valid-component-data-1.6.json. (CycloneDX's bom-examples repository has
//     no ML-BOM; these are the project's own ML-BOM samples.)
//   - mlbom-app.cdx.json: hand-written to the CycloneDX 1.6 schema — an
//     application with a model whose card references a data component, and
//     three services (one serving the model, one calling OpenAI, one not AI).

func TestParseMLBOMSpecSample(t *testing.T) {
	doc := parseFixture(t, "machine-learning-1.6.cdx.json")
	if len(doc.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(doc.Components))
	}
	c := doc.Components[0]
	if c.Kind != KindModel || c.Type != "machine-learning-model" || c.Group != "CompVis" || c.Name != "stable-diffusion" || c.Version != "1.4" {
		t.Fatalf("model = %+v", c)
	}
	want := &MLFacts{
		Publisher:          "Acme Inc",
		Description:        c.ML.Description,
		Approach:           "supervised",
		Task:               "task goes here",
		ArchitectureFamily: "the architecture family goes here",
		ModelArchitecture:  "The architecture of the model.",
		Datasets: []MLDataset{{Type: "dataset", Name: "Training Data", Classification: "public",
			URL: "https://example.com/path/to/dataset"}},
		Inputs:  []string{"string"},
		Outputs: []string{"byte[]"},
	}
	if !reflect.DeepEqual(c.ML, want) {
		t.Errorf("model card =\n %+v\nwant\n %+v", c.ML, want)
	}
	if len(c.ML.Description) < 50 || c.ML.Description[:16] != "Stable Diffusion" {
		t.Errorf("description = %q", c.ML.Description)
	}

	env := parseFixture(t, "machine-learning-env-1.6.cdx.json").Components[0]
	if env.Kind != KindModel || env.Group != "meta-llama" || env.Name != "Llama-2-7b" || env.ML.Supplier != "Hugging Face" ||
		env.ML.Publisher != "meta" || !slices.Equal(env.ML.Organizations(), []string{"Hugging Face", "meta"}) ||
		!reflect.DeepEqual(env.ML.ExternalRefs, []ExternalRef{{Type: "distribution", URL: "https://huggingface.co/meta-llama/Llama-2-7b"}}) {
		t.Errorf("hub model = %+v %+v", env, env.ML)
	}

	data := parseFixture(t, "component-data-1.6.cdx.json").Components[0]
	if data.Kind != KindDataset || data.Name != "my-configs" || !reflect.DeepEqual(data.ML.Data, []MLDataset{
		{Type: "configuration", Name: "app.ini", URL: "https://example.com/cfg/1337/app.ini"},
		{Type: "other", Name: ".env", URL: "https://example.com/cfg/1337/env"},
	}) {
		t.Errorf("dataset = %+v %+v", data, data.ML)
	}
}

func TestParseMLBOMApp(t *testing.T) {
	doc := parseFixture(t, "mlbom-app.cdx.json")
	kinds := map[string]string{}
	byName := map[string]Component{}
	for _, c := range doc.Components {
		kinds[c.Name] = c.Kind
		byName[c.Name] = c
	}
	// chat-inference serves the model (dependency edge); OpenAI is a known
	// model provider API; billing is neither.
	if want := map[string]string{
		"transformers": KindSoftware, "Mistral-7B-Instruct-v0.2": KindModel, "support-tickets-2024": KindDataset,
		"chat-inference": KindAIService, "OpenAI Chat Completions": KindAIService,
	}; !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	if len(doc.Services) != 3 {
		t.Errorf("services = %d, want all 3 kept as services", len(doc.Services))
	}
	if byName["transformers"].ML != nil {
		t.Error("a library carries no ML facts")
	}

	m := byName["Mistral-7B-Instruct-v0.2"]
	if m.License != "Apache-2.0" || m.ML.Supplier != "Hugging Face" || m.ML.Publisher != "Mistral AI" ||
		m.ML.Task != "text-generation" || m.ML.ArchitectureFamily != "mistral" || m.ML.ModelArchitecture != "MistralForCausalLM" {
		t.Errorf("model = %+v %+v", m, m.ML)
	}
	// A dataset ref resolves to the data component's name.
	if !reflect.DeepEqual(m.ML.Datasets, []MLDataset{
		{Ref: "support-tickets", Name: "support-tickets-2024"},
		{Type: "dataset", Name: "ultrachat_200k", Classification: "public", URL: "https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k"},
	}) {
		t.Errorf("datasets = %+v", m.ML.Datasets)
	}
	if !reflect.DeepEqual(m.ML.Ancestors, []MLAncestor{{Type: "machine-learning-model", Group: "mistralai", Name: "Mistral-7B-v0.1"}}) {
		t.Errorf("ancestors = %+v", m.ML.Ancestors)
	}
	if m.Depth == nil || *m.Depth != 2 {
		t.Errorf("model depth = %v, want 2 (app → inference → model)", m.Depth)
	}

	svc := byName["OpenAI Chat Completions"]
	if svc.Type != "service" || svc.BomRef != "openai-api" || svc.ML.Supplier != "OpenAI" ||
		!slices.Equal(svc.ML.Endpoints, []string{"https://api.openai.com/v1/chat/completions"}) || svc.Direct == nil || !*svc.Direct {
		t.Errorf("AI service = %+v %+v", svc, svc.ML)
	}
}

func TestIsAIEndpoint(t *testing.T) {
	for ep, want := range map[string]bool{
		"https://api.openai.com/v1/chat/completions":                             true,
		"https://acme.openai.azure.com/openai/deployments/gpt":                   true,
		"https://bedrock-runtime.eu-west-1.amazonaws.com/model/x/invoke":         true,
		"https://europe-west4-aiplatform.googleapis.com/v1/projects/p":           true,
		"https://api.openai.com.evil.example/v1":                                 false,
		"https://openai.azure.com/":                                              false,
		"https://bedrock-runtime.eu-west-1.amazonaws.com.attacker.example/model": false,
		"https://s3.eu-west-1.amazonaws.com/bucket":                              false,
		"not a url": false,
	} {
		if got := isAIEndpoint(ep); got != want {
			t.Errorf("isAIEndpoint(%q) = %v, want %v", ep, got, want)
		}
	}
}
