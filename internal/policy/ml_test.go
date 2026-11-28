package policy

import (
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/sbom"
)

// The AI inventory subjects: a model (Llama 2 from the Hugging Face hub), a
// dataset, an AI service and an ordinary library. model.* judge models and AI
// services only; facts a model card doesn't state are unknown and never match.
func TestAIConditions(t *testing.T) {
	llama := func(c *Component) {
		c.Kind, c.Type, c.Group, c.Name, c.Version, c.Purl = sbom.KindModel, "machine-learning-model", "meta-llama", "Llama-2-7b", "", ""
		c.ML = &sbom.MLFacts{Supplier: "Hugging Face", Publisher: "meta", Task: "text-generation",
			Datasets: []sbom.MLDataset{{Name: "wikipedia"}, {Ref: "corpus", Name: "web-crawl-2023"}}}
	}
	bare := func(c *Component) { // a model whose card states nothing
		c.Kind, c.Name, c.Purl, c.ML = sbom.KindModel, "mystery", "", &sbom.MLFacts{}
	}
	dataset := func(c *Component) {
		c.Kind, c.Name, c.Purl, c.ML = sbom.KindDataset, "wikipedia", "", &sbom.MLFacts{}
	}
	openai := func(c *Component) {
		c.Kind, c.Type, c.Name, c.Purl = sbom.KindAIService, "service", "OpenAI Chat Completions", ""
		c.ML = &sbom.MLFacts{Supplier: "OpenAI", Endpoints: []string{"https://api.openai.com/v1/chat/completions"}}
	}
	cases := []struct {
		name string
		cond Condition
		c    *Component
		want bool
	}{
		{"kind in", cond(SubjectComponentKind, OpIn, `["model", "ai-service"]`), comp(t, "", llama), true},
		{"kind of a library is software", cond(SubjectComponentKind, OpIn, `"software"`), comp(t, ""), true},
		{"kind not_in", cond(SubjectComponentKind, OpNotIn, `["software"]`), comp(t, "", dataset), true},

		{"name allow list: approved by hub id", cond(SubjectModelName, OpNoMatch, `["meta-llama/*", "mistralai/*"]`), comp(t, "", llama), false},
		{"name allow list: approved by bare name", cond(SubjectModelName, OpNoMatch, `["llama-2-*"]`), comp(t, "", llama), false},
		{"name allow list: unapproved model", cond(SubjectModelName, OpNoMatch, `["mistralai/*"]`), comp(t, "", llama), true},
		{"name allow list ignores libraries", cond(SubjectModelName, OpNoMatch, `["mistralai/*"]`), comp(t, ""), false},
		{"name allow list ignores datasets", cond(SubjectModelName, OpNoMatch, `["mistralai/*"]`), comp(t, "", dataset), false},
		{"name allow list judges AI services", cond(SubjectModelName, OpNoMatch, `["mistralai/*"]`), comp(t, "", openai), true},
		{"name deny list", cond(SubjectModelName, OpMatches, `"*/Llama-2-*"`), comp(t, "", llama), true},

		{"supplier deny list on publisher", cond(SubjectModelSupplier, OpIn, `["Meta"]`), comp(t, "", llama), true},
		{"supplier allow list: one name approved", cond(SubjectModelSupplier, OpNotIn, `["hugging face"]`), comp(t, "", llama), false},
		{"supplier allow list: unapproved provider", cond(SubjectModelSupplier, OpNotIn, `["Anthropic", "Mistral*"]`), comp(t, "", openai), true},
		{"supplier unknown never matches", cond(SubjectModelSupplier, OpNotIn, `["Anthropic"]`), comp(t, "", bare), false},
		{"supplier of a library is unknown", cond(SubjectModelSupplier, OpNotIn, `["Anthropic"]`),
			comp(t, "", func(c *Component) { c.ML = &sbom.MLFacts{Supplier: "npm"} }), false},

		{"license allow list on a model", cond(SubjectModelLicense, OpIsNot, `["Apache-2.0", "MIT"]`), comp(t, "LLAMA2-community OR GPL-3.0-only", llama), true},
		{"license allow list satisfied", cond(SubjectModelLicense, OpIsNot, `["Apache-2.0"]`), comp(t, "Apache-2.0", llama), false},
		{"license ignores libraries", cond(SubjectModelLicense, OpIsNot, `["Apache-2.0"]`), comp(t, "GPL-3.0-only"), false},
		{"license unknown never matches", cond(SubjectModelLicense, OpIsNot, `["Apache-2.0"]`), comp(t, "", llama), false},

		{"task allow list", cond(SubjectModelTask, OpNotIn, `["text-classification"]`), comp(t, "", llama), true},
		{"task deny list glob", cond(SubjectModelTask, OpIn, `["text-*"]`), comp(t, "", llama), true},
		{"task unknown never matches", cond(SubjectModelTask, OpNotIn, `["text-classification"]`), comp(t, "", bare), false},

		{"dataset allow list: one unapproved", cond(SubjectDatasetName, OpNoMatch, `["wikipedia"]`), comp(t, "", llama), true},
		{"dataset allow list: all approved", cond(SubjectDatasetName, OpNoMatch, `["wikipedia", "web-crawl-*"]`), comp(t, "", llama), false},
		{"dataset deny list on a dataset", cond(SubjectDatasetName, OpMatches, `"wiki*"`), comp(t, "", dataset), true},
		{"dataset unknown never matches", cond(SubjectDatasetName, OpNoMatch, `["wikipedia"]`), comp(t, "", bare), false},
		{"dataset of a library is unknown", cond(SubjectDatasetName, OpNoMatch, `["wikipedia"]`), comp(t, ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := compile(tc.cond, groups, ComponentSchema)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got, _ := cc.match(tc.c, now); got != tc.want {
				t.Errorf("match = %v, want %v", got, tc.want)
			}
		})
	}

	// The violation names the fact that made it one.
	cc, _ := compile(cond(SubjectModelName, OpNoMatch, `["mistralai/*"]`), groups, ComponentSchema)
	if _, fact := cc.match(comp(t, "", llama), now); fact != "model Llama-2-7b, meta-llama/Llama-2-7b" {
		t.Errorf("fact = %q", fact)
	}
	// model.license is a license subject: its violations are license findings.
	if !SubjectModelLicense.IsLicense() || SubjectModelName.IsLicense() {
		t.Error("model.license must count as a license subject, model.name not")
	}
}

func TestAIConditionValidation(t *testing.T) {
	for _, c := range []Condition{
		cond(SubjectComponentKind, OpIn, `["llm"]`),
		cond(SubjectComponentKind, OpIs, `"model"`),
		cond(SubjectModelName, OpIn, `["x"]`),
		cond(SubjectModelName, OpNoMatch, `[]`),
		cond(SubjectModelSupplier, OpIn, `[" "]`),
		cond(SubjectModelTask, OpIn, `42`),
		cond(SubjectDatasetName, OpNotIn, `["x"]`),
		cond(SubjectModelLicense, OpIn, `["MIT"]`),
	} {
		_, err := compile(c, groups, ComponentSchema)
		if _, ok := errors.AsType[*ValidationError](err); !ok {
			t.Errorf("compile(%s %s %s) = %v, want a validation error", c.Subject, c.Operator, c.Value, err)
		}
	}
	cc, err := compile(cond(SubjectComponentKind, OpIn, `"Model"`), groups, ComponentSchema)
	if err != nil || string(cc.Value) != `["model"]` {
		t.Errorf("normalized kind = %s (%v), want [\"model\"]", cc.Value, err)
	}
}
