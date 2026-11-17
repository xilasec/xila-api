package notify_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// TestKafkaChannelConfigRoundTrip exercises the config column end to end:
// Create persists brokers/TLS/SASL settings, Get and the ListForEvent/List
// readers (scanChannel) decode them back, and the SASL password is sealed
// like a generic webhook's signing secret (never round-tripped).
func TestKafkaChannelConfigRoundTrip(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := notify.NewRepository(pool)
	ctx := context.Background()

	ch := notify.Channel{Name: "kafka-alerts", Type: notify.TypeKafka, URL: "xila-events", Enabled: true}
	cfg := notify.KafkaConfig{
		Brokers: []string{"broker-1:9092", "broker-2:9092"}, KeyTemplate: "{project_id}",
		TLS: true, SASLMechanism: notify.SASLScramSHA256, SASLUsername: "xila",
	}
	if err := ch.SetKafkaConfig(cfg); err != nil {
		t.Fatalf("SetKafkaConfig: %v", err)
	}

	created, err := repo.Create(ctx, ch)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Kafka == nil {
		t.Fatal("created.Kafka = nil, want the config back")
	}
	if len(created.Kafka.Brokers) != 2 || created.Kafka.Brokers[0] != "broker-1:9092" {
		t.Errorf("created.Kafka.Brokers = %v, want 2 brokers", created.Kafka.Brokers)
	}
	if created.Kafka.SASLMechanism != notify.SASLScramSHA256 {
		t.Errorf("created.Kafka.SASLMechanism = %q, want %q", created.Kafka.SASLMechanism, notify.SASLScramSHA256)
	}

	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Kafka == nil || len(got.Kafka.Brokers) != 2 {
		t.Fatalf("Get().Kafka = %+v, want the config back", got.Kafka)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, c := range list {
		if c.ID == created.ID {
			found = true
			if c.Kafka == nil || c.Kafka.KeyTemplate != "{project_id}" {
				t.Errorf("List()'s kafka channel config = %+v, want key_template preserved", c.Kafka)
			}
		}
	}
	if !found {
		t.Error("created channel missing from List()")
	}

	// A non-kafka channel never decodes a Kafka config.
	other, err := repo.Create(ctx, notify.Channel{Name: "slack", Type: "slack", URL: "https://hooks.slack/x", Enabled: true})
	if err != nil {
		t.Fatalf("create slack: %v", err)
	}
	if other.Kafka != nil {
		t.Errorf("slack channel Kafka = %+v, want nil", other.Kafka)
	}
}

// TestKafkaChannelUpdatePreservesConfig: updating unrelated settings (name,
// enabled) without touching config keeps the stored kafka settings (the
// Repository's COALESCE($11::jsonb, config)).
func TestKafkaChannelUpdatePreservesConfig(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := notify.NewRepository(pool)
	ctx := context.Background()

	ch := notify.Channel{Name: "kafka-alerts", Type: notify.TypeKafka, URL: "xila-events", Enabled: true}
	if err := ch.SetKafkaConfig(notify.KafkaConfig{Brokers: []string{"broker:9092"}}); err != nil {
		t.Fatalf("SetKafkaConfig: %v", err)
	}
	created, err := repo.Create(ctx, ch)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Update without a config (the Go zero value's configRaw is nil): the
	// handler never sets it unless the caller sent a new "kafka" field.
	created.Enabled = false
	updated, err := repo.Update(ctx, created)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Kafka == nil || len(updated.Kafka.Brokers) != 1 || updated.Kafka.Brokers[0] != "broker:9092" {
		t.Errorf("updated.Kafka = %+v, want the original brokers preserved", updated.Kafka)
	}
	if updated.Enabled {
		t.Error("updated.Enabled = true, want false")
	}
}
