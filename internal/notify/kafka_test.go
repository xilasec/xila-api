package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
)

func validKafkaConfig() KafkaConfig {
	return KafkaConfig{Brokers: []string{"kafka.internal:9092"}}
}

func TestValidateKafkaConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      KafkaConfig
		password string
		hasSec   bool
		wantErr  string
	}{
		{name: "no brokers", cfg: KafkaConfig{}, wantErr: "at least one broker"},
		{name: "bad broker", cfg: KafkaConfig{Brokers: []string{"not-a-host-port"}}, wantErr: "host:port"},
		{name: "valid, no sasl", cfg: validKafkaConfig()},
		{
			name:    "bad sasl mechanism",
			cfg:     KafkaConfig{Brokers: validKafkaConfig().Brokers, SASLMechanism: "MD5"},
			wantErr: "sasl_mechanism",
		},
		{
			name:    "sasl without username",
			cfg:     KafkaConfig{Brokers: validKafkaConfig().Brokers, SASLMechanism: SASLPlain},
			wantErr: "sasl_username",
		},
		{
			name:    "sasl without password or existing secret",
			cfg:     KafkaConfig{Brokers: validKafkaConfig().Brokers, SASLMechanism: SASLPlain, SASLUsername: "bob"},
			wantErr: "sasl_password",
		},
		{
			name:     "sasl password supplied",
			cfg:      KafkaConfig{Brokers: validKafkaConfig().Brokers, SASLMechanism: SASLScramSHA256, SASLUsername: "bob"},
			password: "s3cr3t-password",
		},
		{
			name:   "sasl keeps existing secret on update",
			cfg:    KafkaConfig{Brokers: validKafkaConfig().Brokers, SASLMechanism: SASLScramSHA512, SASLUsername: "bob"},
			hasSec: true,
		},
		{
			name:    "bad tls_ca",
			cfg:     KafkaConfig{Brokers: validKafkaConfig().Brokers, TLS: true, TLSCA: "not a pem"},
			wantErr: "tls_ca",
		},
		{
			name: "tls without ca (system roots)",
			cfg:  KafkaConfig{Brokers: validKafkaConfig().Brokers, TLS: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateKafkaConfig(c.cfg, c.password, c.hasSec)
			if c.wantErr == "" {
				if err != nil {
					t.Errorf("ValidateKafkaConfig() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ValidateKafkaConfig() = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestValidSASLMechanism(t *testing.T) {
	for _, m := range []string{"", SASLPlain, SASLScramSHA256, SASLScramSHA512} {
		if !ValidSASLMechanism(m) {
			t.Errorf("ValidSASLMechanism(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"MD5", "plain", "scram-sha-256", "bogus"} {
		if ValidSASLMechanism(m) {
			t.Errorf("ValidSASLMechanism(%q) = true, want false", m)
		}
	}
}

func TestKafkaKey(t *testing.T) {
	e := Event{ProjectID: "proj-1", FindingID: "find-2", Type: EventCriticalFinding, Severity: "critical"}
	cases := []struct {
		template string
		want     string
	}{
		{template: "", want: "proj-1"},
		{template: "{project_id}", want: "proj-1"},
		{template: "{project_id}:{finding_id}", want: "proj-1:find-2"},
		{template: "{event_type}/{severity}", want: "finding.critical/critical"},
		{template: "static-key", want: "static-key"},
	}
	for _, c := range cases {
		if got := kafkaKey(c.template, e); got != c.want {
			t.Errorf("kafkaKey(%q) = %q, want %q", c.template, got, c.want)
		}
	}
	// Empty template, no project: no consistent partition key to fall back to.
	if got := kafkaKey("", Event{Type: EventSummary}); got != "" {
		t.Errorf("kafkaKey(\"\", no project) = %q, want \"\"", got)
	}
}

func TestKafkaTopicValidation(t *testing.T) {
	for _, ok := range []string{"xila-events", "xila.events_1"} {
		if err := ValidateTarget(TypeKafka, ok); err != nil {
			t.Errorf("ValidateTarget(kafka, %q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "topic with spaces", strings.Repeat("x", 250)} {
		if err := ValidateTarget(TypeKafka, bad); err == nil {
			t.Errorf("ValidateTarget(kafka, %q) = nil, want error", bad)
		}
	}
}

// --- kfake integration: produce a real message over the wire and consume it back. ---

func TestSendKafkaProducesToFakeCluster(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.SeedTopics(1, "xila-events"))
	if err != nil {
		t.Fatalf("kfake.NewCluster: %v", err)
	}
	defer cluster.Close()

	cfg := KafkaConfig{Brokers: cluster.ListenAddrs()}
	ch := Channel{Name: "kafka-test", Type: TypeKafka, URL: "xila-events"}
	s := &Service{}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := []byte(`{"type":"finding.critical","title":"test"}`)
	if err := s.sendKafka(ctx, ch, cfg, "", "proj-1", body); err != nil {
		t.Fatalf("sendKafka: %v", err)
	}

	got := consumeOne(t, cluster.ListenAddrs(), "xila-events")
	if string(got.Value) != string(body) {
		t.Errorf("consumed value = %q, want %q", got.Value, body)
	}
	if string(got.Key) != "proj-1" {
		t.Errorf("consumed key = %q, want %q", got.Key, "proj-1")
	}
}

func TestSendKafkaWithSASL(t *testing.T) {
	cluster, err := kfake.NewCluster(
		kfake.SeedTopics(1, "xila-events"),
		kfake.EnableSASL(),
		kfake.Superuser("SCRAM-SHA-256", "xila", "xila-secret-pw"),
	)
	if err != nil {
		t.Fatalf("kfake.NewCluster: %v", err)
	}
	defer cluster.Close()

	cfg := KafkaConfig{
		Brokers: cluster.ListenAddrs(), SASLMechanism: SASLScramSHA256, SASLUsername: "xila",
	}
	ch := Channel{Name: "kafka-sasl-test", Type: TypeKafka, URL: "xila-events"}
	s := &Service{}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.sendKafka(ctx, ch, cfg, "xila-secret-pw", "", []byte("hello")); err != nil {
		t.Fatalf("sendKafka with SASL: %v", err)
	}

	// Wrong password must be refused, not silently accepted.
	if err := s.sendKafka(ctx, ch, cfg, "wrong-password", "", []byte("hello")); err == nil {
		t.Error("sendKafka with a wrong SASL password succeeded, want an error")
	}
}

// consumeOne reads exactly one record from topic and returns it.
func consumeOne(t *testing.T, brokers []string, topic string) *kgo.Record {
	t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(topic), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatalf("kgo.NewClient: %v", err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fetches := cl.PollRecords(ctx, 1)
	if errs := fetches.Errors(); len(errs) > 0 {
		t.Fatalf("PollRecords: %v", errs)
	}
	recs := fetches.Records()
	if len(recs) == 0 {
		t.Fatal("PollRecords: no records")
	}
	return recs[0]
}
