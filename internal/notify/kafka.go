package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/xilasec/xila-api/internal/netguard"
)

// SASL mechanisms a kafka channel may use ("" = none).
const (
	SASLPlain       = "PLAIN"
	SASLScramSHA256 = "SCRAM-SHA-256"
	SASLScramSHA512 = "SCRAM-SHA-512"
)

// kafkaProduceTimeout bounds one publish attempt (dial, auth, produce) — the
// same budget as the HTTP channels' client timeout.
const kafkaProduceTimeout = 10 * time.Second

// kafkaTopicRe is Kafka's own topic naming rule: letters, digits, '.', '_' or
// '-', 1–249 characters.
var kafkaTopicRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,249}$`)

// KafkaConfig is a kafka channel's broker and security settings. The topic is
// the channel's URL (every other channel type also keeps its target there);
// the SASL password is sealed into the channel's secretEnc, like a generic
// webhook's signing secret, and is never round-tripped by the API.
type KafkaConfig struct {
	Brokers []string `json:"brokers"`
	// KeyTemplate computes the record key (kafkaKey); "" keys by the project id.
	KeyTemplate   string `json:"key_template,omitempty"`
	TLS           bool   `json:"tls"`
	TLSCA         string `json:"tls_ca,omitempty"`
	SASLMechanism string `json:"sasl_mechanism,omitempty"`
	SASLUsername  string `json:"sasl_username,omitempty"`
}

// ValidSASLMechanism reports whether m is a supported mechanism, including ""
// (no SASL).
func ValidSASLMechanism(m string) bool {
	switch m {
	case "", SASLPlain, SASLScramSHA256, SASLScramSHA512:
		return true
	}
	return false
}

// ValidateKafkaConfig checks a kafka channel's brokers, SASL and TLS
// settings. hasSecret says whether the channel already has a sealed SASL
// password — an update that doesn't resend one keeps the existing one;
// password is a new one being set now, if any.
func ValidateKafkaConfig(cfg KafkaConfig, password string, hasSecret bool) error {
	if len(cfg.Brokers) == 0 {
		return errors.New("kafka: at least one broker is required")
	}
	for _, b := range cfg.Brokers {
		if _, _, err := net.SplitHostPort(b); err != nil {
			return fmt.Errorf("kafka: broker %q must be host:port", b)
		}
	}
	if !ValidSASLMechanism(cfg.SASLMechanism) {
		return errors.New("kafka: sasl_mechanism must be PLAIN, SCRAM-SHA-256, SCRAM-SHA-512 or empty")
	}
	if cfg.SASLMechanism != "" {
		if cfg.SASLUsername == "" {
			return errors.New("kafka: sasl_username is required with a sasl_mechanism")
		}
		if password == "" && !hasSecret {
			return errors.New("kafka: sasl_password is required with a sasl_mechanism")
		}
	}
	if cfg.TLSCA != "" {
		block, _ := pem.Decode([]byte(cfg.TLSCA))
		if block == nil {
			return errors.New("kafka: tls_ca must be a PEM certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("kafka: tls_ca: %w", err)
		}
	}
	return nil
}

// kafkaKey computes a record key from a channel's key_template: literal text
// with {project_id}, {finding_id}, {event_type} and {severity} placeholders.
// An empty template keys by the project id, so a consumer can partition or
// compact by project without configuring anything; a global event (no
// project) then has no key.
func kafkaKey(template string, e Event) string {
	if template == "" {
		return e.ProjectID
	}
	r := strings.NewReplacer(
		"{project_id}", e.ProjectID,
		"{finding_id}", e.FindingID,
		"{event_type}", e.Type,
		"{severity}", e.Severity,
	)
	return r.Replace(template)
}

// kafkaDialer returns the dial function a client should use: netguard's
// guarded TCP dialer, wrapped in a TLS handshake when cfg.TLS is set so
// private/metadata-range (OUTBOUND_*) policy applies to the exact address
// Kafka connects to either way.
func kafkaDialer(cfg KafkaConfig) (func(ctx context.Context, network, host string) (net.Conn, error), error) {
	if !cfg.TLS {
		return netguard.DialContext, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.TLSCA)) {
			return nil, errors.New("kafka: tls_ca must be a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := netguard.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		c := tlsConfig.Clone()
		c.ServerName = host
		tc := tls.Client(conn, c)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tc, nil
	}, nil
}

// newKafkaClient builds a one-shot client for a single publish attempt:
// dialing (and SASL) is its own cost per retry, which is fine at alerting
// volume and means a connection to a broker that's since gone away never
// lingers between attempts.
func newKafkaClient(cfg KafkaConfig, password string) (*kgo.Client, error) {
	dial, err := kafkaDialer(cfg)
	if err != nil {
		return nil, err
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.Dialer(dial),
		kgo.ProduceRequestTimeout(kafkaProduceTimeout),
	}
	switch cfg.SASLMechanism {
	case SASLPlain:
		opts = append(opts, kgo.SASL(plain.Auth{User: cfg.SASLUsername, Pass: password}.AsMechanism()))
	case SASLScramSHA256:
		opts = append(opts, kgo.SASL(scram.Auth{User: cfg.SASLUsername, Pass: password}.AsSha256Mechanism()))
	case SASLScramSHA512:
		opts = append(opts, kgo.SASL(scram.Auth{User: cfg.SASLUsername, Pass: password}.AsSha512Mechanism()))
	}
	return kgo.NewClient(opts...)
}

// sendKafka publishes one message (the channel's url is the topic) and waits
// for the broker's ack.
func (s *Service) sendKafka(ctx context.Context, ch Channel, cfg KafkaConfig, password, key string, body []byte) error {
	cl, err := newKafkaClient(cfg, password)
	if err != nil {
		return fmt.Errorf("kafka client: %w", err)
	}
	defer cl.Close()
	cctx, cancel := context.WithTimeout(ctx, kafkaProduceTimeout)
	defer cancel()
	rec := &kgo.Record{Topic: ch.URL, Value: body}
	if key != "" {
		rec.Key = []byte(key)
	}
	res := cl.ProduceSync(cctx, rec)
	if err := res.FirstErr(); err != nil {
		return fmt.Errorf("produce to %q: %w", ch.URL, err)
	}
	return nil
}
