package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// CryptoLyzer parses the JSON output of CryptoLyzer's full TLS analysis
// (`cryptolyze --output-format json tls all <host>`): the offered protocol
// versions, cipher suites per version, elliptic curves and signature
// algorithms, plus its verdicts on known attacks.
//
// The report states what a server offers, not what is wrong with it, so the
// offer is checked against BSI TR-02102-2 (the German Federal Office for
// Information Security's TLS recommendations, as SecObserve does): protocols
// older than TLS 1.2, and cipher suites, curves and signature algorithms the
// guideline doesn't recommend, each become one finding per host listing what
// was offered. The attack verdicts that are true become findings of their own,
// with the attack's CVE, so they deduplicate against testssl.sh reporting the
// same flaw. The location is host:port, like testssl.sh.
type CryptoLyzer struct{}

// NewCryptoLyzer constructs a CryptoLyzer parser.
func NewCryptoLyzer() CryptoLyzer { return CryptoLyzer{} }

// Scanner returns the tool identifier.
func (CryptoLyzer) Scanner() string { return "cryptolyzer" }

// PrimaryCategory is the scan-level category for CryptoLyzer reports.
func (CryptoLyzer) PrimaryCategory() domain.Category { return domain.CategoryDAST }

// bsiTR02102 is the reference every check links to.
const bsiTR02102 = "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf"

// Recommended by BSI TR-02102-2 (2023).
var (
	bsiTLS12Ciphers = []string{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_128_CCM", "TLS_DHE_RSA_WITH_AES_256_CCM",
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_PSK_WITH_AES_128_CCM", "TLS_DHE_PSK_WITH_AES_256_CCM",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}
	bsiTLS13Ciphers = []string{
		"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_CCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
	}
	bsiCurves = []string{
		"BRAINPOOLP256R1TLS13", "BRAINPOOLP384R1TLS13", "BRAINPOOLP512R1TLS13",
		"BRAINPOOLP256R1", "BRAINPOOLP384R1", "BRAINPOOLP512R1",
		"SECP256R1", "PRIME256V1", "SECP384R1", "SECP521R1", "FFDHE3072", "FFDHE4096",
		"X25519_ML_KEM_768", "X25519_KYBER_768_R3", "X25519",
	}
	bsiSigAlgos = []string{
		"RSA_SHA256", "RSA_SHA384", "RSA_SHA512", "DSA_SHA256", "DSA_SHA384", "DSA_SHA512",
		"ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
		"RSA_PSS_RSAE_SHA256", "RSA_PSS_RSAE_SHA384", "RSA_PSS_RSAE_SHA512",
		"RSA_PSS_PSS_SHA256", "RSA_PSS_PSS_SHA384", "RSA_PSS_PSS_SHA512",
		"ECDSA_SECP256R1_SHA256", "ECDSA_SECP384R1_SHA384", "ECDSA_SECP521R1_SHA512",
		"ECDSA_BRAINPOOLP256R1TLS13_SHA256", "ECDSA_BRAINPOOLP384R1TLS13_SHA384", "ECDSA_BRAINPOOLP512R1TLS13_SHA512",
	}
)

// cryptolyzerAttack describes one verdict of CryptoLyzer's "vulns" section.
type cryptolyzerAttack struct {
	section, key string // vulns.<section>.<key>
	title        string
	severity     domain.Severity
	cve          []string
	cwe          int
}

var cryptolyzerAttacks = []cryptolyzerAttack{
	{"versions", "drown", "DROWN: SSLv2 enables decrypting TLS sessions", domain.SeverityHigh, []string{"CVE-2016-0800"}, 310},
	{"ciphers", "freak", "FREAK: export-grade RSA key exchange", domain.SeverityHigh, []string{"CVE-2015-0204"}, 327},
	{"ciphers", "export_grade", "Export-grade cipher suites offered", domain.SeverityHigh, nil, 327},
	{"ciphers", "null_encryption", "Cipher suites without encryption (NULL) offered", domain.SeverityHigh, nil, 319},
	{"ciphers", "anonymous_dh", "Anonymous Diffie-Hellman (no server authentication) offered", domain.SeverityHigh, nil, 287},
	{"dhparams", "logjam", "Logjam: weak Diffie-Hellman parameters", domain.SeverityHigh, []string{"CVE-2015-4000"}, 310},
	{"ciphers", "rc4", "RC4 cipher suites offered", domain.SeverityMedium, []string{"CVE-2013-2566", "CVE-2015-2808"}, 327},
	{"ciphers", "sweet32", "SWEET32: 64-bit block ciphers (3DES) offered", domain.SeverityMedium, []string{"CVE-2016-2183"}, 327},
	{"dhparams", "dheat", "DHEat: Diffie-Hellman key exchange denial of service", domain.SeverityMedium, []string{"CVE-2002-20001"}, 400},
	{"ciphers", "lucky13", "LUCKY13: CBC cipher suites with a padding-oracle timing side channel", domain.SeverityLow, []string{"CVE-2013-0169"}, 310},
	{"ciphers", "non_forward_secret", "Cipher suites without forward secrecy offered", domain.SeverityLow, nil, 310},
}

type cryptolyzerTarget struct {
	Address      string `json:"address"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	ProtoVersion string `json:"proto_version"`
}

type cryptolyzerReport struct {
	Target   *cryptolyzerTarget `json:"target"`
	Versions *struct {
		Target   cryptolyzerTarget `json:"target"`
		Versions []string          `json:"versions"`
	} `json:"versions"`
	Ciphers []struct {
		Target       cryptolyzerTarget `json:"target"`
		CipherSuites []string          `json:"cipher_suites"`
	} `json:"ciphers"`
	Curves *struct {
		Target cryptolyzerTarget `json:"target"`
		Curves []string          `json:"curves"`
	} `json:"curves"`
	SigAlgos *struct {
		Target   cryptolyzerTarget `json:"target"`
		SigAlgos []string          `json:"sig_algos"`
	} `json:"sigalgos"`
	Vulns map[string]json.RawMessage `json:"vulns"`
}

// Parse implements Parser.
func (CryptoLyzer) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep cryptolyzerReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode cryptolyzer json: %w", err)
	}
	if rep.Target == nil || rep.Versions == nil {
		return nil, errors.New("decode cryptolyzer json: no target/versions — not a CryptoLyzer `tls all` report")
	}
	host := *rep.Target
	if host.Address == "" && host.IP == "" {
		return nil, errors.New("decode cryptolyzer json: report names no target host")
	}
	location := func(t cryptolyzerTarget) string {
		h := firstNonEmpty(t.Address, t.IP, host.Address, host.IP)
		port := t.Port
		if port == 0 {
			port = host.Port
		}
		if port != 0 {
			h += ":" + strconv.Itoa(port)
		}
		return h
	}
	out := []ParsedFinding{}
	add := func(t cryptolyzerTarget, rule, title, desc string, sev domain.Severity, cwe int, cves []string, offered []string) {
		loc := location(t)
		meta := map[string]any{"host": firstNonEmpty(t.Address, host.Address), "references": []string{bsiTR02102}}
		if ip := firstNonEmpty(t.IP, host.IP); ip != "" {
			meta["ip"] = ip
		}
		if len(offered) > 0 {
			meta["offered"] = offered
		}
		out = append(out, ParsedFinding{
			Category: domain.CategoryDAST, RuleID: rule, Title: title, Description: desc, Severity: sev,
			CWE: new(cwe), CVE: cves, FilePath: loc, URL: loc, Metadata: meta,
		})
	}

	// Protocols: anything older than TLS 1.2 (SSL 2/3, TLS 1.0/1.1).
	var weak []string
	for _, v := range rep.Versions.Versions {
		if v != "tls1_2" && v != "tls1_3" {
			weak = append(weak, v)
		}
	}
	if len(weak) > 0 {
		add(rep.Versions.Target, "weak-protocols", "Weak protocols offered: "+strings.Join(weak, ", "),
			"The server accepts protocol versions older than TLS 1.2, which BSI TR-02102-2 no longer recommends:\n- "+strings.Join(weak, "\n- "),
			domain.SeverityHigh, 326, nil, weak)
	}

	// Cipher suites per protocol version.
	for _, c := range rep.Ciphers {
		var recommended []string
		var name string
		switch c.Target.ProtoVersion {
		case "tls1_2":
			recommended, name = bsiTLS12Ciphers, "TLS 1.2"
		case "tls1_3":
			recommended, name = bsiTLS13Ciphers, "TLS 1.3"
		default:
			continue // older versions are already reported as weak protocols
		}
		var bad []string
		for _, s := range c.CipherSuites {
			if !slices.Contains(recommended, ianaCipher(s)) {
				bad = append(bad, s)
			}
		}
		if len(bad) > 0 {
			add(c.Target, c.Target.ProtoVersion+"-cipher-suites", "Unrecommended "+name+" cipher suites offered",
				"BSI TR-02102-2 doesn't recommend these "+name+" cipher suites the server offers:\n- "+strings.Join(bad, "\n- "),
				domain.SeverityMedium, 327, nil, bad)
		}
	}
	if rep.Curves != nil {
		if bad := notIn(rep.Curves.Curves, bsiCurves); len(bad) > 0 {
			add(rep.Curves.Target, "elliptic-curves", "Unrecommended elliptic curves offered",
				"BSI TR-02102-2 doesn't recommend these key-exchange groups the server offers:\n- "+strings.Join(bad, "\n- "),
				domain.SeverityMedium, 327, nil, bad)
		}
	}
	if rep.SigAlgos != nil {
		if bad := notIn(rep.SigAlgos.SigAlgos, bsiSigAlgos); len(bad) > 0 {
			add(rep.SigAlgos.Target, "signature-algorithms", "Unrecommended signature algorithms offered",
				"BSI TR-02102-2 doesn't recommend these signature algorithms the server accepts:\n- "+strings.Join(bad, "\n- "),
				domain.SeverityMedium, 327, nil, bad)
		}
	}

	// Known attacks CryptoLyzer found the server exposed to.
	verdicts := map[string]map[string]bool{}
	for section, raw := range rep.Vulns {
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil {
			continue
		}
		verdicts[section] = map[string]bool{}
		for k, val := range v {
			if b, ok := val.(bool); ok {
				verdicts[section][k] = b
			}
		}
	}
	for _, a := range cryptolyzerAttacks {
		if !verdicts[a.section][a.key] {
			continue
		}
		add(host, a.key, a.title, a.title+" (CryptoLyzer vulnerability check "+a.section+"."+a.key+").",
			a.severity, a.cwe, a.cve, nil)
	}
	return out, nil
}

// ianaCipher is a cipher suite's IANA name: CryptoLyzer occasionally drops the
// TLS_ prefix ("ECDHE_RSA_WITH_AES_256_GCM_SHA384").
func ianaCipher(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "TLS_") {
		s = "TLS_" + s
	}
	return s
}

// notIn returns the items of offered (compared upper-cased) missing from
// recommended, in report order.
func notIn(offered, recommended []string) []string {
	var out []string
	for _, o := range offered {
		if !slices.Contains(recommended, strings.ToUpper(strings.TrimSpace(o))) {
			out = append(out, o)
		}
	}
	return out
}
