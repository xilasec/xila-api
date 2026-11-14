// Package netguard is the one way Xila makes server-side HTTP requests to URLs
// someone configured (issue trackers, connectors, SSO issuers and metadata,
// registry and advisory mirrors, webhooks). It refuses destinations that are
// never a legitimate integration target — cloud metadata services, link-local
// addresses — and, by policy, loopback and private networks.
//
// The check runs where it can't be bypassed: in the dialer, on the address
// actually being connected to after DNS resolution (so a hostname that
// resolves — or rebinds — to 169.254.169.254 is refused) and therefore again on
// every redirect hop. Through an HTTP proxy the dialer only sees the proxy, so
// the target's resolved addresses are checked before the request is forwarded.
//
// The policy is process-wide: main sets it from configuration at startup
// (SetDefault) and every client reads it at dial time.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrBlocked is returned (wrapped) when a destination is refused.
var ErrBlocked = errors.New("destination not allowed")

// Policy says which destinations outbound requests may reach. Link-local and
// metadata addresses are always refused.
type Policy struct {
	// AllowPrivate admits RFC 1918, unique-local (fc00::/7) and CGNAT
	// (100.64/10) addresses — where self-hosted Jira, GitLab, DefectDojo or a
	// registry mirror usually live.
	AllowPrivate bool
	// AllowLoopback admits 127/8 and ::1 (development, sidecars).
	AllowLoopback bool
	// AllowedHosts are hostnames (exact, case-insensitive) exempt from the
	// private/loopback rules. Never from the link-local/metadata rule.
	AllowedHosts []string
}

// Permissive is the policy before configuration: everything but link-local
// and metadata addresses. Tests and tools that never call SetDefault get it.
var Permissive = Policy{AllowPrivate: true, AllowLoopback: true}

var current atomic.Pointer[Policy]

func init() { SetDefault(Permissive) }

// SetDefault sets the process-wide policy.
func SetDefault(p Policy) {
	p.AllowedHosts = slices.Clone(p.AllowedHosts)
	for i, h := range p.AllowedHosts {
		p.AllowedHosts[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	}
	current.Store(&p)
}

// Default returns the process-wide policy.
func Default() Policy { return *current.Load() }

// metadata addresses that aren't link-local (AWS IPv6 IMDS).
var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	thisNet    = netip.MustParsePrefix("0.0.0.0/8")
	broadcast4 = netip.MustParseAddr("255.255.255.255")
)

// CheckAddr reports whether p admits a connection to ip. host is the requested
// hostname (for AllowedHosts); empty when unknown.
func (p Policy) CheckAddr(host string, ip netip.Addr) error {
	ip = ip.Unmap() // ::ffff:169.254.169.254 is 169.254.169.254
	switch {
	case !ip.IsValid():
		return fmt.Errorf("%w: invalid address", ErrBlocked)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), ip == broadcast4, thisNet.Contains(ip):
		return fmt.Errorf("%w: %s is a link-local, multicast or unspecified address", ErrBlocked, ip)
	}
	for _, pfx := range alwaysBlocked {
		if pfx.Contains(ip) {
			return fmt.Errorf("%w: %s is a cloud metadata address", ErrBlocked, ip)
		}
	}
	if host != "" && slices.Contains(p.AllowedHosts, strings.ToLower(strings.TrimSuffix(host, "."))) {
		return nil
	}
	if ip.IsLoopback() && !p.AllowLoopback {
		return fmt.Errorf("%w: %s is a loopback address (OUTBOUND_ALLOW_LOOPBACK)", ErrBlocked, ip)
	}
	if (ip.IsPrivate() || cgnat.Contains(ip)) && !p.AllowPrivate {
		return fmt.Errorf("%w: %s is a private address (OUTBOUND_ALLOW_PRIVATE)", ErrBlocked, ip)
	}
	return nil
}

type hostKey struct{}

// control is the dialer hook: it sees the resolved address being connected to.
func control(ctx context.Context) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: unparseable address %q", ErrBlocked, address)
		}
		host, _ := ctx.Value(hostKey{}).(string)
		return Default().CheckAddr(host, ap.Addr())
	}
}

// DialContext dials like net.Dialer but refuses blocked destinations.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	ctx = context.WithValue(ctx, hostKey{}, host)
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return control(ctx)(network, address, c)
	}
	return d.DialContext(ctx, network, address)
}

// Transport returns an http.Transport with the guarded dialer and the usual
// defaults (environment proxy, HTTP/2, idle pooling). Callers may tune its
// timeouts.
func Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = DialContext
	return t
}

// guard checks the target itself when a proxy is in the way (the dialer then
// only ever sees the proxy's address).
type guard struct{ base *http.Transport }

func (g guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrBlocked, r.URL.Scheme)
	}
	if g.base.Proxy != nil {
		if proxy, err := g.base.Proxy(r); err == nil && proxy != nil {
			if err := checkHost(r.Context(), Default(), r.URL.Hostname()); err != nil {
				return nil, err
			}
		}
	}
	return g.base.RoundTrip(r)
}

// NewClient returns an HTTP client that refuses blocked destinations,
// including on redirects.
func NewClient(timeout time.Duration) *http.Client {
	return WrapTransport(Transport(), timeout)
}

// WrapTransport builds a guarded client around t (whose DialContext must be
// DialContext — Transport() returns one).
func WrapTransport(t *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: guard{base: t},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrBlocked, req.URL.Scheme)
			}
			return nil
		},
	}
}

// CheckURL validates a configured URL up front (forms, provider tests), so a
// blocked target is a clear 400 instead of a failed request later. It resolves
// the host; the dial-time check still applies when the URL is used.
func CheckURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: not an absolute URL", ErrBlocked)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be http or https", ErrBlocked)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return checkHost(ctx, Default(), u.Hostname())
}

func checkHost(ctx context.Context, p Policy, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return p.CheckAddr(host, ip)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// Unresolvable now isn't a policy violation; the request will fail on
		// its own (and the dialer re-checks whatever it resolves to later).
		return nil
	}
	for _, a := range addrs {
		if err := p.CheckAddr(host, a); err != nil {
			return fmt.Errorf("%s resolves to a refused address: %w", host, err)
		}
	}
	return nil
}
