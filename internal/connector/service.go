package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// ValidationError is a rejected connector config (HTTP 400).
type ValidationError struct{ msg string }

func (e ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Store is the persistence the service needs (implemented by *Repository).
type Store interface {
	List(ctx context.Context, projectID string) ([]Connector, error)
	Get(ctx context.Context, projectID, id string) (Connector, error)
	Create(ctx context.Context, c Connector, tokenEnc []byte) (Connector, error)
	Update(ctx context.Context, c Connector, tokenEnc []byte) (Connector, error)
	Delete(ctx context.Context, projectID, id string) error
	ListDue(ctx context.Context, every time.Duration) ([]Connector, error)
	StillDue(ctx context.Context, id string, every time.Duration) (bool, error)
	TryLock(ctx context.Context, id string) (release func(), ok bool, err error)
	ResolveVersion(ctx context.Context, projectID, name string) (string, error)
	RecordSuccess(ctx context.Context, id, scanID string, count int) (Connector, error)
	RecordFailure(ctx context.Context, id, msg string) (Connector, error)
	Outcome(ctx context.Context, scanID string) (created, closed int, err error)
}

// Applier records a pull as a scan (implemented by *scan.Service).
type Applier interface {
	ApplyFindings(ctx context.Context, projectID, versionID, scannerName string, category domain.Category, findings []finding.Finding) (scan.Scan, error)
}

// Service manages connectors and runs pulls.
type Service struct {
	store  Store
	apply  Applier
	cipher *secretbox.Cipher
	hc     *http.Client
}

// NewService constructs a Service. cipher may be nil (no INTEGRATION_SECRET_KEY):
// connectors can then not be configured or pulled.
func NewService(store Store, apply Applier, cipher *secretbox.Cipher) *Service {
	return &Service{store: store, apply: apply, cipher: cipher, hc: netguard.NewClient(2 * time.Minute)}
}

// Input is a connector config as written by POST / PUT. Token is write-only:
// on update an empty one keeps the stored token.
type Input struct {
	Kind          Kind   `json:"kind"`
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
	RemoteProject string `json:"remote_project"`
	Token         string `json:"token"`
	Version       string `json:"version"`
	Enabled       *bool  `json:"enabled"`
}

var (
	ddProduct    = regexp.MustCompile(`^(?:product:)?([1-9][0-9]*)$`)
	ddEngagement = regexp.MustCompile(`^engagement:([1-9][0-9]*)$`)
)

// Normalize validates the input and applies defaults, returning the config it
// describes (without the token).
func (in Input) Normalize(projectID string) (Connector, error) {
	c := Connector{
		ProjectID:     projectID,
		Kind:          Kind(strings.ToLower(strings.TrimSpace(string(in.Kind)))),
		Name:          strings.TrimSpace(in.Name),
		BaseURL:       strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"),
		RemoteProject: strings.ToLower(strings.TrimSpace(in.RemoteProject)),
		Version:       strings.TrimSpace(in.Version),
		Enabled:       in.Enabled == nil || *in.Enabled,
	}
	if !c.Kind.Valid() {
		return Connector{}, invalid("kind must be dependency-track or defectdojo")
	}
	if len(c.Name) > 100 {
		return Connector{}, invalid("name must be at most 100 characters")
	}
	if len(c.Version) > 255 {
		return Connector{}, invalid("version must be at most 255 characters")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return Connector{}, invalid("base_url must be an http(s) URL")
	}
	if err := netguard.CheckURL(c.BaseURL); err != nil {
		return Connector{}, invalid("base_url is not an allowed destination: %v", err)
	}
	// The API prefix is ours to add; accept the URL as copied from the docs too.
	switch c.Kind {
	case KindDependencyTrack:
		c.BaseURL = strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/api/v1"), "/api")
		if _, err := uuid.Parse(c.RemoteProject); err != nil {
			return Connector{}, invalid("remote_project must be the Dependency-Track project UUID")
		}
	case KindDefectDojo:
		c.BaseURL = strings.TrimSuffix(strings.TrimSuffix(c.BaseURL, "/api/v2"), "/api")
		if m := ddProduct.FindStringSubmatch(c.RemoteProject); m != nil {
			c.RemoteProject = m[1]
		} else if !ddEngagement.MatchString(c.RemoteProject) {
			return Connector{}, invalid("remote_project must be a DefectDojo product id (42) or engagement id (engagement:42)")
		}
	}
	return c, nil
}

// List returns the project's connectors.
func (s *Service) List(ctx context.Context, projectID string) ([]Connector, error) {
	return s.store.List(ctx, projectID)
}

// Create adds a connector. A token is required.
func (s *Service) Create(ctx context.Context, projectID string, in Input) (Connector, error) {
	if s.cipher == nil {
		return Connector{}, secretbox.ErrNoKey
	}
	c, err := in.Normalize(projectID)
	if err != nil {
		return Connector{}, err
	}
	tok := strings.TrimSpace(in.Token)
	if tok == "" {
		return Connector{}, invalid("token is required")
	}
	sealed, err := s.cipher.Seal(tok, projectID)
	if err != nil {
		return Connector{}, err
	}
	return s.store.Create(ctx, c, sealed)
}

// Update rewrites a connector's config. The kind is fixed (its findings are
// recorded under it). An empty token keeps the stored one — unless the
// connector is pointed at another server, which must be given its own token:
// otherwise anyone allowed to edit the URL could send the stored credential to
// a host of their choosing.
func (s *Service) Update(ctx context.Context, projectID, id string, in Input) (Connector, error) {
	if s.cipher == nil {
		return Connector{}, secretbox.ErrNoKey
	}
	cur, err := s.store.Get(ctx, projectID, id)
	if err != nil {
		return Connector{}, err
	}
	if strings.TrimSpace(string(in.Kind)) == "" {
		in.Kind = cur.Kind
	}
	c, err := in.Normalize(projectID)
	if err != nil {
		return Connector{}, err
	}
	if c.Kind != cur.Kind {
		return Connector{}, invalid("kind can't be changed; create a new connector")
	}
	c.ID = id
	var sealed []byte
	if tok := strings.TrimSpace(in.Token); tok != "" {
		if sealed, err = s.cipher.Seal(tok, projectID); err != nil {
			return Connector{}, err
		}
	} else if c.BaseURL != cur.BaseURL {
		return Connector{}, invalid("token is required when base_url changes")
	}
	return s.store.Update(ctx, c, sealed)
}

// Delete removes a connector. Its findings stay, like a scanner's that stopped
// running.
func (s *Service) Delete(ctx context.Context, projectID, id string) error {
	return s.store.Delete(ctx, projectID, id)
}

func (s *Service) client(c Connector) (Client, error) {
	token, err := s.cipher.Open(c.tokenEnc, c.ProjectID)
	if err != nil {
		return nil, err
	}
	return NewClient(c, token, s.hc)
}

// Test makes one cheap authenticated call with the stored config and returns
// the remote project's name. Remote failures are RemoteErrors.
func (s *Service) Test(ctx context.Context, projectID, id string) (string, error) {
	c, err := s.store.Get(ctx, projectID, id)
	if err != nil {
		return "", err
	}
	cl, err := s.client(c)
	if err != nil {
		return "", err
	}
	return cl.Check(ctx)
}

// PullResult is the outcome of an applied pull.
type PullResult struct {
	Connector Connector      `json:"connector"`
	ScanID    string         `json:"scan_id"`
	Imported  int            `json:"imported"`
	New       int            `json:"new"`
	Closed    int            `json:"closed"`
	Summary   map[string]int `json:"summary"`
}

// Pull runs one connector now. ErrBusy means a pull of it is already running.
// A failed fetch is recorded on the connector and returned (a RemoteError for
// remote failures) without touching any finding.
func (s *Service) Pull(ctx context.Context, projectID, id string) (PullResult, error) {
	c, err := s.store.Get(ctx, projectID, id)
	if err != nil {
		return PullResult{}, err
	}
	release, ok, err := s.store.TryLock(ctx, c.ID)
	if err != nil {
		return PullResult{}, err
	}
	if !ok {
		return PullResult{}, ErrBusy
	}
	defer release()
	// Re-read under the lock: the config (or token) may have changed meanwhile.
	if c, err = s.store.Get(ctx, projectID, id); err != nil {
		return PullResult{}, err
	}
	return s.pull(ctx, c)
}

// pull fetches and applies; the caller holds the connector's lock.
func (s *Service) pull(ctx context.Context, c Connector) (PullResult, error) {
	fail := func(err error) (PullResult, error) {
		// last_error is visible to everyone on the project; the remote's own
		// words (response body, dial error) go to the server log only.
		slog.WarnContext(ctx, "connector request failed", "connector_id", c.ID, "error", err)
		if _, rerr := s.store.RecordFailure(context.WithoutCancel(ctx), c.ID, PublicMessage(err)); rerr != nil {
			return PullResult{}, errors.Join(err, rerr)
		}
		return PullResult{}, err
	}
	cl, err := s.client(c)
	if err != nil {
		return fail(err)
	}
	// A fetch that failed part-way never reaches ApplyFindings: applying a
	// partial view would auto-close everything that wasn't fetched.
	fs, err := cl.Fetch(ctx)
	if err != nil {
		return fail(err)
	}
	versionID, err := s.store.ResolveVersion(ctx, c.ProjectID, c.Version)
	if err != nil {
		return fail(err)
	}
	for i := range fs {
		fs[i].Metadata["connector_id"] = c.ID
	}
	sc, err := s.apply.ApplyFindings(ctx, c.ProjectID, versionID, string(c.Kind), cl.Category(fs), fs)
	if err != nil {
		return fail(fmt.Errorf("apply findings: %w", err))
	}
	updated, err := s.store.RecordSuccess(ctx, c.ID, sc.ID, len(fs))
	if err != nil {
		return PullResult{}, err
	}
	created, closed, err := s.store.Outcome(ctx, sc.ID)
	if err != nil {
		return PullResult{}, err
	}
	summary := sc.Summary
	if summary == nil {
		summary = map[string]int{}
	}
	return PullResult{Connector: updated, ScanID: sc.ID, Imported: len(fs), New: created, Closed: closed, Summary: summary}, nil
}

// RunResult tallies one scheduled run.
type RunResult struct {
	Pulled  int `json:"pulled"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// PullDue pulls every enabled connector not attempted within every. Each
// connector is isolated: one failing remote doesn't stop the others. A
// connector another instance is pulling (or just pulled) is skipped.
func (s *Service) PullDue(ctx context.Context, every time.Duration) (RunResult, error) {
	var res RunResult
	if s.cipher == nil {
		return res, nil
	}
	due, err := s.store.ListDue(ctx, every)
	if err != nil {
		return res, err
	}
	for _, c := range due {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		switch err := s.pullIfDue(ctx, c, every); {
		case errors.Is(err, errSkipped):
			res.Skipped++
		case err != nil:
			res.Failed++
			slog.WarnContext(ctx, "connector pull failed", "connector_id", c.ID, "project_id", c.ProjectID,
				"kind", c.Kind, "error", err)
		default:
			res.Pulled++
		}
	}
	return res, nil
}

var errSkipped = errors.New("skipped")

func (s *Service) pullIfDue(ctx context.Context, c Connector, every time.Duration) error {
	release, ok, err := s.store.TryLock(ctx, c.ID)
	if err != nil {
		return err
	}
	if !ok {
		return errSkipped
	}
	defer release()
	if due, err := s.store.StillDue(ctx, c.ID, every); err != nil {
		return err
	} else if !due {
		return errSkipped
	}
	if c, err = s.store.Get(ctx, c.ProjectID, c.ID); err != nil {
		return err
	}
	_, err = s.pull(ctx, c)
	return err
}

// Findings is the finding access RemoteTriage needs (implemented by
// *finding.Repository).
type Findings interface {
	SetStatus(ctx context.Context, id string, t finding.Triage) (finding.Finding, error)
	AcceptBySystem(ctx context.Context, s finding.SystemAcceptance, ids []string) ([]string, error)
}

// triageStore lists the findings a scan created with a remote verdict
// (implemented by *Repository).
type triageStore interface {
	RemoteTriageCandidates(ctx context.Context, projectID, scanID string) ([]triageCandidate, error)
}

// RemoteTriage is the post-ingest pass that carries an imported verdict over to
// the findings a scan *newly created*. Its producers write it into the
// finding's metadata: `remote_triage` (the status), `remote_triage_reason` and,
// for a risk acceptance, `remote_triage_expires` (RFC 3339). Connectors set it
// from Dependency-Track analysis / DefectDojo flags; importing parsers from the
// report's own triage. It runs last (after VEX and the triage rules) and touches
// only findings still open, so it never overturns a local decision; an existing
// finding keeps its Xila triage whatever the remote says later (the verdict
// stays visible in the metadata). The actor is the producing scanner.
//
// A carried risk acceptance becomes a risk acceptance of the project, one per
// (scanner, reason, expiry): approved at once, or — with
// RISK_ACCEPTANCE_REQUIRES_APPROVAL — a request a project owner approves
// (the findings stay open until then).
type RemoteTriage struct {
	store           triageStore
	findings        Findings
	now             func() time.Time
	requireApproval bool
}

// NewRemoteTriage constructs the pass.
func NewRemoteTriage(store *Repository, findings Findings) *RemoteTriage {
	return &RemoteTriage{store: store, findings: findings, now: time.Now}
}

// WithApproval holds carried risk acceptances for approval
// (RISK_ACCEPTANCE_REQUIRES_APPROVAL).
func (t *RemoteTriage) WithApproval(required bool) *RemoteTriage {
	t.requireApproval = required
	return t
}

// Name identifies the pass in logs.
func (*RemoteTriage) Name() string { return "remote-triage" }

// ApplyToScan applies imported verdicts to the scan's new, untriaged findings.
// A verdict that isn't a triage state, or a risk acceptance that has already
// expired (or whose expiry can't be read), leaves the finding open.
func (t *RemoteTriage) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	cands, err := t.store.RemoteTriageCandidates(ctx, projectID, scanID)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, c := range cands {
		switch c.Status {
		case domain.FindingConfirmed, domain.FindingFalsePositive, domain.FindingRiskAccepted, domain.FindingWontFix:
		default:
			continue
		}
		tr := finding.Triage{Status: c.Status, Reason: c.Reason, Actor: c.Scanner}
		if c.Expires != "" {
			exp, err := time.Parse(time.RFC3339, c.Expires)
			if err != nil || !exp.After(t.now()) {
				continue
			}
			tr.ExpiresAt = &exp
		}
		if c.Status == domain.FindingRiskAccepted {
			moved, err := t.findings.AcceptBySystem(ctx, t.importedAcceptance(projectID, c, tr), []string{c.ID})
			if err != nil {
				return changed, err
			}
			changed += len(moved)
			continue
		}
		if _, err := t.findings.SetStatus(ctx, c.ID, tr); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// importedAcceptance is the acceptance a carried risk acceptance joins: one per
// project, scanner, reason and expiry.
func (t *RemoteTriage) importedAcceptance(projectID string, c triageCandidate, tr finding.Triage) finding.SystemAcceptance {
	expiry := ""
	if tr.ExpiresAt != nil {
		expiry = tr.ExpiresAt.UTC().Format(time.RFC3339)
	}
	reason := c.Reason
	if reason == "" {
		reason = "risk accepted in " + c.Scanner
	}
	title := "Imported from " + c.Scanner + ": " + reason
	if len(title) > 120 {
		title = title[:120]
	}
	return finding.SystemAcceptance{
		ProjectID: projectID, SourceKey: "import:" + c.Scanner + "|" + c.Reason + "|" + expiry,
		Title: strings.ToValidUTF8(title, ""), Justification: reason, Actor: c.Scanner,
		ExpiresAt: tr.ExpiresAt, Approve: !t.requireApproval,
	}
}
