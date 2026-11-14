package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/netguard"
)

const epssAPI = "https://api.first.org/data/v1/epss"

// HTTPSource fetches EPSS (FIRST.org) over HTTP. It satisfies EPSSSource.
type HTTPSource struct {
	client *http.Client
}

// NewHTTPSource constructs an HTTP-backed EPSS source.
func NewHTTPSource() *HTTPSource {
	return &HTTPSource{client: netguard.NewClient(30 * time.Second)}
}

// Scores fetches EPSS probabilities, chunking CVEs to keep request URLs sane.
func (h *HTTPSource) Scores(ctx context.Context, cves []string) (map[string]float64, error) {
	out := make(map[string]float64, len(cves))
	const chunk = 100
	for i := 0; i < len(cves); i += chunk {
		batch := cves[i:min(i+chunk, len(cves))]
		u := epssAPI + "?cve=" + url.QueryEscape(strings.Join(batch, ","))

		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := h.getJSON(ctx, u, &resp); err != nil {
			return nil, err
		}
		for _, d := range resp.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = f
			}
		}
	}
	return out, nil
}

func (h *HTTPSource) getJSON(ctx context.Context, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", u, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: %s", u, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(dst)
}
