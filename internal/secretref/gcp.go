package secretref

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpScope is the OAuth scope Secret Manager needs.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform"

// defaultGCPBaseURL is the Secret Manager REST API.
const defaultGCPBaseURL = "https://secretmanager.googleapis.com"

// gcpBackend resolves gcp-sm:// references over plain HTTPS (not the gRPC
// client), authenticating with Application Default Credentials: workload
// identity, the GCE/GKE metadata server, or GOOGLE_APPLICATION_CREDENTIALS.
type gcpBackend struct {
	ts onceValue[oauth2.TokenSource]
}

func (b *gcpBackend) ensure(ctx context.Context) (oauth2.TokenSource, error) {
	return b.ts.get(func() (oauth2.TokenSource, error) {
		creds, err := google.FindDefaultCredentials(ctx, gcpScope)
		if err != nil {
			return nil, fmt.Errorf("application default credentials: %w", err)
		}
		return creds.TokenSource, nil
	})
}

// gcpResourceName turns "projects/<p>/secrets/<s>[/versions/<v>]" into the
// full resource name with an explicit version (default "latest").
func gcpResourceName(path string) (string, error) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(segs) == 4 && segs[0] == "projects" && segs[2] == "secrets":
		return path + "/versions/latest", nil
	case len(segs) == 6 && segs[0] == "projects" && segs[2] == "secrets" && segs[4] == "versions":
		return path, nil
	default:
		return "", fmt.Errorf("%q is not projects/<p>/secrets/<s>[/versions/<v>]", path)
	}
}

// gcpAccessResponse is the Secret Manager REST API's
// projects.secrets.versions.access response.
type gcpAccessResponse struct {
	Payload struct {
		Data       string `json:"data"`
		DataCRC32C string `json:"dataCrc32c"`
	} `json:"payload"`
}

func (b *gcpBackend) resolve(ctx context.Context, r ref, tsOverride oauth2.TokenSource, baseURLOverride string) (string, error) {
	name, err := gcpResourceName(r.path)
	if err != nil {
		return "", err
	}
	ts := tsOverride
	if ts == nil {
		if ts, err = b.ensure(ctx); err != nil {
			return "", err
		}
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	base := cmp.Or(baseURLOverride, defaultGCPBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/"+name+":access", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out gcpAccessResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("invalid response: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}
	if out.Payload.DataCRC32C != "" {
		want, err := strconv.ParseUint(out.Payload.DataCRC32C, 10, 32)
		if err == nil {
			if got := uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))); got != want {
				return "", fmt.Errorf("checksum mismatch")
			}
		}
	}
	return jsonField(string(data), r.key)
}
