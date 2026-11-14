package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// xila mcp forwards each stdin line with the token and writes each reply as
// one line; a notification (202) writes nothing; an HTTP failure becomes a
// JSON-RPC error for a request, and stdout stays pure JSON-RPC.
func TestMCPStdioProxy(t *testing.T) {
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path != "/api/v1/mcp":
			http.NotFound(w, r)
		case strings.Contains(string(body), `"notifications/initialized"`):
			w.WriteHeader(http.StatusAccepted)
		case strings.Contains(string(body), `"boom"`):
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"the MCP server is disabled (MCP_ENABLED)"}`))
		default:
			w.Write([]byte("{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {}\n}"))
		}
	}))
	defer srv.Close()

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}
{"jsonrpc":"2.0","method":"notifications/initialized"}

{"jsonrpc":"2.0","id":7,"method":"boom"}
`)
	var out, errw bytes.Buffer
	if code := cmdMCP([]string{"--url", srv.URL, "--token", "xila_t"}, in, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != `{"jsonrpc":"2.0","id":1,"result":{}}` ||
		!strings.Contains(lines[1], `"id":7`) || !strings.Contains(lines[1], "MCP_ENABLED") {
		t.Fatalf("stdout:\n%s", out.String())
	}
	for _, a := range auths {
		if a != "Bearer xila_t" {
			t.Errorf("Authorization = %q", a)
		}
	}
}
