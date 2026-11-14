package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cmdMCP bridges MCP's stdio transport — newline-delimited JSON-RPC on
// stdin/stdout, what desktop AI clients launch — to the server's Streamable
// HTTP endpoint (POST /api/v1/mcp, MCP_ENABLED). Every message is forwarded
// with the token, so the agent acts with exactly the token's permissions.
// stdout carries JSON-RPC only; diagnostics go to stderr.
func cmdMCP(args []string, in io.Reader, out, errw io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(errw)
	url, token, oidcToken := globalFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bearer, err := resolveToken(*url, *token, *oidcToken, errw)
	if err != nil {
		fmt.Fprintln(errw, "xila mcp:", err)
		return 2
	}
	endpoint := strings.TrimRight(*url, "/") + "/api/v1/mcp"
	hc := &http.Client{Timeout: 5 * time.Minute} // an upload_scan can take a while
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20) // a report argument can be large
	w := bufio.NewWriter(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		reply := forwardMCP(hc, endpoint, bearer, line, errw)
		if reply != nil {
			w.Write(reply)
			w.WriteByte('\n')
			w.Flush()
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(errw, "xila mcp: read stdin:", err)
		return 2
	}
	return 0
}

// forwardMCP posts one message and returns the line to write back (nil for
// none: a notification, or a transport failure on a message without an id).
func forwardMCP(hc *http.Client, endpoint, bearer string, msg []byte, errw io.Writer) []byte {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(msg, &probe)
	fail := func(text string) []byte {
		fmt.Fprintln(errw, "xila mcp:", text)
		if len(probe.ID) == 0 {
			return nil
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": probe.ID,
			"error": map[string]any{"code": -32000, "message": text}})
		return b
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(msg))
	if err != nil {
		return fail(err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := hc.Do(req)
	if err != nil {
		return fail(err.Error())
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fail(err.Error())
	}
	switch {
	case res.StatusCode == http.StatusAccepted:
		return nil
	case res.StatusCode != http.StatusOK:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return fail(fmt.Sprintf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(e.Error)))
	}
	// One line per message: compact whatever the server indented.
	var compact bytes.Buffer
	if json.Compact(&compact, body) != nil {
		return fail("the server's reply is not JSON")
	}
	return compact.Bytes()
}
