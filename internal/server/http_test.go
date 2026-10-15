package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/confirm"
	"github.com/salehparsa/pihole-mcp/internal/instances"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
	"github.com/salehparsa/pihole-mcp/internal/testutil/fakepihole"
	"github.com/salehparsa/pihole-mcp/internal/tools"
)

const token = "s3cret-token"

func newTestServer(t *testing.T, fake *fakepihole.Server, origins ...string) *httptest.Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.Transport, cfg.Server.AuthToken, cfg.Server.AllowedOrigins = "http", token, origins
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, _ := pihole.New(pihole.Options{BaseURL: fake.URL, Password: fakepihole.Password})
	reg := instances.FromClients(map[string]*pihole.Client{"home": c}, "home")
	cm, _ := confirm.New("x", time.Minute)
	cat, _ := catalog.Load("")
	ads, _ := analysis.NewAdMatcher("")
	mcpSrv := tools.New(&tools.Deps{Cfg: &cfg, Reg: reg, Confirm: cm, Catalog: cat, Ads: ads, Log: log, Version: "t",
		Now: func() time.Time { return time.Unix(fakepihole.Now+60, 0) }})
	ts := httptest.NewServer(Handler(&cfg, mcpSrv, reg, log))
	t.Cleanup(ts.Close)
	return ts
}

// result is the part of a response the tests inspect (the body is already closed).
type result struct {
	StatusCode int
	Header     http.Header
}

func do(t *testing.T, method, url string, hdr map[string]string, body string) result {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return result{resp.StatusCode, resp.Header}
}

func TestHealthEndpointsNeedNoAuth(t *testing.T) {
	ts := newTestServer(t, fakepihole.New(t))
	if r := do(t, "GET", ts.URL+"/healthz", nil, ""); r.StatusCode != 200 {
		t.Fatalf("healthz %d", r.StatusCode)
	}
	if r := do(t, "GET", ts.URL+"/readyz", nil, ""); r.StatusCode != 200 {
		t.Fatalf("readyz %d", r.StatusCode)
	}
}

func TestReadyzFailsWhenPiholeDown(t *testing.T) {
	fake := fakepihole.New(t)
	ts := newTestServer(t, fake)
	fake.Close()
	if r := do(t, "GET", ts.URL+"/readyz", nil, ""); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d", r.StatusCode)
	}
	if r := do(t, "GET", ts.URL+"/healthz", nil, ""); r.StatusCode != 200 {
		t.Fatal("liveness must not depend on Pi-hole")
	}
}

func TestMCPEndpointRequiresBearer(t *testing.T) {
	ts := newTestServer(t, fakepihole.New(t))
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	hdr["Authorization"] = "Bearer wrong"
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 401 {
		t.Fatalf("wrong token: %d", r.StatusCode)
	}
	hdr["Authorization"] = "Basic " + token
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 401 {
		t.Fatalf("wrong scheme: %d", r.StatusCode)
	}
	hdr["Authorization"] = "Bearer " + token
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 200 {
		t.Fatalf("good token: %d", r.StatusCode)
	}
}

func TestOriginCheck(t *testing.T) {
	ts := newTestServer(t, fakepihole.New(t), "https://app.example")
	hdr := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	hdr["Origin"] = "https://evil.example"
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 403 {
		t.Fatalf("evil origin: %d", r.StatusCode)
	}
	hdr["Origin"] = "https://app.example"
	if r := do(t, "POST", ts.URL+"/mcp", hdr, init); r.StatusCode != 200 {
		t.Fatalf("allowed origin: %d", r.StatusCode)
	}
	// with no allowed origins configured, any browser Origin is refused
	ts2 := newTestServer(t, fakepihole.New(t))
	if r := do(t, "POST", ts2.URL+"/mcp", hdr, init); r.StatusCode != 403 {
		t.Fatalf("default must refuse browser origins: %d", r.StatusCode)
	}
}

func TestBodyLimit(t *testing.T) {
	ts := newTestServer(t, fakepihole.New(t))
	hdr := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":"` + strings.Repeat("a", MaxBodyBytes+10) + `"}`
	if r := do(t, "POST", ts.URL+"/mcp", hdr, big); r.StatusCode < 400 {
		t.Fatalf("oversized body accepted: %d", r.StatusCode)
	}
}

type bearerRT struct{ base http.RoundTripper }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return b.base.RoundTrip(r)
}

func TestFullMCPSessionOverHTTP(t *testing.T) {
	ts := newTestServer(t, fakepihole.New(t))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{http.DefaultTransport}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_summary", Arguments: map[string]any{"period": "24h"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "360 queries") {
		t.Fatalf("%s", res.Content[0].(*mcp.TextContent).Text)
	}
}
