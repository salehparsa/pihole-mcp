//go:build integration

package tools

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/confirm"
	"github.com/salehparsa/pihole-mcp/internal/instances"
)

// TestIntegrationReadOnly calls every READ tool once against a live Pi-hole.
// It never registers or calls a change tool. Run with:
//
//	PIHOLE_URL=... PIHOLE_APP_PASSWORD=... go test -tags=integration -run Integration -v ./internal/tools/
func TestIntegrationReadOnly(t *testing.T) {
	url, pw := os.Getenv("PIHOLE_URL"), os.Getenv("PIHOLE_APP_PASSWORD")
	if url == "" || pw == "" {
		t.Skip("PIHOLE_URL and PIHOLE_APP_PASSWORD not set")
	}
	cfg, err := config.Load(config.Options{}, func(k string) string {
		switch k {
		case "PIHOLE_URL":
			return url
		case "PIHOLE_APP_PASSWORD":
			return pw
		case "PIHOLE_MCP_ALLOW_WRITES":
			return "false" // hard-wired: this test must never be able to change anything
		case "TZ", "PIHOLE_MCP_TIMEZONE":
			return os.Getenv(k)
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Writes.Enabled {
		t.Fatal("writes must be disabled in integration tests")
	}
	reg, err := instances.New(cfg.Instances)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close(context.Background())
	cm, _ := confirm.New("", time.Minute)
	cat, _ := catalog.Load("")
	ads, _ := analysis.NewAdMatcher("")
	srv := New(&Deps{Cfg: cfg, Reg: reg, Confirm: cm, Catalog: cat, Ads: ads, Version: "integration"})
	t1, t2 := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ss, err := srv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "it", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	calls := map[string]map[string]any{
		"list_instances": nil, "get_summary": {"period": "24h"}, "top_domains": {"count": 5}, "top_clients": {"count": 5},
		"blocked_by_device": {"period": "24h", "domains": 5}, "query_timeline": {"period": "24h"},
		"search_queries": {"limit": 5}, "list_devices": nil, "list_blocklists": nil, "list_domain_rules": nil,
		"assess_blocklists": {"sample": 10}, "network_health": nil, "get_pihole_messages": nil,
		"suggest_improvements": {"period": "24h"}, "explain_domain": {"domain": "example.com"},
	}
	for name, args := range calls {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || res.IsError {
			text := ""
			if res != nil && len(res.Content) > 0 {
				text = res.Content[0].(*mcp.TextContent).Text
			}
			t.Errorf("%s failed: %v %s", name, err, text)
			continue
		}
		t.Logf("%-22s ok: %.110s", name, strings.ReplaceAll(res.Content[0].(*mcp.TextContent).Text, "\n", " "))
	}
}
