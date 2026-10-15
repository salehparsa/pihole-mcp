package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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
)

type env struct {
	t        *testing.T
	fake     *fakepihole.Server
	fake2    *fakepihole.Server
	cs       *mcp.ClientSession
	confirm  *confirm.Manager
	clock    *time.Time
	mu       sync.Mutex
	progress []string
	logs     *bytes.Buffer
}

type opt func(*config.Config)

func writes(on bool, allowed ...string) opt {
	return func(c *config.Config) { c.Writes.Enabled = on; c.Writes.AllowedTools = allowed }
}

func setup(t *testing.T, opts ...opt) *env {
	t.Helper()
	e := &env{t: t, fake: fakepihole.New(t), fake2: fakepihole.New(t), logs: &bytes.Buffer{}}
	cfg := config.Defaults()
	for _, o := range opts {
		o(&cfg)
	}
	mk := func(f *fakepihole.Server) *pihole.Client {
		c, err := pihole.New(pihole.Options{BaseURL: f.URL, Password: fakepihole.Password})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	reg := instances.FromClients(map[string]*pihole.Client{"home": mk(e.fake), "cabin": mk(e.fake2)}, "home", "cabin")
	cm, err := confirm.New("test-secret", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(fakepihole.Now+60, 0)
	e.clock = &now
	cm.SetClock(func() time.Time { return *e.clock })
	e.confirm = cm
	cat, _ := catalog.Load("")
	ads, _ := analysis.NewAdMatcher("")
	d := &Deps{Cfg: &cfg, Reg: reg, Confirm: cm, Catalog: cat, Ads: ads, Now: func() time.Time { return *e.clock }, Version: "test",
		Log: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	srv := New(d)
	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			e.mu.Lock()
			e.progress = append(e.progress, r.Params.Message)
			e.mu.Unlock()
		},
	})
	e.cs, err = client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.cs.Close() })
	return e
}

// call invokes a tool; it returns the structured output and the text.
func (e *env) call(name string, args map[string]any) (map[string]any, string, bool) {
	e.t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args, Meta: mcp.Meta{"progressToken": "p1"}})
	if err != nil {
		e.t.Fatalf("%s: protocol error: %v", name, err)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	var out map[string]any
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &out)
	}
	return out, text, res.IsError
}

func (e *env) ok(name string, args map[string]any) map[string]any {
	e.t.Helper()
	out, text, isErr := e.call(name, args)
	if isErr {
		e.t.Fatalf("%s returned error: %s", name, text)
	}
	return out
}

func (e *env) fail(name string, args map[string]any, want string) {
	e.t.Helper()
	_, text, isErr := e.call(name, args)
	if !isErr || !strings.Contains(text, want) {
		e.t.Fatalf("%s: want error containing %q, got isErr=%v text=%s", name, want, isErr, text)
	}
}

func (e *env) toolNames() map[string]*mcp.Tool {
	e.t.Helper()
	m := map[string]*mcp.Tool{}
	for tool, err := range e.cs.Tools(context.Background(), nil) {
		if err != nil {
			e.t.Fatal(err)
		}
		m[tool.Name] = tool
	}
	return m
}

func num(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }

var readTools = []string{"get_summary", "top_domains", "top_clients", "blocked_by_device", "client_activity", "query_timeline",
	"search_queries", "explain_domain", "list_devices", "list_instances", "list_blocklists", "list_domain_rules",
	"assess_blocklists", "network_health", "get_pihole_messages", "suggest_improvements"}
var writeTools = []string{"add_blocklist", "remove_blocklist", "set_blocklist_enabled", "add_domain_rule", "remove_domain_rule", "update_gravity", "set_blocking"}

func TestToolSurfaceReadOnlyByDefault(t *testing.T) {
	e := setup(t)
	names := e.toolNames()
	for _, n := range readTools {
		tool := names[n]
		if tool == nil {
			t.Errorf("missing read tool %s", n)
			continue
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s must be annotated read-only", n)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", n)
		}
	}
	for _, n := range writeTools {
		if names[n] != nil {
			t.Errorf("write tool %s must not be registered when writes are disabled", n)
		}
	}
}

func TestWriteToolsRegisteredAndAnnotated(t *testing.T) {
	e := setup(t, writes(true))
	names := e.toolNames()
	for _, n := range writeTools {
		tool := names[n]
		if tool == nil {
			t.Fatalf("missing write tool %s", n)
		}
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil {
			t.Errorf("%s annotations wrong: %+v", n, tool.Annotations)
		}
	}
}

func TestAllowedToolsFilter(t *testing.T) {
	e := setup(t, writes(true, "add_domain_rule", "update_gravity"))
	names := e.toolNames()
	if names["add_domain_rule"] == nil || names["update_gravity"] == nil {
		t.Fatal("allowed tools must be listed")
	}
	if names["add_blocklist"] != nil || names["set_blocking"] != nil {
		t.Fatal("tools outside allowed_tools must not be listed")
	}
	if _, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "set_blocking", Arguments: map[string]any{"enabled": false}}); err == nil {
		t.Fatal("tool outside allowed_tools must not be callable")
	}
}

func TestGetSummary(t *testing.T) {
	e := setup(t)
	// the live 24h window has full detail
	out := e.ok("get_summary", map[string]any{"period": "24h"})
	if num(out, "total_queries") != 360 || out["instance"] != "home" || !strings.HasPrefix(out["source"].(string), "live") || num(out, "gravity_domains") != 176000 {
		t.Fatalf("%v", out)
	}
	if num(out, "cached_queries") != 50 || num(out, "active_clients") != 4 || out["query_types"] == nil {
		t.Fatalf("live summary should carry the detailed breakdown: %v", out)
	}
	if !strings.HasPrefix(out["until"].(string), "2025-10-09") {
		t.Fatalf("until %v", out["until"])
	}
	e.fail("get_summary", map[string]any{"period": "banana"}, "invalid period")
}

// The long-term database summary has a different, smaller shape than the live one
// (sum_queries/sum_blocked/...). Regression test: it must not read as zeros.
func TestGetSummaryFromDatabaseShape(t *testing.T) {
	e := setup(t)
	for _, period := range []string{"7d", "1h", "12h"} {
		out := e.ok("get_summary", map[string]any{"period": period})
		if out["source"] != "database" {
			t.Fatalf("%s: source %v", period, out["source"])
		}
		total := num(out, "total_queries")
		if period == "7d" && (total != 360 || num(out, "blocked_queries") != 172 || num(out, "total_clients") != 4) {
			t.Fatalf("7d totals wrong (database shape not decoded): %v", out)
		}
		if period == "12h" && (total == 0 || total >= 360) {
			t.Fatalf("12h window should be a subset, got %v", total)
		}
		if num(out, "gravity_domains") != 176000 {
			t.Fatalf("gravity size is current state and must come from the live summary: %v", out)
		}
		for _, k := range []string{"cached_queries", "forwarded_queries", "unique_domains", "active_clients", "query_types"} {
			if _, present := out[k]; present {
				t.Fatalf("%s must be absent (unknown) for database windows, not zero: %v", k, out)
			}
		}
		if !strings.Contains(out["note"].(string), "live 24h") {
			t.Fatalf("note missing: %v", out)
		}
	}
}

// Pi-hole returns only 10 devices unless max_devices is passed.
func TestDeviceListIsNotCappedAtTen(t *testing.T) {
	e := setup(t)
	e.fake.SetExtraDevices(25)
	out := e.ok("list_devices", nil)
	if n := len(out["devices"].([]any)); n != 30 {
		t.Fatalf("want 30 devices (5 fixture + 25 extra), got %d", n)
	}
	h := e.ok("network_health", nil)
	if num(h["metrics"].(map[string]any), "known_devices") != 30 {
		t.Fatalf("health must see every device: %v", h["metrics"])
	}
}

func TestTopDomainsAndClients(t *testing.T) {
	e := setup(t)
	out := e.ok("top_domains", map[string]any{"blocked": true, "count": 3})
	doms := out["domains"].([]any)
	if len(doms) != 3 || !strings.Contains(fmt.Sprint(doms[0]), "telemetry.smart-fridge.example") {
		t.Fatalf("%v", doms)
	}
	out = e.ok("top_domains", map[string]any{"blocked": true, "client": "192.0.2.13"})
	if out["source"] != "query log" || len(out["domains"].([]any)) == 0 {
		t.Fatalf("%v", out)
	}
	if !strings.Contains(fmt.Sprint(out["domains"].([]any)[0]), "telemetry.smart-fridge.example") {
		t.Fatalf("fridge's top blocked domain should be telemetry: %v", out["domains"])
	}
	out = e.ok("top_clients", map[string]any{"count": 2})
	if len(out["clients"].([]any)) != 2 {
		t.Fatalf("%v", out)
	}
}

func TestBlockedByDevice(t *testing.T) {
	e := setup(t)
	out := e.ok("blocked_by_device", map[string]any{"domains": 5})
	rows := out["rows"].([]any)
	if len(rows) == 0 || len(rows) > 5 {
		t.Fatalf("rows %d", len(rows))
	}
	scan := out["scan"].(map[string]any)
	if num(scan, "scanned") != 360 || scan["truncated"] != false {
		t.Fatalf("scan %v", scan)
	}
	row := rows[0].(map[string]any)
	if len(row["devices"].([]any)) == 0 || row["devices"].([]any)[0].(map[string]any)["name"] == "" {
		t.Fatalf("devices missing: %v", row)
	}
	// filtering by client only counts that client
	out = e.ok("blocked_by_device", map[string]any{"client": "kids-tablet"})
	for _, r := range out["rows"].([]any) {
		for _, d := range r.(map[string]any)["devices"].([]any) {
			if d.(map[string]any)["name"] != "kids-tablet" {
				t.Fatalf("leaked another device: %v", d)
			}
		}
	}
}

func TestScanTruncationReported(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Analysis.MaxScan = 50 })
	out := e.ok("blocked_by_device", nil)
	scan := out["scan"].(map[string]any)
	if scan["truncated"] != true || num(scan, "scanned") != 50 {
		t.Fatalf("scan %v", scan)
	}
	_, text, _ := e.call("blocked_by_device", nil)
	if !strings.Contains(text, "TRUNCATED") {
		t.Fatalf("summary must say truncated: %s", text)
	}
	if scan["covered_from"] == scan["covered_until"] || !strings.HasPrefix(scan["covered_from"].(string), "2025-10-0") {
		t.Fatalf("covered range %v", scan)
	}
}

func TestClientActivity(t *testing.T) {
	e := setup(t)
	out := e.ok("client_activity", map[string]any{"client": "smart-fridge"})
	act := out["activity"].(map[string]any)
	if out["found"] != true || act["ip"] != "192.0.2.13" || num(act, "block_ratio") < 0.7 {
		t.Fatalf("%v", out)
	}
	if len(act["top_blocked"].([]any)) == 0 {
		t.Fatal("expected top blocked")
	}
	out = e.ok("client_activity", map[string]any{"client": "203.0.113.99"})
	if out["found"] != false {
		t.Fatalf("unknown client: %v", out)
	}
	e.fail("client_activity", map[string]any{"client": " "}, "client is required")
}

func TestQueryTimelineAndSearch(t *testing.T) {
	e := setup(t)
	out := e.ok("query_timeline", map[string]any{"bucket": "1h"})
	if len(out["buckets"].([]any)) == 0 {
		t.Fatalf("%v", out)
	}
	out = e.ok("query_timeline", map[string]any{"client": "192.0.2.12", "bucket": "6h"})
	if out["source"] != "query log" || len(out["buckets"].([]any)) == 0 {
		t.Fatalf("%v", out)
	}
	// pagination covers every query exactly once
	seen := map[float64]bool{}
	cursor := 0.0
	for page := 0; page < 20; page++ {
		args := map[string]any{"limit": 100, "period": "30d"}
		if cursor > 0 {
			args["cursor"] = cursor
		}
		out = e.ok("search_queries", args)
		for _, q := range out["queries"].([]any) {
			id := q.(map[string]any)["id"].(float64)
			if seen[id] {
				t.Fatalf("duplicate id %v across pages", id)
			}
			seen[id] = true
		}
		cursor, _ = out["next_cursor"].(float64)
		if cursor == 0 {
			break
		}
	}
	if len(seen) != 360 {
		t.Fatalf("paged %d queries, want 360", len(seen))
	}
	out = e.ok("search_queries", map[string]any{"status": "GRAVITY", "limit": 5, "client": "192.0.2.13"})
	for _, q := range out["queries"].([]any) {
		if q.(map[string]any)["blocked"] != true {
			t.Fatalf("not blocked: %v", q)
		}
	}
}

func TestExplainDomain(t *testing.T) {
	e := setup(t)
	out := e.ok("explain_domain", map[string]any{"domain": "pixel.example-track.net"})
	if out["verdict"] != "blocked" || len(out["matches"].([]any)) != 2 || out["recent"] == nil {
		t.Fatalf("%v", out)
	}
	out = e.ok("explain_domain", map[string]any{"domain": "ads.example-tracker.net"})
	if out["verdict"] != "allowed" || !strings.Contains(out["reason"].(string), "allow rule") {
		t.Fatalf("allow rule must win over lists: %v", out)
	}
	out = e.ok("explain_domain", map[string]any{"domain": "unknown.example.org"})
	if out["verdict"] != "not_matched" {
		t.Fatalf("%v", out)
	}
	e.fail("explain_domain", map[string]any{"domain": ""}, "domain is required")
}

func TestListDevicesAndInstances(t *testing.T) {
	e := setup(t)
	out := e.ok("list_devices", nil)
	devs := out["devices"].([]any)
	if len(devs) != 5 {
		t.Fatalf("%v", devs)
	}
	first := devs[0].(map[string]any)
	if first["mac"] == "" || len(first["ips"].([]any)) == 0 {
		t.Fatalf("%v", first)
	}
	out = e.ok("list_instances", nil)
	insts := out["instances"].([]any)
	if len(insts) != 2 || insts[0].(map[string]any)["default"] != true || insts[0].(map[string]any)["ftl_version"] != "v6.7.1" {
		t.Fatalf("%v", out)
	}
	if strings.Contains(fmt.Sprint(out), fakepihole.Password) {
		t.Fatal("secrets must never be returned")
	}
}

func TestMultiInstanceSelection(t *testing.T) {
	e := setup(t)
	e.ok("get_summary", map[string]any{"instance": "cabin"})
	before := len(e.fake.Calls())
	if len(e.fake2.Calls()) == 0 {
		t.Fatal("cabin instance not used")
	}
	e.ok("get_summary", nil)
	if len(e.fake.Calls()) == before {
		t.Fatal("default instance not used")
	}
	e.fail("get_summary", map[string]any{"instance": "nope"}, `unknown instance "nope"`)
}

func TestBlocklistsAndAssessment(t *testing.T) {
	e := setup(t)
	out := e.ok("list_blocklists", nil)
	if len(out["lists"].([]any)) != 5 || num(out, "total_domains") != 150000+20000+0+1000 {
		t.Fatalf("%v", out)
	}
	out = e.ok("list_domain_rules", map[string]any{"type": "allow", "kind": "regex"})
	if len(out["rules"].([]any)) != 1 {
		t.Fatalf("%v", out)
	}
	e.fail("list_domain_rules", map[string]any{"kind": "regex"}, "kind requires type")

	out = e.ok("assess_blocklists", map[string]any{"sample": 20})
	text := fmt.Sprint(out["findings"])
	for _, want := range []string{"List failed to download", "List has not been updated recently", "List is disabled", "List has many invalid entries", "extremely broad"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing finding %q", want)
		}
	}
	if num(out, "sample_size") == 0 || out["contribution"] == nil {
		t.Fatalf("attribution missing: %v", out)
	}
	first := out["findings"].([]any)[0].(map[string]any)
	if first["severity"] != "critical" {
		t.Fatalf("critical findings first: %v", first)
	}
}

func TestNetworkHealth(t *testing.T) {
	e := setup(t)
	out := e.ok("network_health", nil)
	text := fmt.Sprint(out["findings"])
	for _, want := range []string{"Device may be bypassing Pi-hole", "FTL diagnostic: DNSMASQ_WARN", "Single upstream resolver", "Update available: FTL"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	m := out["metrics"].(map[string]any)
	if m["cpu_temp_c"] != 52.3 || num(m, "known_devices") != 5 {
		t.Fatalf("metrics %v", m)
	}
	// a failing data source degrades, it does not fail the tool
	e.fake.FailPath("/info/sensors", 500)
	out = e.ok("network_health", nil)
	if len(out["unavailable"].([]any)) == 0 {
		t.Fatal("unavailable sources must be reported")
	}
	out = e.ok("get_pihole_messages", nil)
	if len(out["messages"].([]any)) != 1 {
		t.Fatalf("%v", out)
	}
}

func TestSuggestImprovements(t *testing.T) {
	e := setup(t)
	out := e.ok("suggest_improvements", map[string]any{"period": "7d"})
	text := fmt.Sprint(out["findings"])
	for _, want := range []string{"Device has a very high block ratio", "Catalog list not installed", "List failed to download"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	if !strings.Contains(text, "looks like an ad/tracker") {
		t.Errorf("expected an ad-pattern suggestion: %s", text)
	}
}

func TestPromptsAndResources(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	n := 0
	for p, err := range e.cs.Prompts(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		n++
		args := map[string]string{}
		if p.Name == "investigate_device" {
			args["client"] = "192.0.2.12"
		}
		res, err := e.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: args})
		if err != nil || len(res.Messages) == 0 {
			t.Fatalf("%s: %v", p.Name, err)
		}
		txt := res.Messages[0].Content.(*mcp.TextContent).Text
		if !strings.Contains(txt, "two-step") && p.Name != "weekly_report" {
			t.Errorf("%s should mention the preview rule", p.Name)
		}
	}
	if n != 4 {
		t.Fatalf("want 4 prompts, got %d", n)
	}
	if _, err := e.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "investigate_device"}); err == nil {
		t.Fatal("client argument must be required")
	}
	res, err := e.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "pihole://catalog/blocklists"})
	if err != nil || !strings.Contains(res.Contents[0].Text, "hagezi") {
		t.Fatalf("catalog resource: %v", err)
	}
	res, err = e.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "pihole://cabin/status"})
	if err != nil || !strings.Contains(res.Contents[0].Text, "ftl_version") {
		t.Fatalf("status resource: %v", err)
	}
}

// ---- change tools

func TestPreviewChangesNothingConfirmApplies(t *testing.T) {
	e := setup(t, writes(true))
	args := map[string]any{"domain": "mcp-test.invalid", "type": "deny"}
	out := e.ok("add_domain_rule", args)
	if out["mode"] != "preview" || out["confirm_token"] == "" || out["confirm_token"] == nil {
		t.Fatalf("%v", out)
	}
	if len(e.fake.WriteCalls()) != 0 {
		t.Fatalf("preview must not write: %v", e.fake.WriteCalls())
	}
	if !strings.Contains(out["request"].(string), "POST /api/domains/deny/exact") || out["impact"] == "" {
		t.Fatalf("preview must show the request and impact: %v", out)
	}
	args["confirm_token"] = out["confirm_token"]
	out = e.ok("add_domain_rule", args)
	if out["mode"] != "applied" {
		t.Fatalf("%v", out)
	}
	if w := e.fake.WriteCalls(); len(w) != 1 || !strings.HasPrefix(w[0], "POST /api/domains/deny/exact") {
		t.Fatalf("writes %v", w)
	}
	rules := e.ok("list_domain_rules", map[string]any{"type": "deny", "kind": "exact"})
	if !strings.Contains(fmt.Sprint(rules), "mcp-test.invalid") {
		t.Fatal("rule not added")
	}
	// the same call again is refused: rule exists
	e.fail("add_domain_rule", map[string]any{"domain": "mcp-test.invalid", "type": "deny"}, "already exists")

	// removal is also two-step
	rm := map[string]any{"domain": "mcp-test.invalid", "type": "deny"}
	pre := e.ok("remove_domain_rule", rm)
	if pre["mode"] != "preview" || len(e.fake.WriteCalls()) != 1 {
		t.Fatalf("remove preview wrote: %v", e.fake.WriteCalls())
	}
	rm["confirm_token"] = pre["confirm_token"]
	e.ok("remove_domain_rule", rm)
	if w := e.fake.WriteCalls(); len(w) != 2 || !strings.HasPrefix(w[1], "DELETE /api/domains/deny/exact/mcp-test.invalid") {
		t.Fatalf("writes %v", w)
	}
}

func TestTamperedAndExpiredTokensRejected(t *testing.T) {
	e := setup(t, writes(true))
	pre := e.ok("add_domain_rule", map[string]any{"domain": "a.invalid", "type": "deny"})
	tok := pre["confirm_token"]

	e.fail("add_domain_rule", map[string]any{"domain": "b.invalid", "type": "deny", "confirm_token": tok}, "does not match")
	e.fail("add_domain_rule", map[string]any{"domain": "a.invalid", "type": "allow", "confirm_token": tok}, "does not match")
	e.fail("add_domain_rule", map[string]any{"domain": "a.invalid", "type": "deny", "confirm_token": "garbage"}, "malformed")
	e.fail("add_domain_rule", map[string]any{"instance": "cabin", "domain": "a.invalid", "type": "deny", "confirm_token": tok}, "does not match")
	if len(e.fake.WriteCalls())+len(e.fake2.WriteCalls()) != 0 {
		t.Fatal("rejected tokens must not write")
	}
	*e.clock = e.clock.Add(6 * time.Minute)
	e.fail("add_domain_rule", map[string]any{"domain": "a.invalid", "type": "deny", "confirm_token": tok}, "expired")
	if len(e.fake.WriteCalls()) != 0 {
		t.Fatal("expired token must not write")
	}
}

func TestDomainRuleValidation(t *testing.T) {
	e := setup(t, writes(true))
	e.fail("add_domain_rule", map[string]any{"domain": "bad domain!", "type": "deny"}, "not a valid host name")
	e.fail("add_domain_rule", map[string]any{"domain": "x.example", "type": "block"}, "type must be allow or deny")
	e.fail("add_domain_rule", map[string]any{"domain": ".*", "type": "allow", "kind": "regex"}, "over-broad")
	e.fail("add_domain_rule", map[string]any{"domain": "x.example", "type": "deny", "kind": "glob"}, "kind must be")
	e.fail("remove_domain_rule", map[string]any{"domain": "nothere.example", "type": "deny"}, "no deny exact rule")
	// a regex deny preview estimates impact from the query log
	out := e.ok("add_domain_rule", map[string]any{"domain": `(^|\.)example-tracker\.net$`, "type": "deny", "kind": "regex"})
	if !strings.Contains(out["impact"].(string), "allowed queries") {
		t.Fatalf("%v", out["impact"])
	}
}

func TestBlocklistChanges(t *testing.T) {
	e := setup(t, writes(true))
	e.fail("add_blocklist", map[string]any{"address": "ftp://x.example/l.txt"}, "http(s) URL")
	e.fail("add_blocklist", map[string]any{"address": "https://lists.example.org/pro.txt"}, "already installed")
	args := map[string]any{"address": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt", "comment": "test"}
	pre := e.ok("add_blocklist", args)
	if !strings.Contains(fmt.Sprint(pre["warnings"]), "Known list: HaGeZi Light") {
		t.Fatalf("catalog hint missing: %v", pre["warnings"])
	}
	args["confirm_token"] = pre["confirm_token"]
	e.ok("add_blocklist", args)
	if !strings.Contains(fmt.Sprint(e.ok("list_blocklists", nil)), "hagezi") {
		t.Fatal("list not added (cache must be invalidated)")
	}

	en := map[string]any{"address": "https://lists.example.org/pro.txt", "enabled": false}
	pre = e.ok("set_blocklist_enabled", en)
	en["confirm_token"] = pre["confirm_token"]
	e.ok("set_blocklist_enabled", en)
	e.fail("set_blocklist_enabled", map[string]any{"address": "https://lists.example.org/pro.txt", "enabled": false}, "already enabled=false")

	rm := map[string]any{"address": "https://lists.example.org/stale.txt"}
	pre = e.ok("remove_blocklist", rm)
	if !strings.Contains(pre["impact"].(string), "20000") {
		t.Fatalf("%v", pre)
	}
	rm["confirm_token"] = pre["confirm_token"]
	e.ok("remove_blocklist", rm)
	e.fail("remove_blocklist", map[string]any{"address": "https://lists.example.org/stale.txt"}, "no installed list")
}

func TestSetBlocking(t *testing.T) {
	e := setup(t, writes(true))
	e.fail("set_blocking", map[string]any{"enabled": true}, "already enabled")
	args := map[string]any{"enabled": false, "timer_seconds": 300}
	pre := e.ok("set_blocking", args)
	if !strings.Contains(pre["impact"].(string), "ALL DNS filtering stops") {
		t.Fatalf("%v", pre)
	}
	args["confirm_token"] = pre["confirm_token"]
	out := e.ok("set_blocking", args)
	if !strings.Contains(out["result"].(string), "disabled") {
		t.Fatalf("%v", out)
	}
	noTimer := e.ok("set_blocking", map[string]any{"enabled": true})
	_ = noTimer
	pre = e.ok("set_blocking", map[string]any{"enabled": false})
	if !strings.Contains(fmt.Sprint(pre["warnings"]), "No timer") {
		t.Fatalf("missing no-timer warning: %v", pre)
	}
}

func TestUpdateGravityStreamsProgress(t *testing.T) {
	e := setup(t, writes(true))
	pre := e.ok("update_gravity", nil)
	if pre["mode"] != "preview" || len(e.fake.WriteCalls()) != 0 {
		t.Fatalf("%v", pre)
	}
	out := e.ok("update_gravity", map[string]any{"confirm_token": pre["confirm_token"]})
	lines := out["output"].([]any)
	if out["mode"] != "applied" || len(lines) != 4 || !strings.Contains(out["result"].(string), "176000") {
		t.Fatalf("%v", out)
	}
	time.Sleep(50 * time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.progress) != 4 || !strings.Contains(e.progress[3], "Done") {
		t.Fatalf("progress notifications: %v", e.progress)
	}
}

func TestWritesDisabledCannotBeCalled(t *testing.T) {
	e := setup(t)
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "add_domain_rule", Arguments: map[string]any{"domain": "x.invalid", "type": "deny"}})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("calling an unregistered write tool must fail")
	}
	if len(e.fake.WriteCalls()) != 0 {
		t.Fatal("no write may reach Pi-hole")
	}
}

func TestToolsMarkdownIsStable(t *testing.T) {
	a, err := Markdown(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Markdown(context.Background())
	if a != b {
		t.Fatal("docs generation must be deterministic")
	}
	for _, n := range append(append([]string{}, readTools...), writeTools...) {
		if !strings.Contains(a, "## "+n+"\n") {
			t.Errorf("docs missing %s", n)
		}
	}
}

func TestAuditLogRecordsAppliedChangesOnly(t *testing.T) {
	e := setup(t, writes(true))
	args := map[string]any{"domain": "audit.invalid", "type": "deny"}
	pre := e.ok("add_domain_rule", args)
	if strings.Contains(e.logs.String(), "event=audit") {
		t.Fatal("previews must not be audited as changes")
	}
	args["confirm_token"] = pre["confirm_token"]
	e.ok("add_domain_rule", args)
	logs := e.logs.String()
	if !strings.Contains(logs, "event=audit") || !strings.Contains(logs, "tool=add_domain_rule") || !strings.Contains(logs, "audit.invalid") || !strings.Contains(logs, "instance=home") {
		t.Fatalf("audit entry incomplete:\n%s", logs)
	}
	if strings.Contains(logs, fakepihole.Password) || strings.Contains(logs, pre["confirm_token"].(string)) {
		t.Fatal("secrets and tokens must not be logged")
	}
}
