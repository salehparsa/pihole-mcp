// Package tools registers the MCP tools, prompts and resources. It is a thin
// layer over internal/pihole (data) and internal/analysis (evidence).
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/confirm"
	"github.com/salehparsa/pihole-mcp/internal/instances"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// Deps are the collaborators every tool needs.
type Deps struct {
	Cfg     *config.Config
	Reg     *instances.Registry
	Confirm *confirm.Manager
	Catalog []catalog.Entry
	Ads     *analysis.AdMatcher
	Now     func() time.Time
	Log     *slog.Logger
	Version string
}

const serverInstructions = `Pi-hole v6 analysis and management. Every tool takes an optional "instance" (default: the first configured).
Read tools are safe. Time windows: "period" (1h, 24h, 7d, 30d) or "from"/"until" (RFC3339).
Aggregations scan the query log up to a cap and report "scanned"/"truncated" — treat truncated numbers as partial.
Change tools (only present when writes are enabled) are two-step: call once without confirm_token to get a preview and a token, show the preview to the user, and only call again with the token after they agree.`

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deps) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// New builds a configured MCP server.
func New(d *Deps) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "pihole-mcp", Version: d.Version}, &mcp.ServerOptions{
		Instructions: serverInstructions,
		Logger:       d.log(),
	})
	Register(srv, d)
	return srv
}

// Register adds all tools, prompts and resources to srv.
func Register(srv *mcp.Server, d *Deps) {
	registerUsage(srv, d)
	registerBlocklists(srv, d)
	registerHealth(srv, d)
	if d.Cfg != nil && d.Cfg.Writes.Enabled {
		registerWrites(srv, d)
	}
	registerPrompts(srv, d)
	registerResources(srv, d)
}

func ptr[T any](v T) *T { return &v }

// addRead registers a read-only tool. fn returns the structured output and a
// one-paragraph summary; both are sent (summary first, then the JSON) so
// clients that only read text content still get the data.
func addRead[In, Out any](srv *mcp.Server, name, title, desc string, fn func(context.Context, In) (Out, string, error)) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: name, Title: title, Description: desc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false), Title: title},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		out, summary, err := fn(ctx, in)
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		return textResult(summary, out), out, nil
	})
}

func textResult(summary string, out any) *mcp.CallToolResult {
	b, _ := json.Marshal(out)
	text := summary
	if text != "" {
		text += "\n\n"
	}
	text += string(b)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// client resolves the instance argument.
func (d *Deps) client(instance string) (string, *pihole.Client, error) {
	return d.Reg.Get(instance)
}

// window resolves period/from/until against the configured zone and default.
func (d *Deps) window(period, from, until string) (analysis.Range, error) {
	return analysis.ResolveRange(period, from, until, d.now(), d.Cfg.Location(), d.Cfg.Analysis.DefaultPeriod)
}

func (d *Deps) statsRange(r analysis.Range) pihole.TimeRange {
	return pihole.TimeRange{From: r.From.Unix(), Until: r.Until.Unix()}
}

// liveOK reports whether the window could be served by the in-memory (live) stats.
func (d *Deps) liveOK(r analysis.Range) bool {
	return r.Duration() <= 24*time.Hour && d.now().Sub(r.Until) < 5*time.Minute
}

// stats calls f with the database range, falling back to live stats when the
// database is unavailable and the window is within the live 24h.
func stats[T any](d *Deps, r analysis.Range, f func(pihole.TimeRange) (*T, error)) (*T, string, error) {
	v, err := f(d.statsRange(r))
	if err == nil {
		return v, "database", nil
	}
	if d.liveOK(r) {
		if v2, err2 := f(pihole.TimeRange{}); err2 == nil {
			return v2, "live (last 24h in memory; the long-term database was unavailable)", nil
		}
	}
	return nil, "", err
}

// ScanInfo tells the agent how complete an aggregation is.
type ScanInfo struct {
	Scanned   int    `json:"scanned" jsonschema:"query-log entries examined"`
	Truncated bool   `json:"truncated" jsonschema:"true when the scan cap was hit, so numbers are partial"`
	From      string `json:"covered_from" jsonschema:"start of the time range actually covered (RFC3339)"`
	Until     string `json:"covered_until" jsonschema:"end of the time range actually covered (RFC3339)"`
}

// scan pages through the query log for the window, feeding fn.
func (d *Deps) scan(ctx context.Context, c *pihole.Client, r analysis.Range, f pihole.QueryFilter, fn func(pihole.Query)) (ScanInfo, error) {
	f.From, f.Until = r.From.Unix(), r.Until.Unix()
	f.Disk = f.Disk || d.now().Sub(r.From) > 24*time.Hour
	oldest := float64(0)
	n, trunc, err := c.ScanQueries(ctx, f, d.Cfg.Analysis.MaxScan, func(q pihole.Query) bool {
		if oldest == 0 || q.Time < oldest {
			oldest = q.Time
		}
		fn(q)
		return true
	})
	info := ScanInfo{Scanned: n, Truncated: trunc, From: d.ts(r.From), Until: d.ts(r.Until)}
	if trunc && oldest > 0 {
		info.From = d.ts(time.Unix(int64(oldest), 0))
	}
	return info, err
}

func (d *Deps) ts(t time.Time) string { return t.In(d.Cfg.Location()).Format(time.RFC3339) }

func (d *Deps) unix(f float64) string { return d.ts(time.Unix(int64(f), 0)) }

// clientFilter turns an IP or a name into the matching query filter.
func clientFilter(client string, f *pihole.QueryFilter) {
	if client == "" {
		return
	}
	if net.ParseIP(client) != nil {
		f.ClientIP = client
	} else {
		f.ClientName = client
	}
}

func clamp(v, def, lo, hi int) int {
	if v == 0 {
		v = def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(int(float64(n)/float64(d)*10000+0.5)) / 100
}

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
