package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

func registerHealth(srv *mcp.Server, d *Deps) {
	addRead(srv, "network_health", "Network health",
		"Health check of Pi-hole and its DNS service: host load/memory/temperature, FTL diagnostics, upstream latency and diversity, cache/NXDOMAIN/SERVFAIL rates, DNSSEC failures, available updates, and devices that may be bypassing Pi-hole. Returns findings with metrics.",
		d.networkHealth)
	addRead(srv, "get_pihole_messages", "Pi-hole diagnostic messages",
		"FTL diagnostic messages (warnings about misconfiguration, database problems, etc.) exactly as Pi-hole reports them.",
		d.piholeMessages)
	addRead(srv, "suggest_improvements", "Suggest improvements",
		"Ranked evidence for improving ad blocking and the network: frequently allowed domains that look like ads/trackers, devices with unusually high block ratios, block-list problems, well-known lists that are not installed, and health issues. The server provides evidence; you write the advice.",
		d.suggestImprovements)
}

// NetworkHealthIn is the input of network_health.
type NetworkHealthIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Window for upstream statistics and DNSSEC failures (default 24h); cache/NXDOMAIN/SERVFAIL rates always use the live last 24h"`
}

// NetworkHealthOut is the output of network_health.
type NetworkHealthOut struct {
	Instance    string             `json:"instance"`
	Findings    []analysis.Finding `json:"findings"`
	Metrics     map[string]any     `json:"metrics"`
	Unavailable []string           `json:"unavailable,omitempty" jsonschema:"data sources that could not be read, so related checks were skipped"`
}

func (d *Deps) collectHealth(ctx context.Context, name string, c *pihole.Client, period string) (analysis.HealthInput, map[string]any, []string, error) {
	r, err := d.window(period, "", "")
	if err != nil {
		return analysis.HealthInput{}, nil, nil, err
	}
	in := analysis.HealthInput{Now: d.now()}
	metrics := map[string]any{}
	var unavailable []string
	note := func(what string, err error) {
		unavailable = append(unavailable, what+": "+err.Error())
	}
	if v, err := c.Info(ctx, "system"); err != nil {
		note("info/system", err)
	} else {
		in.System = v
	}
	if v, err := c.Info(ctx, "sensors"); err != nil {
		note("info/sensors", err)
	} else {
		in.Sensors = v
	}
	if v, err := c.Info(ctx, "database"); err != nil {
		note("info/database", err)
	} else {
		in.Database = v
	}
	if v, err := c.Info(ctx, "version"); err != nil {
		note("info/version", err)
	} else {
		in.Version = v
	}
	if v, err := c.Messages(ctx); err != nil {
		note("info/messages", err)
	} else {
		in.Messages = v
	}
	if v, _, err := stats(d, r, func(tr pihole.TimeRange) (*pihole.Upstreams, error) { return c.Upstreams(ctx, tr) }); err != nil {
		note("stats/upstreams", err)
	} else {
		in.Upstream = v
	}
	// rates (cache, NXDOMAIN, SERVFAIL) need the detailed live summary of the last 24h
	if v, err := c.Summary(ctx, pihole.TimeRange{}); err != nil {
		note("stats/summary", err)
	} else {
		in.Summary = v
		metrics["total_queries"] = v.Queries.Total
		metrics["blocked_percent"] = pct(v.Queries.Blocked, v.Queries.Total)
		metrics["cache_hit_percent"] = pct(v.Queries.Cached, v.Queries.Total)
		metrics["nxdomain_percent"] = pct(v.Queries.Replies["NXDOMAIN"], v.Queries.Total)
		metrics["servfail_percent"] = pct(v.Queries.Replies["SERVFAIL"], v.Queries.Total)
		metrics["gravity_domains"] = v.Gravity.DomainsBeingBlocked
	}
	if v, err := c.Devices(ctx); err != nil {
		note("network/devices", err)
	} else {
		in.Devices = v
		metrics["known_devices"] = len(v)
	}
	if page, err := c.Queries(ctx, pihole.QueryFilter{From: r.From.Unix(), Until: r.Until.Unix(), DNSSEC: "BOGUS", Length: 1, Disk: d.now().Sub(r.From) > 24*time.Hour}); err != nil {
		note("queries (dnssec)", err)
	} else {
		in.BogusDNSSEC = page.RecordsFiltered
		if in.Summary != nil {
			in.SampleSize = in.Summary.Queries.Total
		}
	}
	if in.Upstream != nil {
		metrics["upstreams"] = len(in.Upstream.Upstreams)
		var worst float64
		for _, u := range in.Upstream.Upstreams {
			if u.Statistics.Response > worst {
				worst = u.Statistics.Response
			}
		}
		metrics["slowest_upstream_ms"] = int(worst * 1000)
	}
	for k, path := range map[string][]string{
		"ram_percent": {"system", "memory", "ram", "%used"}, "swap_percent": {"system", "memory", "swap", "%used"},
		"cpu_percent": {"system", "cpu", "%cpu"},
	} {
		if in.System != nil {
			if v, ok := digNum(in.System, path...); ok {
				metrics[k] = v
			}
		}
	}
	if in.Sensors != nil {
		if v, ok := digNum(in.Sensors, "sensors", "cpu_temp"); ok {
			metrics["cpu_temp_c"] = v
		}
	}
	if in.Database != nil {
		if v, ok := digNum(in.Database, "size"); ok {
			metrics["database_bytes"] = v
		}
	}
	_ = name
	return in, metrics, unavailable, nil
}

// healthSources is the number of data sources collectHealth reads.
const healthSources = 9

func digNum(m map[string]any, path ...string) (float64, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = mm[p]
	}
	f, ok := cur.(float64)
	return f, ok
}

func (d *Deps) networkHealth(ctx context.Context, in NetworkHealthIn) (NetworkHealthOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return NetworkHealthOut{}, "", err
	}
	hin, metrics, unavailable, err := d.collectHealth(ctx, name, c, in.Period)
	if err != nil {
		return NetworkHealthOut{}, "", err
	}
	if len(unavailable) >= healthSources { // nothing at all could be read
		return NetworkHealthOut{}, "", errf("could not read any health data from %s: %s", name, strings.Join(unavailable[:1], "; "))
	}
	out := NetworkHealthOut{Instance: name, Findings: analysis.Health(hin), Metrics: metrics, Unavailable: unavailable}
	if out.Findings == nil {
		out.Findings = []analysis.Finding{}
	}
	crit, warn := 0, 0
	for _, f := range out.Findings {
		switch f.Severity {
		case analysis.SevCritical:
			crit++
		case analysis.SevWarning:
			warn++
		}
	}
	return out, fmt.Sprintf("%s health: %d critical, %d warning, %d total findings; %d data sources unavailable.", name, crit, warn, len(out.Findings), len(unavailable)), nil
}

// PiholeMessagesIn is the input of get_pihole_messages.
type PiholeMessagesIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
}

// MessageOut is one FTL diagnostic message.
type MessageOut struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Text string `json:"text"`
	Time string `json:"time,omitempty"`
}

// PiholeMessagesOut is the output of get_pihole_messages.
type PiholeMessagesOut struct {
	Instance string       `json:"instance"`
	Messages []MessageOut `json:"messages"`
}

func (d *Deps) piholeMessages(ctx context.Context, in PiholeMessagesIn) (PiholeMessagesOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return PiholeMessagesOut{}, "", err
	}
	ms, err := c.Messages(ctx)
	if err != nil {
		return PiholeMessagesOut{}, "", err
	}
	out := PiholeMessagesOut{Instance: name, Messages: []MessageOut{}}
	for _, m := range ms {
		o := MessageOut{ID: m.ID, Type: m.Type, Text: firstNonEmpty(m.Plain, m.HTML)}
		if m.Timestamp > 0 {
			o.Time = d.unix(m.Timestamp)
		}
		out.Messages = append(out.Messages, o)
	}
	return out, fmt.Sprintf("%d diagnostic message(s).", len(out.Messages)), nil
}

// SuggestIn is the input of suggest_improvements.
type SuggestIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Window of traffic to analyze (default 7d)"`
}

// SuggestOut is the output of suggest_improvements.
type SuggestOut struct {
	Instance string             `json:"instance"`
	Findings []analysis.Finding `json:"findings"`
	Scan     ScanInfo           `json:"scan"`
}

func (d *Deps) suggestImprovements(ctx context.Context, in SuggestIn) (SuggestOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return SuggestOut{}, "", err
	}
	period := in.Period
	if period == "" {
		period = "7d"
	}
	r, err := d.window(period, "", "")
	if err != nil {
		return SuggestOut{}, "", err
	}
	lists, err := c.Lists(ctx)
	if err != nil {
		return SuggestOut{}, "", err
	}
	rules, err := c.Domains(ctx, "", "")
	if err != nil {
		return SuggestOut{}, "", err
	}
	agg := analysis.NewAggregator(d.Cfg.Location())
	info, err := d.scan(ctx, c, r, pihole.QueryFilter{}, agg.Add)
	if err != nil {
		return SuggestOut{}, "", err
	}
	carried := analysis.AssessLists(lists, rules, d.now(), analysis.Thresholds{StaleListDays: d.Cfg.Analysis.StaleListDays})
	if hin, _, _, err := d.collectHealth(ctx, name, c, "24h"); err == nil {
		carried = append(carried, analysis.Health(hin)...)
	}
	fs := analysis.Suggest(analysis.SuggestInput{
		Agg: agg, Lists: lists, Rules: rules, Catalog: d.Catalog, Ads: d.Ads,
		Findings: carried, HighBlockRatio: d.Cfg.Analysis.HighBlockRatio,
	})
	if fs == nil {
		fs = []analysis.Finding{}
	}
	out := SuggestOut{Instance: name, Findings: fs, Scan: info}
	return out, fmt.Sprintf("%d suggestions from %d queries over %s%s.", len(fs), info.Scanned, period, partial(info)), nil
}
