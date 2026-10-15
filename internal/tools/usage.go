package tools

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

func registerUsage(srv *mcp.Server, d *Deps) {
	addRead(srv, "get_summary", "Query summary",
		"Totals for a time window: queries, blocked, percent blocked, cache/forwarded counts, unique domains, active clients and the size of the gravity (block) database.",
		d.getSummary)
	addRead(srv, "top_domains", "Top domains",
		"Most queried or most blocked domains in a window. With 'client' set, ranks that device's domains (computed from the query log).",
		d.topDomains)
	addRead(srv, "top_clients", "Top devices",
		"Busiest devices, or the devices with the most blocked queries.",
		d.topClients)
	addRead(srv, "blocked_by_device", "Blocked domains by device",
		"Which domains were blocked and which devices requested them (domain × device matrix). Answers 'which sites get blocked most, and by which devices?'. Optional domain/client filters.",
		d.blockedByDevice)
	addRead(srv, "client_activity", "Device activity profile",
		"Profile of one device: totals, block ratio, top allowed and blocked domains, query types and active hours.",
		d.clientActivity)
	addRead(srv, "query_timeline", "Query timeline",
		"Query counts over time (total/blocked/cached/forwarded), optionally for one device.",
		d.queryTimeline)
	addRead(srv, "search_queries", "Search query log",
		"Raw query-log entries with filters; paginate with the returned next_cursor. Limit ≤ 500.",
		d.searchQueries)
	addRead(srv, "explain_domain", "Explain a domain",
		"Why a domain is or is not blocked: matching block lists and allow/deny rules, plus recent queries and the devices that made them.",
		d.explainDomain)
	addRead(srv, "list_devices", "List devices",
		"Network devices Pi-hole has seen: addresses, MAC, vendor, host names, first/last seen and query counts.",
		d.listDevices)
	addRead(srv, "list_instances", "List Pi-hole instances",
		"Configured Pi-hole instances with their version and blocking state. Never returns secrets.",
		d.listInstances)
}

// ---- get_summary

// SummaryIn is the input of get_summary.
type SummaryIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window ending now, e.g. 1h, 24h, 7d, 30d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339 (default now)"`
}

// SummaryOut is the output of get_summary.
type SummaryOut struct {
	Instance          string         `json:"instance"`
	From              string         `json:"from"`
	Until             string         `json:"until"`
	Source            string         `json:"source" jsonschema:"where the numbers came from: database or live"`
	TotalQueries      int            `json:"total_queries"`
	BlockedQueries    int            `json:"blocked_queries"`
	PercentBlocked    float64        `json:"percent_blocked"`
	CachedQueries     *int           `json:"cached_queries,omitempty" jsonschema:"only for the live 24h window"`
	ForwardedQueries  *int           `json:"forwarded_queries,omitempty" jsonschema:"only for the live 24h window"`
	UniqueDomains     *int           `json:"unique_domains,omitempty" jsonschema:"only for the live 24h window"`
	ActiveClients     *int           `json:"active_clients,omitempty" jsonschema:"only for the live 24h window"`
	TotalClients      int            `json:"total_clients"`
	GravityDomains    int            `json:"gravity_domains" jsonschema:"domains currently on block lists"`
	GravityLastUpdate string         `json:"gravity_last_update,omitempty"`
	QueryTypes        map[string]int `json:"query_types,omitempty"`
	Replies           map[string]int `json:"replies,omitempty"`
	Note              string         `json:"note,omitempty"`
}

// liveWindow reports whether a window is the live 24h (so the in-memory summary,
// which has full detail, describes it exactly).
func (d *Deps) liveWindow(r analysis.Range) bool {
	return d.liveOK(r) && r.Duration() >= 23*time.Hour
}

func (d *Deps) getSummary(ctx context.Context, in SummaryIn) (SummaryOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return SummaryOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return SummaryOut{}, "", err
	}
	out := SummaryOut{Instance: name, From: d.ts(r.From), Until: d.ts(r.Until)}
	var s *pihole.Summary
	if d.liveWindow(r) {
		if s, err = c.Summary(ctx, pihole.TimeRange{}); err == nil {
			out.Source = "live (last 24h)"
		}
	}
	if s == nil {
		var dbErr error
		if s, dbErr = c.Summary(ctx, d.statsRange(r)); dbErr == nil {
			out.Source = "database"
		} else if err == nil {
			err = dbErr
		}
	}
	if s == nil {
		if err == nil && d.liveOK(r) {
			s, err = c.Summary(ctx, pihole.TimeRange{})
			out.Source = "live (last 24h in memory; the long-term database was unavailable)"
		}
		if s == nil {
			return SummaryOut{}, "", err
		}
	}
	out.TotalQueries, out.BlockedQueries, out.PercentBlocked = s.Queries.Total, s.Queries.Blocked, pct(s.Queries.Blocked, s.Queries.Total)
	out.TotalClients = s.Clients.Total
	if s.DatabaseOnly {
		out.Note = "Long-term database statistics only report totals; cache, forwarded, unique-domain and per-type breakdowns are available for the live 24h window (period=24h)."
		// gravity size is current state, not windowed: take it from the live summary
		if live, err := c.Summary(ctx, pihole.TimeRange{}); err == nil {
			s = &pihole.Summary{Gravity: live.Gravity}
		} else {
			s = &pihole.Summary{}
		}
	} else {
		out.CachedQueries, out.ForwardedQueries = &s.Queries.Cached, &s.Queries.Forwarded
		out.UniqueDomains, out.ActiveClients = &s.Queries.UniqueDomains, &s.Clients.Active
		out.QueryTypes, out.Replies = s.Queries.Types, s.Queries.Replies
	}
	out.GravityDomains = s.Gravity.DomainsBeingBlocked
	if s.Gravity.LastUpdate > 0 {
		out.GravityLastUpdate = d.unix(float64(s.Gravity.LastUpdate))
	}
	return out, fmt.Sprintf("%s, %s → %s (%s): %d queries, %d blocked (%.1f%%), %d domains on block lists.",
		name, out.From, out.Until, out.Source, out.TotalQueries, out.BlockedQueries, out.PercentBlocked, out.GravityDomains), nil
}

// ---- top_domains

// TopDomainsIn is the input of top_domains.
type TopDomainsIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 24h, 7d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Count    int    `json:"count,omitempty" jsonschema:"How many domains (1-100, default 10)"`
	Blocked  bool   `json:"blocked,omitempty" jsonschema:"true = most blocked domains; false = most queried allowed domains"`
	Client   string `json:"client,omitempty" jsonschema:"Only this device (IP or name); computed from the query log"`
}

// TopDomainsOut is the output of top_domains.
type TopDomainsOut struct {
	Instance string           `json:"instance"`
	Blocked  bool             `json:"blocked"`
	Client   string           `json:"client,omitempty"`
	From     string           `json:"from"`
	Until    string           `json:"until"`
	Source   string           `json:"source"`
	Domains  []analysis.Count `json:"domains"`
	Scan     *ScanInfo        `json:"scan,omitempty"`
}

func (d *Deps) topDomains(ctx context.Context, in TopDomainsIn) (TopDomainsOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return TopDomainsOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return TopDomainsOut{}, "", err
	}
	n := clamp(in.Count, 10, 1, 100)
	out := TopDomainsOut{Instance: name, Blocked: in.Blocked, Client: in.Client, From: d.ts(r.From), Until: d.ts(r.Until)}
	if in.Client != "" {
		agg := analysis.NewAggregator(d.Cfg.Location())
		var f pihole.QueryFilter
		clientFilter(in.Client, &f)
		info, err := d.scan(ctx, c, r, f, agg.Add)
		if err != nil {
			return out, "", err
		}
		out.Source, out.Scan, out.Domains = "query log", &info, agg.TopDomains(in.Blocked, n)
	} else {
		t, src, err := stats(d, r, func(tr pihole.TimeRange) (*pihole.TopDomains, error) { return c.TopDomains(ctx, tr, n, in.Blocked) })
		if err != nil {
			return out, "", err
		}
		out.Source = src
		for _, dc := range t.Domains {
			out.Domains = append(out.Domains, analysis.Count{Name: dc.Domain, Count: dc.Count})
		}
	}
	kind := "queried"
	if in.Blocked {
		kind = "blocked"
	}
	top := "none"
	if len(out.Domains) > 0 {
		top = fmt.Sprintf("%s (%d)", out.Domains[0].Name, out.Domains[0].Count)
	}
	return out, fmt.Sprintf("Top %d %s domains; #1 is %s.", len(out.Domains), kind, top), nil
}

// ---- top_clients

// TopClientsIn is the input of top_clients.
type TopClientsIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 24h, 7d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Count    int    `json:"count,omitempty" jsonschema:"How many devices (1-100, default 10)"`
	Blocked  bool   `json:"blocked,omitempty" jsonschema:"true = rank by blocked queries instead of total queries"`
}

// TopClientsOut is the output of top_clients.
type TopClientsOut struct {
	Instance string                 `json:"instance"`
	From     string                 `json:"from"`
	Until    string                 `json:"until"`
	Source   string                 `json:"source"`
	Clients  []analysis.DeviceCount `json:"clients"`
}

func (d *Deps) topClients(ctx context.Context, in TopClientsIn) (TopClientsOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return TopClientsOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return TopClientsOut{}, "", err
	}
	n := clamp(in.Count, 10, 1, 100)
	t, src, err := stats(d, r, func(tr pihole.TimeRange) (*pihole.TopClients, error) { return c.TopClients(ctx, tr, n, in.Blocked) })
	if err != nil {
		return TopClientsOut{}, "", err
	}
	out := TopClientsOut{Instance: name, From: d.ts(r.From), Until: d.ts(r.Until), Source: src}
	for _, cl := range t.Clients {
		out.Clients = append(out.Clients, analysis.DeviceCount{IP: cl.IP, Name: cl.Name, Count: cl.Count})
	}
	top := "none"
	if len(out.Clients) > 0 {
		top = fmt.Sprintf("%s (%d)", firstNonEmpty(out.Clients[0].Name, out.Clients[0].IP), out.Clients[0].Count)
	}
	return out, fmt.Sprintf("Top %d devices; #1 is %s.", len(out.Clients), top), nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---- blocked_by_device

// BlockedByDeviceIn is the input of blocked_by_device.
type BlockedByDeviceIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 24h, 7d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Domain   string `json:"domain,omitempty" jsonschema:"Only this domain (Pi-hole filter; * wildcards supported)"`
	Client   string `json:"client,omitempty" jsonschema:"Only this device (IP or name)"`
	Domains  int    `json:"domains,omitempty" jsonschema:"How many blocked domains to return (1-100, default 20)"`
	Devices  int    `json:"devices_per_domain,omitempty" jsonschema:"Devices listed per domain (1-20, default 5)"`
}

// BlockedByDeviceOut is the output of blocked_by_device.
type BlockedByDeviceOut struct {
	Instance       string                `json:"instance"`
	From           string                `json:"from"`
	Until          string                `json:"until"`
	TotalQueries   int                   `json:"total_queries"`
	BlockedQueries int                   `json:"blocked_queries"`
	Rows           []analysis.BlockedRow `json:"rows"`
	Scan           ScanInfo              `json:"scan"`
}

func (d *Deps) blockedByDevice(ctx context.Context, in BlockedByDeviceIn) (BlockedByDeviceOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return BlockedByDeviceOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return BlockedByDeviceOut{}, "", err
	}
	agg := analysis.NewAggregator(d.Cfg.Location())
	f := pihole.QueryFilter{Domain: in.Domain}
	clientFilter(in.Client, &f)
	info, err := d.scan(ctx, c, r, f, agg.Add)
	if err != nil {
		return BlockedByDeviceOut{}, "", err
	}
	out := BlockedByDeviceOut{Instance: name, From: d.ts(r.From), Until: d.ts(r.Until), TotalQueries: agg.Total, BlockedQueries: agg.Blocked,
		Rows: agg.BlockedMatrix(clamp(in.Domains, 20, 1, 100), clamp(in.Devices, 5, 1, 20)), Scan: info}
	sum := fmt.Sprintf("%d of %d queries blocked across %d domains (scanned %d%s).", agg.Blocked, agg.Total, len(out.Rows), info.Scanned, partial(info))
	if len(out.Rows) > 0 {
		r0 := out.Rows[0]
		sum += fmt.Sprintf(" Most blocked: %s (%d)", r0.Domain, r0.Blocked)
		if len(r0.Devices) > 0 {
			sum += ", mostly by " + firstNonEmpty(r0.Devices[0].Name, r0.Devices[0].IP)
		}
		sum += "."
	}
	return out, sum, nil
}

func partial(i ScanInfo) string {
	if i.Truncated {
		return ", TRUNCATED — numbers are partial"
	}
	return ""
}

// ---- client_activity

// ClientActivityIn is the input of client_activity.
type ClientActivityIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Client   string `json:"client" jsonschema:"Device IP address or host name"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 24h, 7d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Top      int    `json:"top,omitempty" jsonschema:"How many top domains per list (1-50, default 10)"`
}

// ClientActivityOut is the output of client_activity.
type ClientActivityOut struct {
	Instance string                 `json:"instance"`
	From     string                 `json:"from"`
	Until    string                 `json:"until"`
	Found    bool                   `json:"found" jsonschema:"false when the device made no queries in the window"`
	Activity *analysis.ClientDetail `json:"activity,omitempty"`
	Scan     ScanInfo               `json:"scan"`
}

func (d *Deps) clientActivity(ctx context.Context, in ClientActivityIn) (ClientActivityOut, string, error) {
	if strings.TrimSpace(in.Client) == "" {
		return ClientActivityOut{}, "", errf("client is required (an IP address or host name)")
	}
	name, c, err := d.client(in.Instance)
	if err != nil {
		return ClientActivityOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return ClientActivityOut{}, "", err
	}
	agg := analysis.NewAggregator(d.Cfg.Location())
	var f pihole.QueryFilter
	clientFilter(in.Client, &f)
	info, err := d.scan(ctx, c, r, f, agg.Add)
	if err != nil {
		return ClientActivityOut{}, "", err
	}
	out := ClientActivityOut{Instance: name, From: d.ts(r.From), Until: d.ts(r.Until), Scan: info}
	// a name filter can match several addresses; report the busiest
	cs := agg.Clients(false, 1)
	if len(cs) == 0 {
		return out, fmt.Sprintf("No queries from %q in the window.", in.Client), nil
	}
	det, _ := agg.Client(cs[0].IP, clamp(in.Top, 10, 1, 50))
	out.Found, out.Activity = true, &det
	return out, fmt.Sprintf("%s: %d queries, %d blocked (%.0f%%), busiest around %02d:00 (scanned %d%s).",
		firstNonEmpty(det.Name, det.IP), det.Total, det.Blocked, det.BlockRatio*100, det.PeakHour, info.Scanned, partial(info)), nil
}

// ---- query_timeline

// TimelineIn is the input of query_timeline.
type TimelineIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 24h, 7d (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Bucket   string `json:"bucket,omitempty" jsonschema:"Bucket size, e.g. 10m, 1h, 1d (default depends on the window)"`
	Client   string `json:"client,omitempty" jsonschema:"Only this device (IP or name); computed from the query log"`
}

// TimelineBucket is one slice of query_timeline.
type TimelineBucket struct {
	Start     string `json:"start"`
	Total     int    `json:"total"`
	Blocked   int    `json:"blocked"`
	Cached    int    `json:"cached,omitempty"`
	Forwarded int    `json:"forwarded,omitempty"`
}

// TimelineOut is the output of query_timeline.
type TimelineOut struct {
	Instance string           `json:"instance"`
	From     string           `json:"from"`
	Until    string           `json:"until"`
	Bucket   string           `json:"bucket"`
	Source   string           `json:"source"`
	Buckets  []TimelineBucket `json:"buckets"`
	Scan     *ScanInfo        `json:"scan,omitempty"`
}

func (d *Deps) queryTimeline(ctx context.Context, in TimelineIn) (TimelineOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return TimelineOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return TimelineOut{}, "", err
	}
	size := analysis.DefaultBucket(r.Duration())
	if in.Bucket != "" {
		if size, err = analysis.ParsePeriod(in.Bucket); err != nil {
			return TimelineOut{}, "", fmt.Errorf("bucket: %w", err)
		}
	}
	tl := analysis.NewTimeline(size, d.Cfg.Location())
	out := TimelineOut{Instance: name, From: d.ts(r.From), Until: d.ts(r.Until), Bucket: size.String()}
	if in.Client != "" {
		var f pihole.QueryFilter
		clientFilter(in.Client, &f)
		info, err := d.scan(ctx, c, r, f, tl.AddQuery)
		if err != nil {
			return out, "", err
		}
		out.Source, out.Scan = "query log", &info
	} else {
		pts, src, err := statsSlice(d, r, func(tr pihole.TimeRange) ([]pihole.HistoryPoint, error) { return c.History(ctx, tr) })
		if err != nil {
			return out, "", err
		}
		out.Source = src
		for _, p := range pts {
			if int64(p.Timestamp) >= r.From.Unix() && int64(p.Timestamp) <= r.Until.Unix() {
				tl.AddPoint(p)
			}
		}
	}
	peak := TimelineBucket{}
	for _, b := range tl.Buckets() {
		tb := TimelineBucket{Start: d.ts(b.Start), Total: b.Total, Blocked: b.Blocked, Cached: b.Cached, Forwarded: b.Forwarded}
		out.Buckets = append(out.Buckets, tb)
		if tb.Total > peak.Total {
			peak = tb
		}
	}
	return out, fmt.Sprintf("%d buckets of %s; peak %d queries at %s.", len(out.Buckets), size, peak.Total, peak.Start), nil
}

func statsSlice[T any](d *Deps, r analysis.Range, f func(pihole.TimeRange) ([]T, error)) ([]T, string, error) {
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

// ---- search_queries

// SearchQueriesIn is the input of search_queries.
type SearchQueriesIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Look-back window, e.g. 1h, 24h (default 24h)"`
	From     string `json:"from,omitempty" jsonschema:"Window start, RFC3339"`
	Until    string `json:"until,omitempty" jsonschema:"Window end, RFC3339"`
	Domain   string `json:"domain,omitempty" jsonschema:"Domain filter (* wildcards supported by Pi-hole)"`
	Client   string `json:"client,omitempty" jsonschema:"Device IP or name"`
	Upstream string `json:"upstream,omitempty" jsonschema:"Upstream server filter"`
	Type     string `json:"type,omitempty" jsonschema:"Query type, e.g. A, AAAA, HTTPS"`
	Status   string `json:"status,omitempty" jsonschema:"Query status, e.g. GRAVITY, FORWARDED, CACHE, DENYLIST, REGEX"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Entries to return (1-500, default 100)"`
	Cursor   int    `json:"cursor,omitempty" jsonschema:"Cursor from a previous call's next_cursor to get the next page"`
}

// QueryOut is one query-log entry.
type QueryOut struct {
	ID         int    `json:"id"`
	Time       string `json:"time"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Blocked    bool   `json:"blocked"`
	ClientIP   string `json:"client_ip"`
	ClientName string `json:"client_name,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
	Reply      string `json:"reply,omitempty"`
	ListID     *int   `json:"list_id,omitempty"`
}

// SearchQueriesOut is the output of search_queries.
type SearchQueriesOut struct {
	Instance   string     `json:"instance"`
	Queries    []QueryOut `json:"queries"`
	Matched    int        `json:"matched" jsonschema:"total entries matching the filters (all pages)"`
	NextCursor int        `json:"next_cursor,omitempty" jsonschema:"pass as cursor to get the next page; absent when done"`
}

func (d *Deps) searchQueries(ctx context.Context, in SearchQueriesIn) (SearchQueriesOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return SearchQueriesOut{}, "", err
	}
	r, err := d.window(in.Period, in.From, in.Until)
	if err != nil {
		return SearchQueriesOut{}, "", err
	}
	limit := clamp(in.Limit, 100, 1, 500)
	f := pihole.QueryFilter{From: r.From.Unix(), Until: r.Until.Unix(), Domain: in.Domain, Upstream: in.Upstream, Type: in.Type,
		Status: in.Status, Length: limit, Cursor: in.Cursor, Disk: d.now().Sub(r.From) > 24*time.Hour}
	clientFilter(in.Client, &f)
	page, err := c.Queries(ctx, f)
	if err != nil {
		return SearchQueriesOut{}, "", err
	}
	out := SearchQueriesOut{Instance: name, Matched: page.RecordsFiltered, Queries: []QueryOut{}}
	for _, q := range page.Queries {
		out.Queries = append(out.Queries, d.queryOut(q))
	}
	if len(page.Queries) >= limit {
		out.NextCursor = pihole.NextCursor(page) // oldest id returned - 1; absent on the last page
	}
	return out, fmt.Sprintf("%d of %d matching queries returned.", len(out.Queries), out.Matched), nil
}

func (d *Deps) queryOut(q pihole.Query) QueryOut {
	o := QueryOut{ID: q.ID, Time: d.unix(q.Time), Domain: q.Domain, Type: q.Type, Status: q.Status, Blocked: pihole.IsBlocked(q.Status),
		ClientIP: q.Client.IP, ClientName: q.Client.Name, Reply: q.Reply.Type, ListID: q.ListID}
	if q.Upstream != nil {
		o.Upstream = *q.Upstream
	}
	return o
}

// ---- explain_domain

// ExplainDomainIn is the input of explain_domain.
type ExplainDomainIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Domain   string `json:"domain" jsonschema:"Domain name to explain, e.g. ads.example.com"`
	Period   string `json:"period,omitempty" jsonschema:"Window for recent queries (default 24h)"`
}

// MatchRule is a rule or list that matches the domain.
type MatchRule struct {
	Source  string `json:"source" jsonschema:"list or rule"`
	Type    string `json:"type" jsonschema:"allow or block/deny"`
	Detail  string `json:"detail"`
	Enabled bool   `json:"enabled"`
}

// ExplainDomainOut is the output of explain_domain.
type ExplainDomainOut struct {
	Instance string         `json:"instance"`
	Domain   string         `json:"domain"`
	Verdict  string         `json:"verdict" jsonschema:"blocked, allowed or not_matched"`
	Reason   string         `json:"reason"`
	Matches  []MatchRule    `json:"matches"`
	Recent   *RecentQueries `json:"recent,omitempty"`
}

// RecentQueries summarizes recent traffic for a domain.
type RecentQueries struct {
	Total    int                    `json:"total"`
	Statuses map[string]int         `json:"statuses"`
	Devices  []analysis.DeviceCount `json:"devices"`
	LastSeen string                 `json:"last_seen,omitempty"`
}

func (d *Deps) explainDomain(ctx context.Context, in ExplainDomainIn) (ExplainDomainOut, string, error) {
	dom := strings.ToLower(strings.TrimSpace(in.Domain))
	if dom == "" {
		return ExplainDomainOut{}, "", errf("domain is required")
	}
	name, c, err := d.client(in.Instance)
	if err != nil {
		return ExplainDomainOut{}, "", err
	}
	sr, err := c.Search(ctx, dom, 50)
	if err != nil {
		return ExplainDomainOut{}, "", err
	}
	out := ExplainDomainOut{Instance: name, Domain: dom, Matches: []MatchRule{}}
	var allowRule, denyRule, blockList, allowList bool
	for _, r := range sr.Domains {
		out.Matches = append(out.Matches, MatchRule{Source: "rule", Type: r.Type, Detail: fmt.Sprintf("%s %s rule: %s", r.Type, r.Kind, r.Domain), Enabled: r.Enabled})
		if r.Enabled {
			if r.Type == "allow" {
				allowRule = true
			} else {
				denyRule = true
			}
		}
	}
	for _, g := range sr.Gravity {
		out.Matches = append(out.Matches, MatchRule{Source: "list", Type: g.Type, Detail: g.Address, Enabled: g.Enabled})
		if g.Enabled {
			if g.Type == "allow" {
				allowList = true
			} else {
				blockList = true
			}
		}
	}
	switch {
	case allowRule:
		out.Verdict, out.Reason = "allowed", "An enabled allow rule matches; allow rules override deny rules and block lists."
	case allowList && !denyRule:
		out.Verdict, out.Reason = "allowed", "An enabled allow list matches this domain."
	case denyRule:
		out.Verdict, out.Reason = "blocked", "An enabled deny rule matches."
	case blockList:
		out.Verdict, out.Reason = "blocked", "One or more enabled block lists contain this domain."
	default:
		out.Verdict, out.Reason = "not_matched", "No enabled list or rule matches, so queries are forwarded upstream (they may still be blocked by CNAME inspection or special-domain handling)."
	}
	r, err := d.window(in.Period, "", "")
	if err != nil {
		return out, "", err
	}
	agg := analysis.NewAggregator(d.Cfg.Location())
	statuses := map[string]int{}
	var last float64
	_, err = d.scan(ctx, c, r, pihole.QueryFilter{Domain: dom}, func(q pihole.Query) {
		if q.Domain != dom {
			return
		}
		agg.Add(q)
		statuses[q.Status]++
		if q.Time > last {
			last = q.Time
		}
	})
	if err != nil {
		return out, "", err
	}
	if agg.Total > 0 {
		rq := &RecentQueries{Total: agg.Total, Statuses: statuses}
		for _, cl := range agg.Clients(false, 10) {
			rq.Devices = append(rq.Devices, analysis.DeviceCount{IP: cl.IP, Name: cl.Name, Count: cl.Total})
		}
		rq.LastSeen = d.unix(last)
		out.Recent = rq
	}
	recent := "no recent queries"
	if out.Recent != nil {
		recent = fmt.Sprintf("%d recent queries", out.Recent.Total)
	}
	return out, fmt.Sprintf("%s is %s: %s (%d matching list/rule entries; %s).", dom, out.Verdict, out.Reason, len(out.Matches), recent), nil
}

// ---- list_devices

// ListDevicesIn is the input of list_devices.
type ListDevicesIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
}

// DeviceOut is one network device.
type DeviceOut struct {
	MAC        string   `json:"mac,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	IPs        []string `json:"ips"`
	Names      []string `json:"names,omitempty"`
	FirstSeen  string   `json:"first_seen,omitempty"`
	LastSeen   string   `json:"last_seen,omitempty"`
	LastQuery  string   `json:"last_query,omitempty"`
	NumQueries int      `json:"num_queries"`
}

// ListDevicesOut is the output of list_devices.
type ListDevicesOut struct {
	Instance string      `json:"instance"`
	Devices  []DeviceOut `json:"devices"`
}

func (d *Deps) listDevices(ctx context.Context, in ListDevicesIn) (ListDevicesOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return ListDevicesOut{}, "", err
	}
	devs, err := c.Devices(ctx)
	if err != nil {
		return ListDevicesOut{}, "", err
	}
	known := map[string]string{} // ip -> configured name
	if cl, err := c.ConfiguredClients(ctx); err == nil {
		for _, e := range cl {
			if e.Name != "" {
				known[e.Client] = e.Name
			}
		}
	}
	out := ListDevicesOut{Instance: name, Devices: []DeviceOut{}}
	for _, dv := range devs {
		o := DeviceOut{MAC: dv.HWAddr, Vendor: dv.MACVendor, NumQueries: dv.NumQueries, IPs: []string{}}
		var seen int64
		names := map[string]bool{}
		for _, ip := range dv.IPs {
			o.IPs = append(o.IPs, ip.IP)
			if ip.Name != "" {
				names[ip.Name] = true
			}
			if n := known[ip.IP]; n != "" {
				names[n] = true
			}
			if ip.LastSeen > seen {
				seen = ip.LastSeen
			}
		}
		for n := range names {
			o.Names = append(o.Names, n)
		}
		sort.Strings(o.Names)
		if dv.FirstSeen > 0 {
			o.FirstSeen = d.unix(float64(dv.FirstSeen))
		}
		if seen > 0 {
			o.LastSeen = d.unix(float64(seen))
		}
		if dv.LastQuery > 0 {
			o.LastQuery = d.unix(float64(dv.LastQuery))
		}
		out.Devices = append(out.Devices, o)
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].NumQueries > out.Devices[j].NumQueries })
	return out, fmt.Sprintf("%d devices known to %s.", len(out.Devices), name), nil
}

// ---- list_instances

// ListInstancesIn is the input of list_instances.
type ListInstancesIn struct{}

// InstanceInfo describes one configured instance.
type InstanceInfo struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Default    bool   `json:"default"`
	FTLVersion string `json:"ftl_version,omitempty"`
	Blocking   string `json:"blocking,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ListInstancesOut is the output of list_instances.
type ListInstancesOut struct {
	Instances     []InstanceInfo `json:"instances"`
	WritesEnabled bool           `json:"writes_enabled"`
}

func (d *Deps) listInstances(ctx context.Context, _ ListInstancesIn) (ListInstancesOut, string, error) {
	out := ListInstancesOut{Instances: []InstanceInfo{}, WritesEnabled: d.Cfg.Writes.Enabled}
	for i, n := range d.Reg.Names() {
		_, c, _ := d.client(n)
		info := InstanceInfo{Name: n, URL: c.BaseURL(), Default: i == 0}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if v, err := c.FTLVersion(cctx); err != nil {
			info.Error = err.Error()
		} else {
			info.FTLVersion = v
		}
		if b, err := c.GetBlocking(cctx); err == nil {
			info.Blocking = b.Blocking
		} else if info.Error == "" {
			info.Error = err.Error()
		}
		cancel()
		out.Instances = append(out.Instances, info)
	}
	return out, fmt.Sprintf("%d Pi-hole instance(s) configured; writes %s.", len(out.Instances), map[bool]string{true: "enabled", false: "disabled"}[out.WritesEnabled]), nil
}

var _ = net.ParseIP
