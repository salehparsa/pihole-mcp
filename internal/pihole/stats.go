package pihole

import (
	"context"
	"net/url"
	"strconv"
)

// TimeRange selects a window in Unix seconds. Zero means "live (last 24h in memory)".
type TimeRange struct{ From, Until int64 }

func (r TimeRange) database() bool { return r.From > 0 }

func (r TimeRange) values() url.Values {
	q := url.Values{}
	if r.From > 0 {
		q.Set("from", strconv.FormatInt(r.From, 10))
	}
	if r.Until > 0 {
		q.Set("until", strconv.FormatInt(r.Until, 10))
	}
	return q
}

func statsPath(r TimeRange, p string) string {
	if r.database() {
		return "/stats/database" + p
	}
	return "/stats" + p
}

// Summary returns totals for the range. With a zero range it is the live
// summary (last 24h in memory, full detail); otherwise the long-term database
// is queried, which only reports totals (see Summary.DatabaseOnly).
func (c *Client) Summary(ctx context.Context, r TimeRange) (*Summary, error) {
	if !r.database() {
		var s Summary
		if err := c.get(ctx, "/stats/summary", nil, &s); err != nil {
			return nil, err
		}
		return &s, nil
	}
	var d DatabaseSummary
	if err := c.get(ctx, "/stats/database/summary", r.values(), &d); err != nil {
		return nil, err
	}
	s := &Summary{DatabaseOnly: true}
	s.Queries.Total, s.Queries.Blocked, s.Queries.PercentBlocked = d.SumQueries, d.SumBlocked, d.PercentBlocked
	s.Clients.Total = d.TotalClients
	return s, nil
}

// TopDomains returns the most queried (or most blocked) domains.
func (c *Client) TopDomains(ctx context.Context, r TimeRange, count int, blocked bool) (*TopDomains, error) {
	q := r.values()
	q.Set("count", strconv.Itoa(count))
	q.Set("blocked", strconv.FormatBool(blocked))
	var t TopDomains
	if err := c.get(ctx, statsPath(r, "/top_domains"), q, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// TopClients returns the busiest (or most-blocked) clients.
func (c *Client) TopClients(ctx context.Context, r TimeRange, count int, blocked bool) (*TopClients, error) {
	q := r.values()
	q.Set("count", strconv.Itoa(count))
	q.Set("blocked", strconv.FormatBool(blocked))
	var t TopClients
	if err := c.get(ctx, statsPath(r, "/top_clients"), q, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Upstreams returns upstream server statistics.
func (c *Client) Upstreams(ctx context.Context, r TimeRange) (*Upstreams, error) {
	var u Upstreams
	if err := c.get(ctx, statsPath(r, "/upstreams"), r.values(), &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// History returns total/blocked counts per time slot.
func (c *Client) History(ctx context.Context, r TimeRange) ([]HistoryPoint, error) {
	p := "/history"
	if r.database() {
		p = "/history/database"
	}
	var out struct {
		History []HistoryPoint `json:"history"`
	}
	if err := c.get(ctx, p, r.values(), &out); err != nil {
		return nil, err
	}
	return out.History, nil
}

// ClientHistory returns per-client counts per time slot.
func (c *Client) ClientHistory(ctx context.Context, r TimeRange) (*ClientHistory, error) {
	p := "/history/clients"
	if r.database() {
		p = "/history/database/clients"
	}
	var out ClientHistory
	if err := c.get(ctx, p, r.values(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
