package pihole

import (
	"context"
	"net/url"
	"strconv"
)

// QueryFilter selects entries from the query log.
type QueryFilter struct {
	From, Until int64
	Domain      string
	ClientIP    string
	ClientName  string
	Upstream    string
	Type        string
	Status      string
	DNSSEC      string
	Length      int
	Cursor      int // 0 = first page
	Disk        bool
}

func (f QueryFilter) values() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	if f.From > 0 {
		q.Set("from", strconv.FormatInt(f.From, 10))
	}
	if f.Until > 0 {
		q.Set("until", strconv.FormatInt(f.Until, 10))
	}
	set("domain", f.Domain)
	set("client_ip", f.ClientIP)
	set("client_name", f.ClientName)
	set("upstream", f.Upstream)
	set("type", f.Type)
	set("status", f.Status)
	set("dnssec", f.DNSSEC)
	if f.Length > 0 {
		q.Set("length", strconv.Itoa(f.Length))
	}
	if f.Cursor > 0 {
		q.Set("cursor", strconv.Itoa(f.Cursor))
	}
	if f.Disk {
		q.Set("disk", "true")
	}
	return q
}

// Queries fetches one page of the query log.
func (c *Client) Queries(ctx context.Context, f QueryFilter) (*QueriesPage, error) {
	var p QueriesPage
	if err := c.get(ctx, "/queries", f.values(), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ScanQueries pages through the query log, calling fn for each entry, until the
// log is exhausted, fn returns false, or max entries have been visited.
// It reports the number scanned and whether the scan was cut short by max.
//
// Pi-hole returns newest first, and its `cursor` request parameter is "the
// database ID of the most recent query to be shown", so the next page starts at
// (oldest ID seen) - 1. Entries are also de-duplicated by ID as a guard.
func (c *Client) ScanQueries(ctx context.Context, f QueryFilter, max int, fn func(Query) bool) (scanned int, truncated bool, err error) {
	const pageSize = 1000
	seen := map[int]struct{}{}
	for {
		if scanned >= max {
			return scanned, true, nil
		}
		f.Length = pageSize
		if rem := max - scanned; rem < pageSize {
			f.Length = rem
		}
		page, err := c.Queries(ctx, f)
		if err != nil {
			return scanned, false, err
		}
		fresh, minID := 0, 0
		for _, q := range page.Queries {
			if minID == 0 || q.ID < minID {
				minID = q.ID
			}
			if _, dup := seen[q.ID]; dup {
				continue
			}
			seen[q.ID] = struct{}{}
			fresh++
			scanned++
			if !fn(q) {
				return scanned, false, nil
			}
		}
		if fresh == 0 || len(page.Queries) < f.Length || minID <= 1 {
			return scanned, false, nil
		}
		f.Cursor = minID - 1
	}
}

// NextCursor returns the cursor for the page after the given one (0 if none).
func NextCursor(page *QueriesPage) int {
	minID := 0
	for _, q := range page.Queries {
		if minID == 0 || q.ID < minID {
			minID = q.ID
		}
	}
	if minID <= 1 {
		return 0
	}
	return minID - 1
}
