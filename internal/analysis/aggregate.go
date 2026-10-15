package analysis

import (
	"sort"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// Count is a name with a count.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// DeviceCount is a device with a count.
type DeviceCount struct {
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"`
	Count int    `json:"count"`
}

// Aggregator accumulates query-log entries in a single pass.
type Aggregator struct {
	loc     *time.Location
	Total   int
	Blocked int
	clients map[string]*clientAgg
	domains map[string]*domainAgg
}

type clientAgg struct {
	ip, name       string
	total, blocked int
	blockedDomains map[string]int
	allowedDomains map[string]int
	types          map[string]int
	hours          [24]int
	first, last    float64
}

type domainAgg struct {
	total, blocked int
	blockedBy      map[string]int // client ip -> blocked count
}

// NewAggregator creates an aggregator; hours are bucketed in loc.
func NewAggregator(loc *time.Location) *Aggregator {
	if loc == nil {
		loc = time.UTC
	}
	return &Aggregator{loc: loc, clients: map[string]*clientAgg{}, domains: map[string]*domainAgg{}}
}

// Add records one query.
func (a *Aggregator) Add(q pihole.Query) {
	blocked := pihole.IsBlocked(q.Status)
	a.Total++
	if blocked {
		a.Blocked++
	}
	c := a.clients[q.Client.IP]
	if c == nil {
		c = &clientAgg{ip: q.Client.IP, blockedDomains: map[string]int{}, allowedDomains: map[string]int{}, types: map[string]int{}}
		a.clients[q.Client.IP] = c
	}
	if q.Client.Name != "" {
		c.name = q.Client.Name
	}
	c.total++
	c.types[q.Type]++
	c.hours[time.Unix(int64(q.Time), 0).In(a.loc).Hour()]++
	if c.first == 0 || q.Time < c.first {
		c.first = q.Time
	}
	if q.Time > c.last {
		c.last = q.Time
	}
	d := a.domains[q.Domain]
	if d == nil {
		d = &domainAgg{blockedBy: map[string]int{}}
		a.domains[q.Domain] = d
	}
	d.total++
	if blocked {
		c.blocked++
		c.blockedDomains[q.Domain]++
		d.blocked++
		d.blockedBy[q.Client.IP]++
	} else {
		c.allowedDomains[q.Domain]++
	}
}

func topN(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// TopDomains returns the most-queried allowed or blocked domains.
func (a *Aggregator) TopDomains(blocked bool, n int) []Count {
	m := map[string]int{}
	for dom, d := range a.domains {
		if blocked && d.blocked > 0 {
			m[dom] = d.blocked
		} else if !blocked && d.total-d.blocked > 0 {
			m[dom] = d.total - d.blocked
		}
	}
	return topN(m, n)
}

// ClientSummary is a one-line view of a device.
type ClientSummary struct {
	IP         string  `json:"ip"`
	Name       string  `json:"name,omitempty"`
	Total      int     `json:"total"`
	Blocked    int     `json:"blocked"`
	BlockRatio float64 `json:"block_ratio"`
}

// Clients returns devices ordered by blocked (byBlocked) or total queries.
func (a *Aggregator) Clients(byBlocked bool, n int) []ClientSummary {
	out := make([]ClientSummary, 0, len(a.clients))
	for _, c := range a.clients {
		out = append(out, ClientSummary{IP: c.ip, Name: c.name, Total: c.total, Blocked: c.blocked, BlockRatio: ratio(c.blocked, c.total)})
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i].Total, out[j].Total
		if byBlocked {
			x, y = out[i].Blocked, out[j].Blocked
		}
		if x != y {
			return x > y
		}
		return out[i].IP < out[j].IP
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// BlockedRow is one blocked domain with the devices that hit it.
type BlockedRow struct {
	Domain  string        `json:"domain"`
	Blocked int           `json:"blocked"`
	Devices []DeviceCount `json:"devices"`
}

// BlockedMatrix returns the top blocked domains, each with its top devices.
func (a *Aggregator) BlockedMatrix(nDomains, nDevices int) []BlockedRow {
	var rows []BlockedRow
	for _, dc := range a.TopDomains(true, nDomains) {
		d := a.domains[dc.Name]
		by := map[string]int{}
		for ip, n := range d.blockedBy {
			by[ip] = n
		}
		row := BlockedRow{Domain: dc.Name, Blocked: dc.Count}
		for _, c := range topN(by, nDevices) {
			row.Devices = append(row.Devices, DeviceCount{IP: c.Name, Name: a.clients[c.Name].name, Count: c.Count})
		}
		rows = append(rows, row)
	}
	return rows
}

// ClientDetail is the activity profile of one device.
type ClientDetail struct {
	ClientSummary
	TopBlocked  []Count        `json:"top_blocked"`
	TopAllowed  []Count        `json:"top_allowed"`
	QueryTypes  map[string]int `json:"query_types"`
	ActiveHours [24]int        `json:"queries_by_hour"`
	PeakHour    int            `json:"peak_hour"`
	FirstQuery  int64          `json:"first_query_unix,omitempty"`
	LastQuery   int64          `json:"last_query_unix,omitempty"`
}

// Client returns the profile of ip, or false if it has no queries.
func (a *Aggregator) Client(ip string, n int) (ClientDetail, bool) {
	c := a.clients[ip]
	if c == nil {
		return ClientDetail{}, false
	}
	d := ClientDetail{
		ClientSummary: ClientSummary{IP: c.ip, Name: c.name, Total: c.total, Blocked: c.blocked, BlockRatio: ratio(c.blocked, c.total)},
		TopBlocked:    topN(c.blockedDomains, n), TopAllowed: topN(c.allowedDomains, n),
		QueryTypes: c.types, ActiveHours: c.hours, FirstQuery: int64(c.first), LastQuery: int64(c.last),
	}
	for h, v := range c.hours {
		if v > c.hours[d.PeakHour] {
			d.PeakHour = h
		}
	}
	return d, true
}

// AllowedCounts returns allowed-query counts per domain (for suggestions).
func (a *Aggregator) AllowedCounts() map[string]int {
	m := map[string]int{}
	for dom, d := range a.domains {
		if n := d.total - d.blocked; n > 0 {
			m[dom] = n
		}
	}
	return m
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
