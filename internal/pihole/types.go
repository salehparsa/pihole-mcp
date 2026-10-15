package pihole

import "strings"

// BlockedStatuses are the FTL query statuses that mean the query was blocked.
// Verified against the Pi-hole v6 /queries "status" enum.
var BlockedStatuses = map[string]bool{
	"GRAVITY": true, "REGEX": true, "DENYLIST": true,
	"EXTERNAL_BLOCKED_IP": true, "EXTERNAL_BLOCKED_NULL": true, "EXTERNAL_BLOCKED_NXRA": true,
	"EXTERNAL_BLOCKED_EDE15": true,
	"GRAVITY_CNAME":          true, "REGEX_CNAME": true, "DENYLIST_CNAME": true,
	"SPECIAL_DOMAIN": true,
}

// IsBlocked reports whether a query status is a blocked one. Any
// EXTERNAL_BLOCKED_* status counts, so new upstream-blocking variants are covered.
func IsBlocked(status string) bool {
	return BlockedStatuses[status] || strings.HasPrefix(status, "EXTERNAL_BLOCKED")
}

// DatabaseSummary is /stats/database/summary: a much smaller shape than the live
// summary (no cache/forwarded/unique-domain counts, no gravity info).
type DatabaseSummary struct {
	SumQueries     int     `json:"sum_queries"`
	SumBlocked     int     `json:"sum_blocked"`
	PercentBlocked float64 `json:"percent_blocked"`
	TotalClients   int     `json:"total_clients"`
}

// Summary is /stats/summary (live, last 24h). A summary built from the long-term
// database has DatabaseOnly set and only Queries.Total/Blocked/PercentBlocked and
// Clients.Total populated.
type Summary struct {
	DatabaseOnly bool `json:"-"`

	Queries struct {
		Total          int            `json:"total"`
		Blocked        int            `json:"blocked"`
		PercentBlocked float64        `json:"percent_blocked"`
		UniqueDomains  int            `json:"unique_domains"`
		Forwarded      int            `json:"forwarded"`
		Cached         int            `json:"cached"`
		Frequency      float64        `json:"frequency"`
		Types          map[string]int `json:"types"`
		Status         map[string]int `json:"status"`
		Replies        map[string]int `json:"replies"`
	} `json:"queries"`
	Clients struct {
		Active int `json:"active"`
		Total  int `json:"total"`
	} `json:"clients"`
	Gravity struct {
		DomainsBeingBlocked int   `json:"domains_being_blocked"`
		LastUpdate          int64 `json:"last_update"`
	} `json:"gravity"`
}

// DomainCount is one row of top_domains.
type DomainCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// TopDomains is /stats/top_domains.
type TopDomains struct {
	Domains        []DomainCount `json:"domains"`
	TotalQueries   int           `json:"total_queries"`
	BlockedQueries int           `json:"blocked_queries"`
}

// ClientCount is one row of top_clients.
type ClientCount struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// TopClients is /stats/top_clients.
type TopClients struct {
	Clients        []ClientCount `json:"clients"`
	TotalQueries   int           `json:"total_queries"`
	BlockedQueries int           `json:"blocked_queries"`
}

// Upstream is one row of /stats/upstreams.
type Upstream struct {
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Port       int    `json:"port"`
	Count      int    `json:"count"`
	Statistics struct {
		Response float64 `json:"response"`
		Variance float64 `json:"variance"`
	} `json:"statistics"`
}

// Upstreams is /stats/upstreams.
type Upstreams struct {
	Upstreams        []Upstream `json:"upstreams"`
	ForwardedQueries int        `json:"forwarded_queries"`
	TotalQueries     int        `json:"total_queries"`
}

// QueryClient is the client of a logged query.
type QueryClient struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// Query is one entry of the query log.
type Query struct {
	ID       int         `json:"id"`
	Time     float64     `json:"time"`
	Type     string      `json:"type"`
	Domain   string      `json:"domain"`
	CNAME    *string     `json:"cname"`
	Status   string      `json:"status"`
	Client   QueryClient `json:"client"`
	DNSSEC   string      `json:"dnssec"`
	Upstream *string     `json:"upstream"`
	Reply    struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
	ListID *int `json:"list_id"`
}

// QueriesPage is one page of /queries.
type QueriesPage struct {
	Queries         []Query `json:"queries"`
	Cursor          int     `json:"cursor"`
	RecordsTotal    int     `json:"recordsTotal"`
	RecordsFiltered int     `json:"recordsFiltered"`
}

// List is a block/allow list (adlist).
type List struct {
	Address        string `json:"address"`
	Type           string `json:"type"`
	Comment        string `json:"comment"`
	Groups         []int  `json:"groups"`
	Enabled        bool   `json:"enabled"`
	ID             int    `json:"id"`
	DateAdded      int64  `json:"date_added"`
	DateModified   int64  `json:"date_modified"`
	DateUpdated    int64  `json:"date_updated"`
	Number         int    `json:"number"`
	InvalidDomains int    `json:"invalid_domains"`
	ABPEntries     int    `json:"abp_entries"`
	Status         int    `json:"status"`
}

// ListStatus values reported by Pi-hole for adlists.
const (
	ListStatusUnknown     = 0
	ListStatusDownloaded  = 1
	ListStatusUnchanged   = 2
	ListStatusUnavailable = 3
	ListStatusInvalid     = 4
)

// DomainRule is an allow/deny rule.
type DomainRule struct {
	Domain       string `json:"domain"`
	Unicode      string `json:"unicode"`
	Type         string `json:"type"` // allow | deny
	Kind         string `json:"kind"` // exact | regex
	Comment      string `json:"comment"`
	Groups       []int  `json:"groups"`
	Enabled      bool   `json:"enabled"`
	ID           int    `json:"id"`
	DateAdded    int64  `json:"date_added"`
	DateModified int64  `json:"date_modified"`
}

// Client is a configured Pi-hole client entry.
type ClientEntry struct {
	Client  string `json:"client"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	ID      int    `json:"id"`
}

// DeviceIP is one address of a network device.
type DeviceIP struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	LastSeen int64  `json:"lastSeen"`
}

// Device is a row of /network/devices.
type Device struct {
	ID         int        `json:"id"`
	HWAddr     string     `json:"hwaddr"`
	Interface  string     `json:"interface"`
	FirstSeen  int64      `json:"firstSeen"`
	LastQuery  int64      `json:"lastQuery"`
	NumQueries int        `json:"numQueries"`
	MACVendor  string     `json:"macVendor"`
	IPs        []DeviceIP `json:"ips"`
}

// SearchResult is /search/{domain}.
type SearchResult struct {
	Domains []DomainRule `json:"domains"`
	Gravity []struct {
		Address string `json:"address"`
		Comment string `json:"comment"`
		Enabled bool   `json:"enabled"`
		ID      int    `json:"id"`
		Type    string `json:"type"`
		Domain  string `json:"domain"`
	} `json:"gravity"`
}

// HistoryPoint is a /history bucket.
type HistoryPoint struct {
	Timestamp float64 `json:"timestamp"`
	Total     int     `json:"total"`
	Cached    int     `json:"cached"`
	Blocked   int     `json:"blocked"`
	Forwarded int     `json:"forwarded"`
}

// ClientHistory is /history/clients.
type ClientHistory struct {
	Clients map[string]struct {
		Name  string `json:"name"`
		Total int    `json:"total"`
	} `json:"clients"`
	History []struct {
		Timestamp float64        `json:"timestamp"`
		Data      map[string]int `json:"data"`
	} `json:"history"`
}

// Blocking is /dns/blocking.
type Blocking struct {
	Blocking string   `json:"blocking"`
	Timer    *float64 `json:"timer"`
}

// Version is /info/version (kept loose: its shape differs between releases).
type Version map[string]any

// Message is an FTL diagnostic message.
type Message struct {
	ID        int     `json:"id"`
	Type      string  `json:"type"`
	Plain     string  `json:"plain"`
	HTML      string  `json:"html"`
	Timestamp float64 `json:"timestamp"`
}
