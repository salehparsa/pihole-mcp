package analysis

import (
	"fmt"
	"sort"

	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// SuggestInput is the evidence suggestions are built from.
type SuggestInput struct {
	Agg            *Aggregator
	Lists          []pihole.List
	Rules          []pihole.DomainRule
	Catalog        []catalog.Entry
	Ads            *AdMatcher
	Findings       []Finding // list + health findings to carry over
	HighBlockRatio float64
	MinAllowedHits int // frequently-allowed threshold (default 5)
	MinClientQ     int // min queries before judging a device (default 20)
}

// Suggest returns ranked improvement findings; the agent turns them into advice.
func Suggest(in SuggestInput) []Finding {
	if in.MinAllowedHits == 0 {
		in.MinAllowedHits = 5
	}
	if in.MinClientQ == 0 {
		in.MinClientQ = 20
	}
	var fs []Finding

	explicit := map[string]bool{}
	for _, r := range in.Rules {
		if r.Type == "allow" && r.Kind == "exact" && r.Enabled {
			explicit[r.Domain] = true
		}
	}
	if in.Agg != nil && in.Ads != nil {
		allowed := in.Agg.AllowedCounts()
		type hit struct {
			dom     string
			n       int
			pattern string
		}
		var hits []hit
		for dom, n := range allowed {
			if n < in.MinAllowedHits {
				continue
			}
			if p, ok := in.Ads.Match(dom); ok {
				hits = append(hits, hit{dom, n, p})
			}
		}
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].n != hits[j].n {
				return hits[i].n > hits[j].n
			}
			return hits[i].dom < hits[j].dom
		})
		for _, h := range hits {
			ev := []string{fmt.Sprintf("%d allowed queries", h.n), "matched pattern " + h.pattern}
			detail := fmt.Sprintf("%s looks like an ad/tracking endpoint but was answered %d times.", h.dom, h.n)
			sug := "Review it; if it is not needed, add a deny rule (add_domain_rule) or a list that covers it."
			if explicit[h.dom] {
				detail += " It is allowed by an explicit allow rule."
				sug = "An allow rule exists for it; keep the rule if something breaks without it, otherwise remove it."
			}
			fs = append(fs, Finding{SevInfo, "adblocking", "Frequently allowed domain looks like an ad/tracker", detail, ev, sug})
		}
		for _, c := range in.Agg.Clients(true, 0) {
			if c.Total >= in.MinClientQ && c.BlockRatio > in.HighBlockRatio {
				name := c.Name
				if name == "" {
					name = c.IP
				}
				fs = append(fs, Finding{SevInfo, "devices", "Device has a very high block ratio",
					fmt.Sprintf("%s had %.0f%% of its %d queries blocked.", name, c.BlockRatio*100, c.Total),
					[]string{c.IP}, "Use client_activity to see what it is contacting; chatty IoT/telemetry devices can be isolated or given a stricter group."})
			}
		}
	}
	for _, f := range in.Findings {
		if f.Severity != SevInfo || f.Area == "adblocking" {
			fs = append(fs, f)
		}
	}
	fs = append(fs, catalogFindings(in)...)
	SortFindings(fs)
	return fs
}

func catalogFindings(in SuggestInput) []Finding {
	installed := map[string]bool{}
	for _, l := range in.Lists {
		installed[catalog.NormalizeURL(l.Address)] = true
	}
	familyInstalled := map[string]bool{}
	for _, e := range in.Catalog {
		if installed[catalog.NormalizeURL(e.URL)] {
			familyInstalled[e.Family] = true
		}
	}
	var fs []Finding
	for _, e := range in.Catalog {
		if installed[catalog.NormalizeURL(e.URL)] || familyInstalled[e.Family] {
			continue
		}
		// only suggest gentle lists and security feeds; aggressive tiers are a user choice
		if e.Level > 2 {
			continue
		}
		if len(fs) >= 4 {
			break
		}
		fs = append(fs, Finding{SevInfo, "blocklists", "Catalog list not installed: " + e.Name,
			e.Description, []string{e.URL, "category " + e.Category}, "Consider add_blocklist if this fits your tolerance for breakage. " + e.Notes})
	}
	return fs
}
