package tools

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

func registerBlocklists(srv *mcp.Server, d *Deps) {
	addRead(srv, "list_blocklists", "List block lists",
		"All subscribed block/allow lists with domain counts, status, last update and whether they are enabled.",
		d.listBlocklists)
	addRead(srv, "list_domain_rules", "List allow/deny rules",
		"Exact and regex allow/deny rules, optionally filtered by type (allow|deny) and kind (exact|regex).",
		d.listDomainRules)
	addRead(srv, "assess_blocklists", "Assess block lists",
		"Health review of block lists and rules: failed or stale lists, empty or messy lists, duplicates, over-broad allow regexes, and (from a sample of the most-blocked domains) lists that contribute nothing or are fully overlapped by others. Returns findings with evidence; you write the advice.",
		d.assessBlocklists)
}

// ListBlocklistsIn is the input of list_blocklists.
type ListBlocklistsIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
}

// ListOut is one block list.
type ListOut struct {
	ID             int    `json:"id"`
	Address        string `json:"address"`
	Type           string `json:"type"`
	Enabled        bool   `json:"enabled"`
	Comment        string `json:"comment,omitempty"`
	Domains        int    `json:"domains"`
	InvalidDomains int    `json:"invalid_domains"`
	ABPEntries     int    `json:"abp_entries,omitempty"`
	Status         string `json:"status"`
	LastUpdated    string `json:"last_updated,omitempty"`
	Groups         []int  `json:"groups"`
}

// ListBlocklistsOut is the output of list_blocklists.
type ListBlocklistsOut struct {
	Instance     string    `json:"instance"`
	Lists        []ListOut `json:"lists"`
	TotalDomains int       `json:"total_domains"`
}

func listStatus(s int) string {
	switch s {
	case pihole.ListStatusDownloaded:
		return "downloaded"
	case pihole.ListStatusUnchanged:
		return "unchanged"
	case pihole.ListStatusUnavailable:
		return "unavailable"
	case pihole.ListStatusInvalid:
		return "invalid"
	}
	return "unknown"
}

func (d *Deps) listBlocklists(ctx context.Context, in ListBlocklistsIn) (ListBlocklistsOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return ListBlocklistsOut{}, "", err
	}
	ls, err := c.Lists(ctx)
	if err != nil {
		return ListBlocklistsOut{}, "", err
	}
	out := ListBlocklistsOut{Instance: name, Lists: []ListOut{}}
	enabled := 0
	for _, l := range ls {
		o := ListOut{ID: l.ID, Address: l.Address, Type: l.Type, Enabled: l.Enabled, Comment: l.Comment, Domains: l.Number,
			InvalidDomains: l.InvalidDomains, ABPEntries: l.ABPEntries, Status: listStatus(l.Status), Groups: l.Groups}
		if l.DateUpdated > 0 {
			o.LastUpdated = d.unix(float64(l.DateUpdated))
		}
		if l.Enabled {
			enabled++
			out.TotalDomains += l.Number
		}
		out.Lists = append(out.Lists, o)
	}
	return out, fmt.Sprintf("%d lists (%d enabled) holding %d domains in total.", len(ls), enabled, out.TotalDomains), nil
}

// ListDomainRulesIn is the input of list_domain_rules.
type ListDomainRulesIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Type     string `json:"type,omitempty" jsonschema:"allow or deny (default: both)"`
	Kind     string `json:"kind,omitempty" jsonschema:"exact or regex (default: both)"`
}

// RuleOut is one allow/deny rule.
type RuleOut struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`
	Added   string `json:"added,omitempty"`
	Groups  []int  `json:"groups"`
}

// ListDomainRulesOut is the output of list_domain_rules.
type ListDomainRulesOut struct {
	Instance string    `json:"instance"`
	Rules    []RuleOut `json:"rules"`
}

func validTypeKind(typ, kind string) error {
	if typ != "" && typ != "allow" && typ != "deny" {
		return errf("type must be allow or deny")
	}
	if kind != "" && kind != "exact" && kind != "regex" {
		return errf("kind must be exact or regex")
	}
	if kind != "" && typ == "" {
		return errf("kind requires type")
	}
	return nil
}

func (d *Deps) listDomainRules(ctx context.Context, in ListDomainRulesIn) (ListDomainRulesOut, string, error) {
	if err := validTypeKind(in.Type, in.Kind); err != nil {
		return ListDomainRulesOut{}, "", err
	}
	name, c, err := d.client(in.Instance)
	if err != nil {
		return ListDomainRulesOut{}, "", err
	}
	rs, err := c.Domains(ctx, in.Type, in.Kind)
	if err != nil {
		return ListDomainRulesOut{}, "", err
	}
	out := ListDomainRulesOut{Instance: name, Rules: []RuleOut{}}
	for _, r := range rs {
		o := RuleOut{ID: r.ID, Domain: r.Domain, Type: r.Type, Kind: r.Kind, Enabled: r.Enabled, Comment: r.Comment, Groups: r.Groups}
		if r.DateAdded > 0 {
			o.Added = d.unix(float64(r.DateAdded))
		}
		out.Rules = append(out.Rules, o)
	}
	return out, fmt.Sprintf("%d allow/deny rules.", len(out.Rules)), nil
}

// AssessBlocklistsIn is the input of assess_blocklists.
type AssessBlocklistsIn struct {
	Instance string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Period   string `json:"period,omitempty" jsonschema:"Window used to pick the most-blocked domains to sample (default 7d)"`
	Sample   int    `json:"sample,omitempty" jsonschema:"How many top-blocked domains to attribute to lists (0-200, default 50; 0 skips attribution)"`
}

// AssessBlocklistsOut is the output of assess_blocklists.
type AssessBlocklistsOut struct {
	Instance     string                      `json:"instance"`
	Findings     []analysis.Finding          `json:"findings"`
	Contribution []analysis.ListContribution `json:"contribution,omitempty"`
	SampleSize   int                         `json:"sample_size"`
	Lists        int                         `json:"lists"`
	Rules        int                         `json:"rules"`
}

func (d *Deps) assessBlocklists(ctx context.Context, in AssessBlocklistsIn) (AssessBlocklistsOut, string, error) {
	name, c, err := d.client(in.Instance)
	if err != nil {
		return AssessBlocklistsOut{}, "", err
	}
	period := in.Period
	if period == "" {
		period = "7d"
	}
	r, err := d.window(period, "", "")
	if err != nil {
		return AssessBlocklistsOut{}, "", err
	}
	lists, err := c.Lists(ctx)
	if err != nil {
		return AssessBlocklistsOut{}, "", err
	}
	rules, err := c.Domains(ctx, "", "")
	if err != nil {
		return AssessBlocklistsOut{}, "", err
	}
	out := AssessBlocklistsOut{Instance: name, Lists: len(lists), Rules: len(rules)}
	out.Findings = analysis.AssessLists(lists, rules, d.now(), analysis.Thresholds{StaleListDays: d.Cfg.Analysis.StaleListDays})
	n := in.Sample
	if n == 0 {
		n = 50
	} else if n < 0 {
		n = 0
	}
	if n > 200 {
		n = 200
	}
	if in.Sample >= 0 && n > 0 {
		sample, err := d.sampleListMatches(ctx, c, r, n)
		if err != nil {
			out.Findings = append(out.Findings, analysis.Finding{Severity: analysis.SevInfo, Area: "blocklists", Title: "List attribution skipped",
				Detail: "Could not sample blocked domains: " + err.Error()})
		} else {
			out.SampleSize = len(sample)
			out.Contribution = analysis.Contribution(lists, sample)
			out.Findings = append(out.Findings, analysis.ContributionFindings(lists, out.Contribution, len(sample))...)
		}
	}
	analysis.SortFindings(out.Findings)
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
	return out, fmt.Sprintf("%d lists, %d rules assessed: %d critical, %d warning, %d total findings (attributed %d sampled domains).",
		out.Lists, out.Rules, crit, warn, len(out.Findings), out.SampleSize), nil
}

// sampleListMatches maps the most-blocked domains to the lists that contain them.
func (d *Deps) sampleListMatches(ctx context.Context, c *pihole.Client, r analysis.Range, n int) (map[string][]int, error) {
	top, _, err := stats(d, r, func(tr pihole.TimeRange) (*pihole.TopDomains, error) { return c.TopDomains(ctx, tr, n, true) })
	if err != nil {
		return nil, err
	}
	type res struct {
		dom string
		ids []int
		err error
	}
	results := make(chan res, len(top.Domains))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, dc := range top.Domains {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			sr, err := c.Search(cctx, dom, 50)
			if err != nil {
				results <- res{dom: dom, err: err}
				return
			}
			var ids []int
			for _, g := range sr.Gravity {
				if g.Type != "allow" {
					ids = append(ids, g.ID)
				}
			}
			results <- res{dom: dom, ids: ids}
		}(dc.Domain)
	}
	wg.Wait()
	close(results)
	sample := map[string][]int{}
	var firstErr error
	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if len(r.ids) > 0 { // domains blocked by rules or CNAME have no list to credit
			sort.Ints(r.ids)
			sample[r.dom] = r.ids
		}
	}
	if len(sample) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return sample, nil
}
