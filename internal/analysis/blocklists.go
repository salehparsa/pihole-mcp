package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// Thresholds tune the assessments.
type Thresholds struct {
	StaleListDays int
}

// AssessLists inspects block lists and allow/deny rules.
func AssessLists(lists []pihole.List, rules []pihole.DomainRule, now time.Time, th Thresholds) []Finding {
	var fs []Finding
	seenAddr := map[string][]int{}
	for _, l := range lists {
		if l.Type != "" && l.Type != "block" {
			continue
		}
		key := strings.ToLower(strings.TrimRight(l.Address, "/"))
		seenAddr[key] = append(seenAddr[key], l.ID)
		ev := []string{l.Address}
		failed := l.Status == pihole.ListStatusUnavailable || l.Status == pihole.ListStatusInvalid
		switch {
		case !l.Enabled:
			fs = append(fs, Finding{SevInfo, "blocklists", "List is disabled",
				fmt.Sprintf("List #%d is installed but disabled, so it blocks nothing.", l.ID), ev,
				"Remove it if it is no longer wanted, or enable it."})
			continue
		case failed:
			fs = append(fs, Finding{SevCritical, "blocklists", "List failed to download",
				fmt.Sprintf("List #%d has status %d (%s). Pi-hole could not download a usable copy, so its domains may not be blocked (an old cached copy may still be in use).", l.ID, l.Status, statusName(l.Status)), ev,
				"Check the URL still exists; remove or replace the list, then update gravity."})
			continue
		}
		if l.Number == 0 && l.ABPEntries == 0 {
			fs = append(fs, Finding{SevWarning, "blocklists", "List contains no domains",
				fmt.Sprintf("List #%d is enabled but Pi-hole imported 0 domains from it.", l.ID), ev,
				"Verify the URL and format, or remove the list."})
		}
		if th.StaleListDays > 0 && l.DateUpdated > 0 {
			age := now.Sub(time.Unix(l.DateUpdated, 0))
			if age > time.Duration(th.StaleListDays)*24*time.Hour {
				fs = append(fs, Finding{SevWarning, "blocklists", "List has not been updated recently",
					fmt.Sprintf("List #%d was last updated %d days ago (threshold %d).", l.ID, int(age.Hours()/24), th.StaleListDays),
					append(ev, "date_updated="+time.Unix(l.DateUpdated, 0).UTC().Format(time.RFC3339)),
					"Run update_gravity; if it stays stale the source may be dead."})
			}
		}
		if total := l.Number + l.InvalidDomains; total > 0 && float64(l.InvalidDomains)/float64(total) > 0.2 {
			fs = append(fs, Finding{SevWarning, "blocklists", "List has many invalid entries",
				fmt.Sprintf("List #%d: %d of %d entries (%.0f%%) were rejected as invalid.", l.ID, l.InvalidDomains, total, 100*float64(l.InvalidDomains)/float64(total)), ev,
				"The list may be in a format Pi-hole does not fully support; consider a domain-format variant."})
		}
	}
	for addr, ids := range seenAddr {
		if len(ids) > 1 {
			fs = append(fs, Finding{SevWarning, "blocklists", "Duplicate list address",
				fmt.Sprintf("The same address is installed %d times (ids %v).", len(ids), ids), []string{addr}, "Remove the duplicates."})
		}
	}
	fs = append(fs, assessRules(rules)...)
	SortFindings(fs)
	return fs
}

func statusName(s int) string {
	switch s {
	case pihole.ListStatusUnavailable:
		return "unavailable"
	case pihole.ListStatusInvalid:
		return "invalid"
	case pihole.ListStatusDownloaded:
		return "downloaded"
	case pihole.ListStatusUnchanged:
		return "unchanged"
	}
	return "unknown"
}

var broadProbe = []string{"example.com", "ads.tracker.net", "a.b.c.example.org", "xn--mnchen-3ya.de"}

func assessRules(rules []pihole.DomainRule) []Finding {
	var fs []Finding
	for _, r := range rules {
		if !r.Enabled || r.Kind != "regex" {
			continue
		}
		re, err := regexp.Compile(r.Domain)
		if err != nil {
			fs = append(fs, Finding{SevWarning, "rules", "Regex rule does not compile in Go's RE2",
				fmt.Sprintf("Rule #%d (%s) is not valid RE2 syntax; Pi-hole uses PCRE-compatible RE2-like matching, so check it.", r.ID, r.Type),
				[]string{r.Domain}, "Review the expression."})
			continue
		}
		hits := 0
		for _, p := range broadProbe {
			if re.MatchString(p) {
				hits++
			}
		}
		if hits == len(broadProbe) {
			sev, what := SevWarning, ""
			title := "Regex " + r.Type + " rule is extremely broad"
			sug := "Anchor and narrow the expression."
			if r.Type == "allow" {
				sev = SevCritical
				what = "matches everything, effectively disabling blocking for all clients in its groups"
				sug = "Remove or tighten this allow rule."
			} else {
				what = "matches everything, so it blocks all DNS"
			}
			fs = append(fs, Finding{sev, "rules", title, fmt.Sprintf("Rule #%d %s.", r.ID, what), []string{r.Domain}, sug})
		}
	}
	return fs
}

// ListContribution describes how a list performs against a sample of blocked domains.
type ListContribution struct {
	ListID    int    `json:"list_id"`
	Address   string `json:"address"`
	Matched   int    `json:"matched"`
	Exclusive int    `json:"exclusive"`
}

// Contribution attributes sampled blocked domains to lists. sample maps each
// domain to the ids of lists that match it.
func Contribution(lists []pihole.List, sample map[string][]int) []ListContribution {
	byID := map[int]*ListContribution{}
	for _, l := range lists {
		if l.Enabled && (l.Type == "" || l.Type == "block") {
			byID[l.ID] = &ListContribution{ListID: l.ID, Address: l.Address}
		}
	}
	for _, ids := range sample {
		for _, id := range ids {
			if c := byID[id]; c != nil {
				c.Matched++
				if len(ids) == 1 {
					c.Exclusive++
				}
			}
		}
	}
	out := make([]ListContribution, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ListID < out[j].ListID })
	return out
}

// ContributionFindings turns contribution numbers into findings. sampleSize is
// the number of sampled domains; lists are only judged with at least 10.
func ContributionFindings(lists []pihole.List, contrib []ListContribution, sampleSize int) []Finding {
	if sampleSize < 10 {
		return nil
	}
	num := map[int]int{}
	for _, l := range lists {
		num[l.ID] = l.Number
	}
	var fs []Finding
	for _, c := range contrib {
		ev := []string{c.Address, fmt.Sprintf("matched %d of %d sampled blocked domains, exclusive %d", c.Matched, sampleSize, c.Exclusive)}
		switch {
		case c.Matched == 0 && num[c.ListID] > 0:
			fs = append(fs, Finding{SevInfo, "blocklists", "List blocked none of the sampled domains",
				fmt.Sprintf("List #%d contains %d domains but none of the %d most-blocked domains in the period.", c.ListID, num[c.ListID], sampleSize), ev,
				"It may be dead weight for your traffic; consider removing it (it may still cover rarely-hit domains)."})
		case c.Matched > 0 && c.Exclusive == 0:
			fs = append(fs, Finding{SevInfo, "blocklists", "List is fully overlapped by others",
				fmt.Sprintf("Every sampled domain that list #%d blocks is also blocked by another list.", c.ListID), ev,
				"Removing it would likely change nothing for the sampled traffic."})
		}
	}
	return fs
}
