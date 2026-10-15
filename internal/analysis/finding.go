// Package analysis holds pure, unit-tested functions that turn Pi-hole data into
// evidence. It has no network or MCP dependencies.
package analysis

import "sort"

// Severity ranks a finding.
type Severity string

// Severity levels, most severe first.
const (
	SevCritical Severity = "critical"
	SevWarning  Severity = "warning"
	SevInfo     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SevCritical:
		return 0
	case SevWarning:
		return 1
	default:
		return 2
	}
}

// Finding is one observation, with the evidence behind it.
type Finding struct {
	Severity   Severity `json:"severity"`
	Area       string   `json:"area"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Evidence   []string `json:"evidence,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
}

// SortFindings orders by severity (stable, so insertion order breaks ties).
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity.rank() < fs[j].Severity.rank() })
}
