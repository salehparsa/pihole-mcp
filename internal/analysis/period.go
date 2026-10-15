package analysis

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Range is a resolved time window.
type Range struct {
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}

// Duration is the window length.
func (r Range) Duration() time.Duration { return r.Until.Sub(r.From) }

// ParsePeriod parses "90m", "24h", "7d", "2w" or any time.ParseDuration string.
func ParsePeriod(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty period")
	}
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if strings.HasSuffix(s, suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64)
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("invalid period %q", s)
			}
			return time.Duration(n * float64(unit)), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid period %q (use e.g. 1h, 24h, 7d, 30d)", s)
	}
	return d, nil
}

// ResolveRange picks the window from either from/until (RFC3339, or a date
// without zone interpreted in loc) or a period ending now. Explicit from/until
// win over period; period defaults to def.
func ResolveRange(period, from, until string, now time.Time, loc *time.Location, def time.Duration) (Range, error) {
	if from != "" || until != "" {
		r := Range{Until: now}
		var err error
		if from != "" {
			if r.From, err = parseTime(from, loc); err != nil {
				return r, fmt.Errorf("from: %w", err)
			}
		} else {
			r.From = now.Add(-def)
		}
		if until != "" {
			if r.Until, err = parseTime(until, loc); err != nil {
				return r, fmt.Errorf("until: %w", err)
			}
		}
		if !r.Until.After(r.From) {
			return r, fmt.Errorf("until must be after from")
		}
		return r, nil
	}
	d := def
	if period != "" {
		var err error
		if d, err = ParsePeriod(period); err != nil {
			return Range{}, err
		}
	}
	return Range{From: now.Add(-d), Until: now}, nil
}

func parseTime(s string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q (use RFC3339, e.g. 2025-01-31T08:00:00Z)", s)
}
