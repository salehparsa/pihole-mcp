package analysis

import (
	"sort"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// Bucket is a slice of the timeline.
type Bucket struct {
	Start     time.Time `json:"-"`
	Total     int       `json:"total"`
	Blocked   int       `json:"blocked"`
	Cached    int       `json:"cached,omitempty"`
	Forwarded int       `json:"forwarded,omitempty"`
}

// Timeline accumulates counts into fixed-size buckets aligned in loc.
type Timeline struct {
	size    time.Duration
	loc     *time.Location
	buckets map[int64]*Bucket
}

// NewTimeline creates a timeline with the given bucket size.
func NewTimeline(size time.Duration, loc *time.Location) *Timeline {
	if loc == nil {
		loc = time.UTC
	}
	if size <= 0 {
		size = time.Hour
	}
	return &Timeline{size: size, loc: loc, buckets: map[int64]*Bucket{}}
}

func (t *Timeline) start(ts time.Time) time.Time {
	ts = ts.In(t.loc)
	if t.size == 24*time.Hour {
		y, m, d := ts.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, t.loc)
	}
	return ts.Truncate(t.size)
}

func (t *Timeline) bucket(ts time.Time) *Bucket {
	s := t.start(ts)
	b := t.buckets[s.Unix()]
	if b == nil {
		b = &Bucket{Start: s}
		t.buckets[s.Unix()] = b
	}
	return b
}

// AddQuery records one query.
func (t *Timeline) AddQuery(q pihole.Query) {
	b := t.bucket(time.Unix(int64(q.Time), 0))
	b.Total++
	if pihole.IsBlocked(q.Status) {
		b.Blocked++
	}
	switch q.Status {
	case "CACHE", "CACHE_STALE":
		b.Cached++
	case "FORWARDED", "RETRIED":
		b.Forwarded++
	}
}

// AddPoint records one /history slot.
func (t *Timeline) AddPoint(p pihole.HistoryPoint) {
	b := t.bucket(time.Unix(int64(p.Timestamp), 0))
	b.Total += p.Total
	b.Blocked += p.Blocked
	b.Cached += p.Cached
	b.Forwarded += p.Forwarded
}

// Buckets returns the buckets in chronological order.
func (t *Timeline) Buckets() []Bucket {
	out := make([]Bucket, 0, len(t.buckets))
	for _, b := range t.buckets {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// DefaultBucket picks a sensible bucket size for a window.
func DefaultBucket(window time.Duration) time.Duration {
	switch {
	case window <= 3*time.Hour:
		return 10 * time.Minute
	case window <= 48*time.Hour:
		return time.Hour
	default:
		return 24 * time.Hour
	}
}
