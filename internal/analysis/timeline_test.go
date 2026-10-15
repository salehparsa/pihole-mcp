package analysis

import (
	"testing"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

func TestTimelineBuckets(t *testing.T) {
	tl := NewTimeline(time.Hour, time.UTC)
	base := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	tl.AddQuery(pihole.Query{Time: float64(base.Add(5 * time.Minute).Unix()), Status: "GRAVITY"})
	tl.AddQuery(pihole.Query{Time: float64(base.Add(50 * time.Minute).Unix()), Status: "CACHE"})
	tl.AddQuery(pihole.Query{Time: float64(base.Add(70 * time.Minute).Unix()), Status: "FORWARDED"})
	tl.AddPoint(pihole.HistoryPoint{Timestamp: float64(base.Add(2*time.Hour).Unix()) + 0.5, Total: 7, Blocked: 2})
	b := tl.Buckets()
	if len(b) != 3 || b[0].Total != 2 || b[0].Blocked != 1 || b[0].Cached != 1 || b[1].Forwarded != 1 || b[2].Total != 7 {
		t.Fatalf("%+v", b)
	}
	if !b[0].Start.Equal(base) {
		t.Fatalf("start %v", b[0].Start)
	}
}

func TestTimelineDayBucketsUseLocalMidnight(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	tl := NewTimeline(24*time.Hour, ny)
	tl.AddQuery(pihole.Query{Time: float64(time.Date(2025, 1, 1, 3, 0, 0, 0, time.UTC).Unix())}) // Dec 31 22:00 local
	b := tl.Buckets()
	if b[0].Start.Day() != 31 || b[0].Start.Hour() != 0 {
		t.Fatalf("%v", b[0].Start)
	}
}

func TestDefaultBucket(t *testing.T) {
	if DefaultBucket(time.Hour) != 10*time.Minute || DefaultBucket(24*time.Hour) != time.Hour || DefaultBucket(7*24*time.Hour) != 24*time.Hour {
		t.Fatal("bucket defaults")
	}
}
