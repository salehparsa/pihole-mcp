package pihole_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
	"github.com/salehparsa/pihole-mcp/internal/testutil/fakepihole"
)

func newClient(t *testing.T, f *fakepihole.Server, pw string) *pihole.Client {
	t.Helper()
	c, err := pihole.New(pihole.Options{BaseURL: f.URL, Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginAndSummary(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	s, err := c.Summary(context.Background(), pihole.TimeRange{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Queries.Total != 360 || s.Gravity.DomainsBeingBlocked != 176000 {
		t.Fatalf("unexpected summary %+v", s)
	}
	if f.Logins() != 1 {
		t.Fatalf("want 1 login, got %d", f.Logins())
	}
	_, _ = c.Summary(context.Background(), pihole.TimeRange{})
	if f.Logins() != 1 {
		t.Fatal("session should be reused")
	}
}

func TestWrongPassword(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, "nope")
	_, err := c.Summary(context.Background(), pihole.TimeRange{})
	if err == nil || !pihole.IsAuthError(err) {
		t.Fatalf("want auth error, got %v", err)
	}
}

func Test401ReloginRetry(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	if _, err := c.Summary(context.Background(), pihole.TimeRange{}); err != nil {
		t.Fatal(err)
	}
	f.ExpireSessions()
	if _, err := c.Summary(context.Background(), pihole.TimeRange{}); err != nil {
		t.Fatalf("should transparently re-login: %v", err)
	}
	if f.Logins() != 2 {
		t.Fatalf("want 2 logins, got %d", f.Logins())
	}
}

func TestCloseLogsOut(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	_, _ = c.Summary(context.Background(), pihole.TimeRange{})
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.Logouts() != 1 {
		t.Fatal("expected logout")
	}
}

func TestAPIErrorPassedThrough(t *testing.T) {
	f := fakepihole.New(t)
	f.FailPath("/stats/summary", 500)
	c := newClient(t, f, fakepihole.Password)
	_, err := c.Summary(context.Background(), pihole.TimeRange{})
	var ae *pihole.APIError
	if !errors.As(err, &ae) || ae.Status != 500 || ae.Key != "forced" {
		t.Fatalf("want APIError 500/forced, got %v", err)
	}
}

func TestDatabaseEndpointForRange(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	if _, err := c.Summary(context.Background(), pihole.TimeRange{From: 100, Until: 200}); err != nil {
		t.Fatal(err)
	}
	last := f.Calls()[len(f.Calls())-1]
	if !strings.Contains(last, "/api/stats/database/summary") || !strings.Contains(last, "from=100") {
		t.Fatalf("got %s", last)
	}
}

func TestScanQueriesPagesAndDedupes(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	ids := map[int]bool{}
	n, trunc, err := c.ScanQueries(context.Background(), pihole.QueryFilter{}, 100000, func(q pihole.Query) bool {
		if ids[q.ID] {
			t.Errorf("duplicate id %d", q.ID)
		}
		ids[q.ID] = true
		return true
	})
	if err != nil || trunc || n != 360 || len(ids) != 360 {
		t.Fatalf("n=%d trunc=%v err=%v ids=%d", n, trunc, err, len(ids))
	}
}

func TestScanQueriesTruncates(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	n, trunc, err := c.ScanQueries(context.Background(), pihole.QueryFilter{}, 50, func(pihole.Query) bool { return true })
	if err != nil || !trunc || n != 50 {
		t.Fatalf("n=%d trunc=%v err=%v", n, trunc, err)
	}
}

func TestDatabaseSummaryShapeIsMapped(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	s, err := c.Summary(context.Background(), pihole.TimeRange{From: fakepihole.Now - 86400*7, Until: fakepihole.Now + 1})
	if err != nil {
		t.Fatal(err)
	}
	if !s.DatabaseOnly || s.Queries.Total != 360 || s.Queries.Blocked != 172 || s.Clients.Total != 4 || s.Queries.PercentBlocked < 47 {
		t.Fatalf("%+v", s)
	}
	live, err := c.Summary(context.Background(), pihole.TimeRange{})
	if err != nil || live.DatabaseOnly || live.Queries.Cached != 50 {
		t.Fatalf("live summary: %v %+v", err, live)
	}
}

func TestFractionalTimestampsDecode(t *testing.T) {
	// /history and /info/messages report timestamps as floating point numbers
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	h, err := c.History(context.Background(), pihole.TimeRange{})
	if err != nil || len(h) == 0 || h[0].Timestamp != float64(int64(h[0].Timestamp))+0.5 {
		t.Fatalf("history: %v %+v", err, h)
	}
	m, err := c.Messages(context.Background())
	if err != nil || len(m) != 1 || m[0].Timestamp == 0 {
		t.Fatalf("messages: %v %+v", err, m)
	}
}

func TestDevicesRequestsAllOfThem(t *testing.T) {
	f := fakepihole.New(t)
	f.SetExtraDevices(15)
	c := newClient(t, f, fakepihole.Password)
	devs, err := c.Devices(context.Background())
	if err != nil || len(devs) != 20 {
		t.Fatalf("%v %d", err, len(devs))
	}
}

func TestListsCachedAndInvalidated(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	ctx := context.Background()
	l1, err := c.Lists(ctx)
	if err != nil || len(l1) != 5 {
		t.Fatalf("lists: %v %d", err, len(l1))
	}
	_, _ = c.Lists(ctx)
	gets := 0
	for _, call := range f.Calls() {
		if call == "GET /api/lists" {
			gets++
		}
	}
	if gets != 1 {
		t.Fatalf("expected cache hit, got %d GETs", gets)
	}
	if err := c.AddList(ctx, "block", pihole.ListBody{Address: "https://lists.example.org/new.txt", Groups: []int{0}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	l2, _ := c.Lists(ctx)
	if len(l2) != 6 {
		t.Fatalf("cache not invalidated after add: %d", len(l2))
	}
	if err := c.DeleteList(ctx, "block", "https://lists.example.org/new.txt"); err != nil {
		t.Fatal(err)
	}
	l3, _ := c.Lists(ctx)
	if len(l3) != 5 {
		t.Fatalf("delete failed: %d", len(l3))
	}
}

func TestDomainsAddDelete(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	ctx := context.Background()
	if err := c.AddDomain(ctx, "deny", "exact", pihole.DomainBody{Domain: "mcp-test.invalid", Groups: []int{0}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rules, _ := c.Domains(ctx, "deny", "exact")
	if len(rules) != 1 || rules[0].Domain != "mcp-test.invalid" {
		t.Fatalf("rules=%+v", rules)
	}
	if err := c.DeleteDomain(ctx, "deny", "exact", "mcp-test.invalid"); err != nil {
		t.Fatal(err)
	}
	rules, _ = c.Domains(ctx, "deny", "exact")
	if len(rules) != 0 {
		t.Fatalf("not deleted: %+v", rules)
	}
}

func TestSearchBlockingGravityVersion(t *testing.T) {
	f := fakepihole.New(t)
	c := newClient(t, f, fakepihole.Password)
	ctx := context.Background()
	sr, err := c.Search(ctx, "pixel.example-track.net", 20)
	if err != nil || len(sr.Gravity) != 2 {
		t.Fatalf("search: %v %+v", err, sr)
	}
	b, err := c.SetBlocking(ctx, false, 60)
	if err != nil || b.Blocking != "disabled" {
		t.Fatalf("blocking: %v %+v", err, b)
	}
	var lines []string
	if err := c.UpdateGravity(ctx, func(l string) { lines = append(lines, l) }); err != nil || len(lines) != 4 {
		t.Fatalf("gravity: %v %v", err, lines)
	}
	v, err := c.FTLVersion(ctx)
	if err != nil || v != "v6.7.1" {
		t.Fatalf("version: %v %q", err, v)
	}
}
