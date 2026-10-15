package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

var now = time.Unix(1760000060, 0).UTC()

func TestParsePeriod(t *testing.T) {
	ok := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "90m": 90 * time.Minute, "1.5d": 36 * time.Hour}
	for in, want := range ok {
		if got, err := ParsePeriod(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1d", "0h", "d"} {
		if _, err := ParsePeriod(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestResolveRange(t *testing.T) {
	r, err := ResolveRange("7d", "", "", now, time.UTC, 24*time.Hour)
	if err != nil || r.Duration() != 7*24*time.Hour || !r.Until.Equal(now) {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = ResolveRange("", "", "", now, time.UTC, 24*time.Hour)
	if r.Duration() != 24*time.Hour {
		t.Fatal("default period not used")
	}
	ny, _ := time.LoadLocation("America/New_York")
	r, err = ResolveRange("", "2025-01-01", "2025-01-02", now, ny, time.Hour)
	if err != nil || r.From.UTC().Hour() != 5 {
		t.Fatalf("date should be interpreted in zone: %+v %v", r, err)
	}
	if _, err = ResolveRange("", "2025-01-02T00:00:00Z", "2025-01-01T00:00:00Z", now, time.UTC, time.Hour); err == nil {
		t.Fatal("until before from must fail")
	}
	if _, err = ResolveRange("", "garbage", "", now, time.UTC, time.Hour); err == nil {
		t.Fatal("garbage must fail")
	}
}

func q(ip, name, dom, status string, hour int) pihole.Query {
	ts := time.Date(2025, 1, 1, hour, 30, 0, 0, time.UTC).Unix()
	return pihole.Query{Time: float64(ts), Type: "A", Domain: dom, Status: status, Client: pihole.QueryClient{IP: ip, Name: name}}
}

func TestAggregator(t *testing.T) {
	a := NewAggregator(time.UTC)
	for i := 0; i < 5; i++ {
		a.Add(q("192.0.2.1", "tv", "ads.example.com", "GRAVITY", 8))
	}
	a.Add(q("192.0.2.2", "pc", "ads.example.com", "GRAVITY", 9))
	a.Add(q("192.0.2.2", "pc", "ok.example.com", "FORWARDED", 9))
	a.Add(q("192.0.2.2", "pc", "ok.example.com", "CACHE", 9))
	if a.Total != 8 || a.Blocked != 6 {
		t.Fatalf("totals %d %d", a.Total, a.Blocked)
	}
	if td := a.TopDomains(true, 5); len(td) != 1 || td[0].Count != 6 {
		t.Fatalf("top blocked %+v", td)
	}
	if td := a.TopDomains(false, 5); len(td) != 1 || td[0].Name != "ok.example.com" || td[0].Count != 2 {
		t.Fatalf("top allowed %+v", td)
	}
	m := a.BlockedMatrix(5, 5)
	if len(m) != 1 || len(m[0].Devices) != 2 || m[0].Devices[0].IP != "192.0.2.1" || m[0].Devices[0].Count != 5 || m[0].Devices[0].Name != "tv" {
		t.Fatalf("matrix %+v", m)
	}
	d, ok := a.Client("192.0.2.2", 5)
	if !ok || d.Total != 3 || d.Blocked != 1 || d.PeakHour != 9 || d.ActiveHours[9] != 3 {
		t.Fatalf("detail %+v", d)
	}
	if _, ok := a.Client("203.0.113.9", 5); ok {
		t.Fatal("unknown client should not be found")
	}
	cs := a.Clients(true, 0)
	if cs[0].IP != "192.0.2.1" || cs[0].BlockRatio != 1 {
		t.Fatalf("clients %+v", cs)
	}
}

func TestAggregatorTimezoneBucketing(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	a := NewAggregator(ny)
	a.Add(q("192.0.2.1", "x", "a.example.com", "FORWARDED", 12)) // 12:30 UTC = 07:30 EST
	d, _ := a.Client("192.0.2.1", 1)
	if d.PeakHour != 7 {
		t.Fatalf("peak hour %d", d.PeakHour)
	}
}

func TestAdMatcher(t *testing.T) {
	m, err := NewAdMatcher("")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"ads.example.com", "telemetry.vendor.example", "metrics.example.net", "pixel.example.org", "x.doubleclick.net"} {
		if _, ok := m.Match(d); !ok {
			t.Errorf("%s should match", d)
		}
	}
	for _, d := range []string{"example.com", "github.com", "cdn.example.net", "roads.example.com", "headsup.example.com"} {
		if p, ok := m.Match(d); ok {
			t.Errorf("%s should not match (%s)", d, p)
		}
	}
	m, _ = NewAdMatcher("# replace-defaults\n^custom\\.")
	if _, ok := m.Match("ads.example.com"); ok {
		t.Error("defaults should be replaced")
	}
	if _, ok := m.Match("custom.example.com"); !ok {
		t.Error("custom pattern should match")
	}
	if _, err := NewAdMatcher("([bad"); err == nil {
		t.Error("bad regex must fail")
	}
}

func list(id int, addr string, enabled bool, status, number, invalid int, updatedDaysAgo int) pihole.List {
	return pihole.List{ID: id, Address: addr, Type: "block", Enabled: enabled, Status: status, Number: number, InvalidDomains: invalid,
		DateUpdated: now.Add(-time.Duration(updatedDaysAgo) * 24 * time.Hour).Unix()}
}

func titles(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, string(f.Severity)+":"+f.Title)
	}
	return strings.Join(s, " | ")
}

func TestAssessLists(t *testing.T) {
	lists := []pihole.List{
		list(1, "https://a.example/ok.txt", true, 1, 1000, 0, 1),
		list(2, "https://a.example/stale.txt", true, 2, 1000, 0, 30),
		list(3, "https://a.example/broken.txt", true, 3, 0, 0, 40),
		list(4, "https://a.example/off.txt", false, 1, 10, 0, 1),
		list(5, "https://a.example/messy.txt", true, 1, 100, 400, 1),
		list(6, "https://a.example/empty.txt", true, 1, 0, 0, 1),
		list(7, "https://a.example/ok.txt/", true, 1, 1000, 0, 1),
	}
	got := titles(AssessLists(lists, nil, now, Thresholds{StaleListDays: 7}))
	for _, want := range []string{
		"critical:List failed to download", "warning:List has not been updated recently",
		"info:List is disabled", "warning:List has many invalid entries",
		"warning:List contains no domains", "warning:Duplicate list address"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Count(got, "List has not been updated recently") != 1 {
		t.Errorf("only the stale list should be flagged: %s", got)
	}
	fs := AssessLists(lists, nil, now, Thresholds{StaleListDays: 7})
	if fs[0].Severity != SevCritical {
		t.Errorf("findings must be sorted by severity")
	}
}

func TestAssessRules(t *testing.T) {
	rules := []pihole.DomainRule{
		{ID: 1, Type: "allow", Kind: "regex", Domain: ".*", Enabled: true},
		{ID: 2, Type: "allow", Kind: "regex", Domain: `(\.|^)github\.com$`, Enabled: true},
		{ID: 3, Type: "deny", Kind: "regex", Domain: `.`, Enabled: true},
		{ID: 4, Type: "allow", Kind: "regex", Domain: ".*", Enabled: false},
		{ID: 5, Type: "allow", Kind: "exact", Domain: "x.example", Enabled: true},
	}
	fs := AssessLists(nil, rules, now, Thresholds{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %s", titles(fs))
	}
	if fs[0].Severity != SevCritical || !strings.Contains(fs[0].Detail, "#1") {
		t.Errorf("broad allow should be critical first: %+v", fs[0])
	}
}

func TestContribution(t *testing.T) {
	lists := []pihole.List{
		{ID: 1, Address: "a", Enabled: true, Number: 100, Type: "block"},
		{ID: 2, Address: "b", Enabled: true, Number: 100, Type: "block"},
		{ID: 3, Address: "c", Enabled: true, Number: 100, Type: "block"},
	}
	sample := map[string][]int{}
	for i := 0; i < 12; i++ {
		d := string(rune('a'+i)) + ".example"
		if i < 8 {
			sample[d] = []int{1} // exclusive to list 1
		} else {
			sample[d] = []int{1, 2} // 2 fully overlapped by 1
		}
	}
	c := Contribution(lists, sample)
	if c[0].Matched != 12 || c[0].Exclusive != 8 || c[1].Matched != 4 || c[1].Exclusive != 0 || c[2].Matched != 0 {
		t.Fatalf("%+v", c)
	}
	got := titles(ContributionFindings(lists, c, 12))
	if !strings.Contains(got, "none of the sampled") || !strings.Contains(got, "fully overlapped") {
		t.Fatalf("%s", got)
	}
	if ContributionFindings(lists, c, 5) != nil {
		t.Fatal("small samples must not be judged")
	}
}

func TestHealth(t *testing.T) {
	in := HealthInput{
		System: map[string]any{"system": map[string]any{
			"memory": map[string]any{"ram": map[string]any{"%used": 91.0}, "swap": map[string]any{"%used": 5.0}},
			"cpu":    map[string]any{"load": map[string]any{"percent": []any{10.0, 20.0, 95.0}}}}},
		Sensors:  map[string]any{"sensors": map[string]any{"cpu_temp": 82.0, "hot_limit": 85.0}},
		Messages: []pihole.Message{{Type: "DNSMASQ_WARN", Plain: "boom"}},
		Upstream: &pihole.Upstreams{Upstreams: []pihole.Upstream{{IP: "192.0.2.53", Count: 100}}},
		Version: map[string]any{"version": map[string]any{
			"core": map[string]any{"local": map[string]any{"version": "v6.0"}, "remote": map[string]any{"version": "v6.1"}}}},
		BogusDNSSEC: 3, SampleSize: 100, Now: now,
		Devices: []pihole.Device{{HWAddr: "00:00:5e:00:53:01", LastQuery: now.Add(-20 * 24 * time.Hour).Unix(),
			IPs: []pihole.DeviceIP{{IP: "192.0.2.14", Name: "old-camera", LastSeen: now.Add(-time.Minute).Unix()}}}},
	}
	in.Summary = &pihole.Summary{}
	in.Summary.Queries.Total = 1000
	in.Summary.Queries.Cached = 10
	in.Summary.Queries.Replies = map[string]int{"NXDOMAIN": 300, "SERVFAIL": 50}
	got := titles(Health(in))
	for _, want := range []string{"High memory use", "Sustained high CPU load", "CPU is overheating", "FTL diagnostic: DNSMASQ_WARN",
		"Single upstream resolver", "Very low cache hit ratio", "High NXDOMAIN rate", "SERVFAIL replies",
		"DNSSEC validation failures", "Update available: CORE", "Device may be bypassing Pi-hole"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestHealthEmptyInputIsQuiet(t *testing.T) {
	if fs := Health(HealthInput{Now: now}); len(fs) != 0 {
		t.Fatalf("no data must produce no findings: %s", titles(fs))
	}
}

func TestBypassIgnoresStaleAndActiveDevices(t *testing.T) {
	devs := []pihole.Device{
		{LastQuery: now.Add(-time.Hour).Unix(), IPs: []pihole.DeviceIP{{IP: "a", LastSeen: now.Unix()}}},        // active
		{LastQuery: 0, IPs: []pihole.DeviceIP{{IP: "b", LastSeen: now.Add(-30 * 24 * time.Hour).Unix()}}},       // gone
		{LastQuery: 0, IPs: []pihole.DeviceIP{{IP: "c", Name: "silent", LastSeen: now.Add(-time.Hour).Unix()}}}, // silent
	}
	fs := BypassFindings(devs, now)
	if len(fs) != 1 || !strings.Contains(fs[0].Detail, "silent") {
		t.Fatalf("%+v", fs)
	}
}

func TestSuggest(t *testing.T) {
	agg := NewAggregator(time.UTC)
	for i := 0; i < 6; i++ {
		agg.Add(q("192.0.2.1", "tv", "ads.example-tracker.net", "FORWARDED", 8))
	}
	agg.Add(q("192.0.2.1", "tv", "github.com", "FORWARDED", 8))
	for i := 0; i < 30; i++ {
		agg.Add(q("192.0.2.2", "fridge", "telemetry.vendor.example", "GRAVITY", 8))
	}
	ads, _ := NewAdMatcher("")
	cat := []catalog.Entry{
		{ID: "x", Name: "X Light", URL: "https://x.example/l.txt", Family: "x", Level: 1, Category: "general"},
		{ID: "y", Name: "Y Pro", URL: "https://y.example/p.txt", Family: "y", Level: 2, Category: "general"},
		{ID: "yp", Name: "Y Pro++", URL: "https://y.example/pp.txt", Family: "y", Level: 3, Category: "general"},
	}
	lists := []pihole.List{{ID: 1, Address: "https://y.example/p.txt", Enabled: true, Type: "block"}}
	rules := []pihole.DomainRule{{Type: "allow", Kind: "exact", Domain: "ads.example-tracker.net", Enabled: true}}
	fs := Suggest(SuggestInput{Agg: agg, Lists: lists, Rules: rules, Catalog: cat, Ads: ads, HighBlockRatio: 0.5,
		Findings: []Finding{{Severity: SevCritical, Area: "blocklists", Title: "List failed to download"}, {Severity: SevInfo, Area: "health", Title: "noise"}}})
	got := titles(fs)
	for _, want := range []string{"critical:List failed", "Frequently allowed domain looks like an ad/tracker", "Device has a very high block ratio", "Catalog list not installed: X Light"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	for _, not := range []string{"noise", "Y Pro", "Pro++"} {
		if strings.Contains(got, not) {
			t.Errorf("unexpected %q in %s", not, got)
		}
	}
	if fs[0].Severity != SevCritical {
		t.Error("critical first")
	}
	var explicit bool
	for _, f := range fs {
		if strings.Contains(f.Detail, "explicit allow rule") {
			explicit = true
		}
	}
	if !explicit {
		t.Error("explicit allow rule should be noted")
	}
}
