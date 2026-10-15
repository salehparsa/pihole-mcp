package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// HealthInput is everything network health needs; any part may be nil/empty
// (the API varies by platform), and missing data simply produces no finding.
type HealthInput struct {
	System   map[string]any
	Sensors  map[string]any
	Database map[string]any
	Version  map[string]any
	Messages []pihole.Message
	Upstream *pihole.Upstreams
	Summary  *pihole.Summary
	Devices  []pihole.Device
	// BogusDNSSEC is the number of sampled queries whose DNSSEC status was BOGUS.
	BogusDNSSEC int
	SampleSize  int
	Now         time.Time
}

// dig walks nested maps and returns a number, if present.
func dig(m map[string]any, path ...string) (float64, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = mm[p]
	}
	f, ok := cur.(float64)
	return f, ok
}

// Health evaluates the Pi-hole host and DNS service.
func Health(in HealthInput) []Finding {
	var fs []Finding
	add := func(sev Severity, title, detail string, ev []string, sug string) {
		fs = append(fs, Finding{sev, "health", title, detail, ev, sug})
	}
	if in.System != nil {
		if v, ok := dig(in.System, "system", "memory", "ram", "%used"); ok && v > 85 {
			add(SevWarning, "High memory use", fmt.Sprintf("RAM use is %.0f%%.", v), nil, "Check for other workloads on the host; consider a smaller block list set.")
		}
		if v, ok := dig(in.System, "system", "memory", "swap", "%used"); ok && v > 50 {
			add(SevWarning, "Heavy swap use", fmt.Sprintf("Swap use is %.0f%%.", v), nil, "On SD cards heavy swapping wears the card; reduce memory pressure.")
		}
		if arr, ok := nestedSlice(in.System, "system", "cpu", "load", "percent"); ok && len(arr) > 2 && arr[2] > 80 {
			add(SevWarning, "Sustained high CPU load", fmt.Sprintf("15-minute load is %.0f%% of capacity.", arr[2]), nil, "")
		}
	}
	if in.Sensors != nil {
		temp, okT := dig(in.Sensors, "sensors", "cpu_temp")
		limit, okL := dig(in.Sensors, "sensors", "hot_limit")
		if sm, _ := in.Sensors["sensors"].(map[string]any); sm != nil {
			if unit, _ := sm["unit"].(string); strings.EqualFold(unit, "F") {
				temp, limit = (temp-32)*5/9, (limit-32)*5/9
			}
		}
		if okT {
			switch {
			case temp >= 80, okL && temp >= limit:
				add(SevCritical, "CPU is overheating", fmt.Sprintf("CPU temperature is %.1f°C.", temp), nil, "Improve cooling; the SoC will throttle.")
			case temp >= 70:
				add(SevWarning, "CPU is running hot", fmt.Sprintf("CPU temperature is %.1f°C.", temp), nil, "Consider a heatsink or better airflow.")
			}
		}
	}
	if in.Database != nil {
		if size, ok := dig(in.Database, "size"); ok && size > 2e9 {
			add(SevWarning, "Query database is large", fmt.Sprintf("Database size is %.1f GB.", size/1e9), nil, "Lower webserver/database maxDBdays to shrink it.")
		}
	}
	for _, m := range in.Messages {
		txt := m.Plain
		if txt == "" {
			txt = m.HTML
		}
		add(SevWarning, "FTL diagnostic: "+m.Type, strings.TrimSpace(txt), nil, "Review the message in the Pi-hole UI (Tools → Pi-hole diagnosis) and dismiss once resolved.")
	}
	if in.Upstream != nil {
		if n := len(in.Upstream.Upstreams); n == 1 {
			u := in.Upstream.Upstreams[0]
			add(SevInfo, "Single upstream resolver", fmt.Sprintf("All forwarded queries go to one upstream (%s).", u.IP), nil, "A second upstream improves resilience (at some cost to privacy consistency).")
		}
		for _, u := range in.Upstream.Upstreams {
			if u.Count >= 20 && u.Statistics.Response > 0.2 {
				add(SevWarning, "Slow upstream", fmt.Sprintf("Upstream %s averages %.0f ms per response.", u.IP, u.Statistics.Response*1000),
					[]string{fmt.Sprintf("%d queries", u.Count)}, "Consider a faster or closer resolver.")
			}
		}
	}
	if s := in.Summary; s != nil && s.Queries.Total >= 100 {
		total := float64(s.Queries.Total)
		if r := float64(s.Queries.Cached) / total; r < 0.05 {
			add(SevInfo, "Very low cache hit ratio", fmt.Sprintf("Only %.1f%% of queries were answered from cache.", r*100), nil, "Unusual; check cache-size and clients that bypass caching.")
		}
		if nx := float64(s.Queries.Replies["NXDOMAIN"]) / total; nx > 0.2 {
			add(SevWarning, "High NXDOMAIN rate", fmt.Sprintf("%.0f%% of replies were NXDOMAIN.", nx*100), nil, "A device may be querying nonexistent names (misconfigured search domains, malware, or stale hostnames).")
		}
		if sf := float64(s.Queries.Replies["SERVFAIL"]) / total; sf > 0.02 {
			add(SevWarning, "SERVFAIL replies", fmt.Sprintf("%.1f%% of replies were SERVFAIL.", sf*100), nil, "Check upstream reachability and DNSSEC.")
		}
	}
	if in.BogusDNSSEC > 0 {
		add(SevWarning, "DNSSEC validation failures", fmt.Sprintf("%d of %d sampled queries failed DNSSEC validation (BOGUS).", in.BogusDNSSEC, in.SampleSize), nil, "May indicate a misconfigured domain or tampering; check which domains.")
	}
	fs = append(fs, updateFindings(in.Version)...)
	fs = append(fs, BypassFindings(in.Devices, in.Now)...)
	SortFindings(fs)
	return fs
}

func nestedSlice(m map[string]any, path ...string) ([]float64, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = mm[p]
	}
	a, ok := cur.([]any)
	if !ok {
		return nil, false
	}
	out := make([]float64, 0, len(a))
	for _, v := range a {
		f, ok := v.(float64)
		if !ok {
			return nil, false
		}
		out = append(out, f)
	}
	return out, true
}

func updateFindings(v map[string]any) []Finding {
	if v == nil {
		return nil
	}
	if inner, ok := v["version"].(map[string]any); ok {
		v = inner
	}
	var fs []Finding
	for _, comp := range []string{"core", "web", "ftl"} {
		c, _ := v[comp].(map[string]any)
		local, _ := c["local"].(map[string]any)
		remote, _ := c["remote"].(map[string]any)
		lv, _ := local["version"].(string)
		rv, _ := remote["version"].(string)
		if lv != "" && rv != "" && lv != rv {
			fs = append(fs, Finding{SevInfo, "health", "Update available: " + strings.ToUpper(comp),
				fmt.Sprintf("%s is %s, latest is %s.", strings.ToUpper(comp), lv, rv), nil,
				"Update Pi-hole (for Docker: pull the new image) after reading the release notes."})
		}
	}
	return fs
}

// BypassFindings flags devices that are on the network but do not appear to use Pi-hole.
func BypassFindings(devs []pihole.Device, now time.Time) []Finding {
	var fs []Finding
	for _, d := range devs {
		var seen int64
		var label string
		for _, ip := range d.IPs {
			if ip.LastSeen > seen {
				seen = ip.LastSeen
			}
			if label == "" {
				label = ip.Name
				if label == "" {
					label = ip.IP
				}
			}
		}
		if seen == 0 || now.Sub(time.Unix(seen, 0)) > 7*24*time.Hour {
			continue // not recently on the network
		}
		if d.LastQuery == 0 || now.Sub(time.Unix(d.LastQuery, 0)) > 24*time.Hour {
			ev := []string{d.HWAddr, fmt.Sprintf("last seen %s", time.Unix(seen, 0).UTC().Format(time.RFC3339))}
			if d.LastQuery > 0 {
				ev = append(ev, fmt.Sprintf("last DNS query %s", time.Unix(d.LastQuery, 0).UTC().Format(time.RFC3339)))
			} else {
				ev = append(ev, "never queried Pi-hole")
			}
			fs = append(fs, Finding{SevInfo, "health", "Device may be bypassing Pi-hole",
				fmt.Sprintf("%s is on the network but has not queried Pi-hole in over 24h.", label), ev,
				"It may use hardcoded DNS, DNS-over-HTTPS, or be idle. Consider redirecting outbound port 53 at the router."})
		}
	}
	return fs
}
