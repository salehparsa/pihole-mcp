// Package fakepihole is an in-memory Pi-hole v6 API for tests, served from the
// sanitized fixtures in testdata/. It never talks to a real Pi-hole.
package fakepihole

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Now is the fixed "current time" matching the fixtures (see scripts/gen-testdata.py).
const Now int64 = 1760000000

// Password is the app password the fake accepts.
const Password = "test-app-password"

// Server is a fake Pi-hole.
type Server struct {
	*httptest.Server

	mu        sync.Mutex
	sessions  map[string]bool
	nextSID   int
	logins    int
	logouts   int
	calls     []string
	data      map[string]json.RawMessage
	queries   []map[string]any
	lists     []map[string]any
	domains   []map[string]any
	blocking  map[string]any
	gravity   map[string][]int // domain -> list ids that block it
	failPaths map[string]int   // path -> status to return
	extraDevs int              // synthetic devices appended to the fixtures
}

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata")
}

func load(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdataDir(), name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
}

// New starts a fake Pi-hole; it is closed with the test.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{sessions: map[string]bool{}, data: map[string]json.RawMessage{}, failPaths: map[string]int{}}
	for _, n := range []string{"summary", "upstreams", "history", "clients", "devices",
		"info_version", "info_system", "info_sensors", "info_host", "info_database", "info_ftl", "info_messages"} {
		var raw json.RawMessage
		load(t, n+".json", &raw)
		s.data[n] = raw
	}
	var qf struct{ Queries []map[string]any }
	load(t, "queries.json", &qf)
	s.queries = qf.Queries
	var lf struct{ Lists []map[string]any }
	load(t, "lists.json", &lf)
	s.lists = lf.Lists
	var df struct{ Domains []map[string]any }
	load(t, "domains.json", &df)
	s.domains = df.Domains
	load(t, "blocking.json", &s.blocking)
	s.gravity = map[string][]int{
		"ads.example-ads.com":            {1},
		"pixel.example-track.net":        {1, 5},
		"telemetry.smart-fridge.example": {1},
		"adserver.example.org":           {1},
		"tracker.example-tracker.net":    {5},
		"ads.example-tracker.net":        {1},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Calls returns every request seen ("METHOD /path?query"), excluding auth.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// WriteCalls returns only the mutating calls.
func (s *Server) WriteCalls() []string {
	var out []string
	for _, c := range s.Calls() {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

// Logins returns the number of POST /api/auth calls.
func (s *Server) Logins() int { s.mu.Lock(); defer s.mu.Unlock(); return s.logins }

// Logouts returns the number of DELETE /api/auth calls.
func (s *Server) Logouts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.logouts }

// ExpireSessions invalidates every session so the next call returns 401.
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}

// FailPath makes requests to the API path (e.g. "/stats/summary") return status.
func (s *Server) FailPath(path string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPaths[path] = status
}

// SetExtraDevices appends n synthetic devices (documentation addresses) to the device table.
func (s *Server) SetExtraDevices(n int) { s.mu.Lock(); s.extraDevs = n; s.mu.Unlock() }

// SetList replaces fixture lists (for assessment tests).
func (s *Server) SetLists(l []map[string]any) { s.mu.Lock(); s.lists = l; s.mu.Unlock() }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, key, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"key": key, "message": msg, "hint": nil}})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if path == "/auth" {
		s.auth(w, r)
		return
	}
	sid := r.Header.Get("X-FTL-SID")
	s.mu.Lock()
	ok := s.sessions[sid]
	if ok {
		q := r.URL.RawQuery
		entry := r.Method + " " + r.URL.Path
		if q != "" {
			entry += "?" + q
		}
		s.calls = append(s.calls, entry)
	}
	fail := s.failPaths[path]
	s.mu.Unlock()
	if !ok {
		apiErr(w, http.StatusUnauthorized, "unauthorized", "Unauthorized")
		return
	}
	if fail != 0 {
		apiErr(w, fail, "forced", "forced failure")
		return
	}
	s.route(w, r, path)
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPost:
		var b struct{ Password string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Password != Password {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"session": map[string]any{"valid": false, "sid": nil, "validity": -1, "message": "password incorrect"}})
			return
		}
		s.nextSID++
		s.logins++
		sid := fmt.Sprintf("sid-%d", s.nextSID)
		s.sessions[sid] = true
		writeJSON(w, 200, map[string]any{"session": map[string]any{"valid": true, "totp": false, "sid": sid, "csrf": "x", "validity": 300, "message": "success"}})
	case http.MethodDelete:
		delete(s.sessions, r.Header.Get("X-FTL-SID"))
		s.logouts++
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) raw(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.data[name])
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, path string) {
	q := r.URL.Query()
	switch {
	case path == "/stats/summary":
		s.raw(w, "summary")
	case path == "/stats/database/summary":
		s.dbSummary(w, q)
	case path == "/stats/upstreams" || path == "/stats/database/upstreams":
		s.raw(w, "upstreams")
	case path == "/history" || path == "/history/database":
		s.raw(w, "history")
	case path == "/stats/top_domains" || path == "/stats/database/top_domains":
		s.topDomains(w, q)
	case path == "/stats/top_clients" || path == "/stats/database/top_clients":
		s.topClients(w, q)
	case path == "/history/clients" || path == "/history/database/clients":
		s.clientHistory(w)
	case path == "/queries":
		s.queriesH(w, q)
	case path == "/clients":
		s.raw(w, "clients")
	case path == "/groups":
		writeJSON(w, 200, map[string]any{"groups": []map[string]any{{"name": "Default", "id": 0, "enabled": true}}})
	case path == "/network/devices":
		s.devices(w, q)
	case path == "/lists" || strings.HasPrefix(path, "/lists/"):
		s.listsH(w, r, path)
	case strings.HasPrefix(path, "/domains"):
		s.domainsH(w, r, path)
	case strings.HasPrefix(path, "/search/"):
		s.search(w, strings.TrimPrefix(path, "/search/"))
	case path == "/info/version":
		s.raw(w, "info_version")
	case path == "/info/system":
		s.raw(w, "info_system")
	case path == "/info/sensors":
		s.raw(w, "info_sensors")
	case path == "/info/host":
		s.raw(w, "info_host")
	case path == "/info/database":
		s.raw(w, "info_database")
	case path == "/info/ftl":
		s.raw(w, "info_ftl")
	case path == "/info/messages":
		s.raw(w, "info_messages")
	case path == "/dns/blocking":
		s.blockingH(w, r)
	case path == "/action/gravity" && r.Method == http.MethodPost:
		w.Header().Set("Content-Type", "text/plain")
		for _, l := range []string{"[i] Neutrino emissions detected...", "[✓] Pulling blocklist source list into range", "[i] Number of gravity domains: 176000 (170000 unique domains)", "[✓] Done."} {
			_, _ = fmt.Fprintln(w, l)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	default:
		apiErr(w, http.StatusNotFound, "not_found", "no such endpoint: "+path)
	}
}

func isBlockedStatus(s string) bool {
	switch s {
	case "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN":
		return true
	}
	return strings.HasPrefix(s, "EXTERNAL_BLOCKED")
}

func (s *Server) topDomains(w http.ResponseWriter, q url.Values) {
	wantBlocked := q.Get("blocked") == "true"
	counts := map[string]int{}
	total, blocked := 0, 0
	for _, qu := range s.queries {
		total++
		b := isBlockedStatus(qu["status"].(string))
		if b {
			blocked++
		}
		if b == wantBlocked {
			counts[qu["domain"].(string)]++
		}
	}
	n, _ := strconv.Atoi(q.Get("count"))
	if n == 0 {
		n = 10
	}
	rows := rank(counts, n, func(k string, c int) any { return map[string]any{"domain": k, "count": c} })
	writeJSON(w, 200, map[string]any{"domains": rows, "total_queries": total, "blocked_queries": blocked})
}

func (s *Server) topClients(w http.ResponseWriter, q url.Values) {
	wantBlocked := q.Get("blocked") == "true"
	counts := map[string]int{}
	names := map[string]string{}
	for _, qu := range s.queries {
		c := qu["client"].(map[string]any)
		ip := c["ip"].(string)
		names[ip] = c["name"].(string)
		if !wantBlocked || isBlockedStatus(qu["status"].(string)) {
			counts[ip]++
		}
	}
	n, _ := strconv.Atoi(q.Get("count"))
	if n == 0 {
		n = 10
	}
	rows := rank(counts, n, func(k string, c int) any { return map[string]any{"ip": k, "name": names[k], "count": c} })
	writeJSON(w, 200, map[string]any{"clients": rows, "total_queries": len(s.queries), "blocked_queries": 0})
}

func rank(counts map[string]int, n int, mk func(string, int) any) []any {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, mk(k, counts[k]))
	}
	return out
}

func (s *Server) clientHistory(w http.ResponseWriter) {
	clients := map[string]any{}
	data := map[string]int{}
	for _, qu := range s.queries {
		c := qu["client"].(map[string]any)
		ip := c["ip"].(string)
		clients[ip] = map[string]any{"name": c["name"], "total": 0}
		data[ip]++
	}
	writeJSON(w, 200, map[string]any{"clients": clients, "history": []any{map[string]any{"timestamp": Now - 3600, "data": data}}})
}

func (s *Server) queriesH(w http.ResponseWriter, q url.Values) {
	from, _ := strconv.ParseFloat(q.Get("from"), 64)
	until, _ := strconv.ParseFloat(q.Get("until"), 64)
	length, _ := strconv.Atoi(q.Get("length"))
	if length <= 0 {
		length = 100
	}
	cursor, _ := strconv.Atoi(q.Get("cursor"))
	var matched []map[string]any
	for _, qu := range s.queries {
		t := qu["time"].(float64)
		c := qu["client"].(map[string]any)
		switch {
		case from > 0 && t < from, until > 0 && t > until:
			continue
		case q.Get("domain") != "" && !strings.Contains(qu["domain"].(string), q.Get("domain")):
			continue
		case q.Get("client_ip") != "" && c["ip"] != q.Get("client_ip"):
			continue
		case q.Get("client_name") != "" && c["name"] != q.Get("client_name"):
			continue
		case q.Get("status") != "" && qu["status"] != q.Get("status"):
			continue
		case q.Get("type") != "" && qu["type"] != q.Get("type"):
			continue
		case q.Get("dnssec") != "" && qu["dnssec"] != q.Get("dnssec"):
			continue
		}
		matched = append(matched, qu)
	}
	var page []map[string]any
	for _, qu := range matched {
		id := int(qu["id"].(float64))
		if cursor > 0 && id > cursor {
			continue
		}
		page = append(page, qu)
	}
	next := 0
	if len(page) > length {
		page = page[:length]
	}
	if len(page) > 0 {
		next = int(page[len(page)-1]["id"].(float64)) // intentionally inclusive: clients must de-duplicate
	}
	writeJSON(w, 200, map[string]any{"queries": page, "cursor": next, "recordsTotal": len(s.queries), "recordsFiltered": len(matched)})
}

func (s *Server) listsH(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"lists": s.lists})
	case http.MethodPost:
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		b["type"] = r.URL.Query().Get("type")
		b["id"] = len(s.lists) + 100
		b["number"], b["status"], b["invalid_domains"], b["date_updated"] = 0, 0, 0, 0
		s.lists = append(s.lists, b)
		writeJSON(w, 201, map[string]any{"lists": []any{b}, "processed": map[string]any{"success": []any{}, "errors": []any{}}})
	case http.MethodPut, http.MethodDelete:
		addr, _ := url.PathUnescape(strings.TrimPrefix(path, "/lists/"))
		for i, l := range s.lists {
			if l["address"] != addr {
				continue
			}
			if r.Method == http.MethodDelete {
				s.lists = append(s.lists[:i], s.lists[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			for k, v := range b {
				if k != "address" {
					l[k] = v
				}
			}
			writeJSON(w, 200, map[string]any{"lists": []any{l}})
			return
		}
		apiErr(w, 404, "not_found", "Item not found")
	}
}

func (s *Server) domainsH(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/domains"), "/"), "/")
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	typ, kind, dom := parts[0], parts[1], parts[2]
	switch r.Method {
	case http.MethodGet:
		out := []map[string]any{}
		for _, d := range s.domains {
			if (typ == "" || d["type"] == typ) && (kind == "" || d["kind"] == kind) {
				out = append(out, d)
			}
		}
		writeJSON(w, 200, map[string]any{"domains": out})
	case http.MethodPost:
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		b["type"], b["kind"], b["id"] = typ, kind, len(s.domains)+100
		s.domains = append(s.domains, b)
		writeJSON(w, 201, map[string]any{"domains": []any{b}})
	case http.MethodDelete:
		d, _ := url.PathUnescape(dom)
		for i, x := range s.domains {
			if x["domain"] == d && x["type"] == typ && x["kind"] == kind {
				s.domains = append(s.domains[:i], s.domains[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		apiErr(w, 404, "not_found", "Item not found")
	}
}

func (s *Server) search(w http.ResponseWriter, dom string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dom, _ = url.PathUnescape(dom)
	var rules, gravity []map[string]any
	for _, d := range s.domains {
		if d["kind"] == "exact" && d["domain"] == dom {
			rules = append(rules, d)
		}
	}
	for _, id := range s.gravity[dom] {
		for _, l := range s.lists {
			if int(l["id"].(float64)) == id {
				gravity = append(gravity, map[string]any{"address": l["address"], "comment": l["comment"], "enabled": l["enabled"], "id": id, "type": l["type"], "domain": dom})
			}
		}
	}
	if rules == nil {
		rules = []map[string]any{}
	}
	if gravity == nil {
		gravity = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"search": map[string]any{"domains": rules, "gravity": gravity}})
}

func (s *Server) blockingH(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodPost {
		var b struct {
			Blocking bool
			Timer    *float64
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		s.blocking = map[string]any{"blocking": map[bool]string{true: "enabled", false: "disabled"}[b.Blocking], "timer": b.Timer}
	}
	writeJSON(w, 200, s.blocking)
}

// dbSummary mimics /stats/database/summary, whose shape differs from the live summary.
func (s *Server) dbSummary(w http.ResponseWriter, q url.Values) {
	from, _ := strconv.ParseFloat(q.Get("from"), 64)
	until, _ := strconv.ParseFloat(q.Get("until"), 64)
	total, blocked := 0, 0
	clients := map[string]bool{}
	for _, qu := range s.queries {
		t := qu["time"].(float64)
		if (from > 0 && t < from) || (until > 0 && t > until) {
			continue
		}
		total++
		if isBlockedStatus(qu["status"].(string)) {
			blocked++
		}
		clients[qu["client"].(map[string]any)["ip"].(string)] = true
	}
	pct := 0.0
	if total > 0 {
		pct = float64(blocked) / float64(total) * 100
	}
	writeJSON(w, 200, map[string]any{"sum_queries": total, "sum_blocked": blocked, "percent_blocked": pct, "total_clients": len(clients)})
}

// devices mimics /network/devices, which returns only 10 devices unless max_devices is given.
func (s *Server) devices(w http.ResponseWriter, q url.Values) {
	var doc struct {
		Devices []map[string]any `json:"devices"`
	}
	_ = json.Unmarshal(s.data["devices"], &doc)
	s.mu.Lock()
	for i := 0; i < s.extraDevs; i++ {
		doc.Devices = append(doc.Devices, map[string]any{
			"id": 100 + i, "hwaddr": fmt.Sprintf("00:00:5e:00:53:%02x", 0x80+i%0x70), "interface": "eth0", "firstSeen": Now - 1000,
			"lastQuery": Now - 60, "numQueries": 1, "macVendor": "Example Devices",
			"ips": []map[string]any{{"ip": fmt.Sprintf("192.0.2.%d", 100+i%100), "name": fmt.Sprintf("extra-%d", i), "lastSeen": Now - 60, "nameUpdated": Now - 60}},
		})
	}
	s.mu.Unlock()
	max := 10
	if v, err := strconv.Atoi(q.Get("max_devices")); err == nil && v > 0 {
		max = v
	}
	if len(doc.Devices) > max {
		doc.Devices = doc.Devices[:max]
	}
	writeJSON(w, 200, doc)
}
