package testutil

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestFixturesAreSanitized fails if testdata/ contains anything that looks like
// real network data or a secret: IPs outside the documentation ranges, MAC
// addresses outside the documentation block, or long token-shaped strings.
func TestFixturesAreSanitized(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	ip4 := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ip6 := regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
	mac := regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	token := regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
	docNets := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	inDoc := func(a netip.Addr) bool {
		for _, p := range docNets {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, f := range files {
		if filepath.Ext(f) != ".json" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, m := range ip4.FindAllString(s, -1) {
			a, err := netip.ParseAddr(m)
			if err != nil {
				continue // not an address (e.g. a version string)
			}
			if !inDoc(a) && a.String() != "0.0.0.0" {
				t.Errorf("%s: non-documentation IPv4 %s", filepath.Base(f), m)
			}
		}
		for _, m := range ip6.FindAllString(s, -1) {
			if a, err := netip.ParseAddr(m); err == nil && !inDoc(a) {
				t.Errorf("%s: non-documentation IPv6 %s", filepath.Base(f), m)
			}
		}
		for _, m := range mac.FindAllString(s, -1) {
			if !regexp.MustCompile(`(?i)^00[:-]00[:-]5e[:-]00[:-]53[:-][0-9a-f]{2}$`).MatchString(m) {
				t.Errorf("%s: MAC %s is outside the documentation block 00:00:5e:00:53:xx", filepath.Base(f), m)
			}
		}
		if m := token.FindString(s); m != "" {
			t.Errorf("%s: token-shaped string %q", filepath.Base(f), m)
		}
	}
}
