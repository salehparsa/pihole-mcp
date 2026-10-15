package analysis

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// defaultAdPatterns are heuristics matched against a domain name. They are
// deliberately conservative hints, not a blocklist: a match only means "worth a
// human look".
var defaultAdPatterns = []string{
	`^ads?[0-9]*\.`, `^adserv(er|ice)s?[0-9]*\.`, `^adtrack`, `^tracker?s?[0-9]*\.`, `^track(ing)?\.`,
	`^telemetry\.`, `^metrics?\.`, `^analytics?\.`, `^pixel\.`, `^beacons?\.`, `^stats?\.`, `^collect\.`,
	`(^|\.)doubleclick\.`, `(^|\.)googlesyndication\.`, `(^|\.)googleadservices\.`, `(^|\.)adsystem\.`,
	`(^|\.)adnxs\.`, `(^|\.)scorecardresearch\.`, `(^|\.)outbrain\.`, `(^|\.)taboola\.`,
}

// AdMatcher flags domains that look like ad/tracking endpoints.
type AdMatcher struct{ res []*regexp.Regexp }

// NewAdMatcher compiles the defaults plus extra patterns. If the first line of
// the extra patterns is "# replace-defaults", only the extras are used.
func NewAdMatcher(extra string) (*AdMatcher, error) {
	patterns := append([]string(nil), defaultAdPatterns...)
	sc := bufio.NewScanner(strings.NewReader(extra))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first && line == "# replace-defaults" {
			patterns = nil
		}
		first = false
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	m := &AdMatcher{}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("ad pattern %q: %w", p, err)
		}
		m.res = append(m.res, re)
	}
	return m, nil
}

// Match returns the first pattern that matches domain.
func (m *AdMatcher) Match(domain string) (string, bool) {
	d := strings.ToLower(domain)
	for _, re := range m.res {
		if re.MatchString(d) {
			return re.String(), true
		}
	}
	return "", false
}
