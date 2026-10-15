// Package catalog embeds a curated set of well-known block lists, with an
// optional override file. Catalog URLs are suggestions: verify before adding.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed blocklists.json
var embedded []byte

// Entry describes one well-known block list.
type Entry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Family      string `json:"family"`   // lists of the same family overlap heavily
	Category    string `json:"category"` // general | security | ...
	Level       int    `json:"level"`    // 1 gentle .. 3 aggressive
	Description string `json:"description"`
	Notes       string `json:"notes"`
}

// Load returns the embedded catalog, or the override file when path is set.
func Load(path string) ([]Entry, error) {
	data := embedded
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("catalog: %w", err)
		}
		data = b
	}
	var out []Entry
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return out, nil
}

// NormalizeURL makes list addresses comparable.
func NormalizeURL(u string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(u), "/"))
}
