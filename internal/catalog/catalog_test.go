package catalog

import "testing"

func TestEmbeddedCatalogValid(t *testing.T) {
	es, err := Load("")
	if err != nil || len(es) < 5 {
		t.Fatalf("load: %v (%d)", err, len(es))
	}
	seen := map[string]bool{}
	for _, e := range es {
		if e.ID == "" || e.URL == "" || e.Name == "" || e.Family == "" {
			t.Errorf("incomplete entry %+v", e)
		}
		if seen[e.ID] {
			t.Errorf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
	}
}
