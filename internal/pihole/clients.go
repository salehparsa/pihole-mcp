package pihole

import "context"

// ConfiguredClients returns the clients configured in Pi-hole.
func (c *Client) ConfiguredClients(ctx context.Context) ([]ClientEntry, error) {
	return cached(c, "clients", func() ([]ClientEntry, error) {
		var out struct {
			Clients []ClientEntry `json:"clients"`
		}
		if err := c.get(ctx, "/clients", nil, &out); err != nil {
			return nil, err
		}
		return out.Clients, nil
	})
}

// Groups returns the Pi-hole groups (loosely typed).
func (c *Client) Groups(ctx context.Context) ([]map[string]any, error) {
	return cached(c, "groups", func() ([]map[string]any, error) {
		var out struct {
			Groups []map[string]any `json:"groups"`
		}
		if err := c.get(ctx, "/groups", nil, &out); err != nil {
			return nil, err
		}
		return out.Groups, nil
	})
}
