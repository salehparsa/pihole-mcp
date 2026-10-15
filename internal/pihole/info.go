package pihole

import (
	"context"
	"fmt"
)

// Info fetches /info/<what> (system, sensors, ftl, host, database, version, metrics)
// as loosely typed JSON, because its shape varies by platform and release.
func (c *Client) Info(ctx context.Context, what string) (map[string]any, error) {
	var out map[string]any
	if err := c.get(ctx, "/info/"+what, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Messages returns FTL diagnostic messages.
func (c *Client) Messages(ctx context.Context) ([]Message, error) {
	var out struct {
		Messages []Message `json:"messages"`
	}
	if err := c.get(ctx, "/info/messages", nil, &out); err != nil {
		return nil, err
	}
	return out.Messages, nil
}

// FTLVersion extracts the FTL version string (e.g. "v6.7.1") from /info/version.
func (c *Client) FTLVersion(ctx context.Context) (string, error) {
	v, err := c.Info(ctx, "version")
	if err != nil {
		return "", err
	}
	if ver, ok := v["version"].(map[string]any); ok {
		v = ver
	}
	ftl, ok := v["ftl"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("pihole: /info/version has no ftl section")
	}
	if loc, ok := ftl["local"].(map[string]any); ok {
		if s, ok := loc["version"].(string); ok {
			return s, nil
		}
	}
	return "", fmt.Errorf("pihole: cannot determine FTL version")
}
