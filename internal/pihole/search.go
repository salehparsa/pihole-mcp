package pihole

import (
	"context"
	"net/url"
	"strconv"
)

// Search shows which lists and rules match a domain.
func (c *Client) Search(ctx context.Context, domain string, limit int) (*SearchResult, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("N", strconv.Itoa(limit))
	}
	var out struct {
		Search SearchResult `json:"search"`
	}
	if err := c.get(ctx, "/search/"+url.PathEscape(domain), q, &out); err != nil {
		return nil, err
	}
	return &out.Search, nil
}
