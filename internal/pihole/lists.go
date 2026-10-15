package pihole

import (
	"context"
	"net/http"
	"net/url"
)

// Lists returns all adlists (cached briefly).
func (c *Client) Lists(ctx context.Context) ([]List, error) {
	return cached(c, "lists", func() ([]List, error) {
		var out struct {
			Lists []List `json:"lists"`
		}
		if err := c.get(ctx, "/lists", nil, &out); err != nil {
			return nil, err
		}
		return out.Lists, nil
	})
}

// ListBody is the writable part of a list.
type ListBody struct {
	Address string `json:"address,omitempty"`
	Comment string `json:"comment,omitempty"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
}

// AddList adds an adlist of the given type ("block" or "allow").
func (c *Client) AddList(ctx context.Context, typ string, b ListBody) error {
	defer c.invalidate()
	return c.do(ctx, http.MethodPost, "/lists", url.Values{"type": {typ}}, b, nil)
}

// UpdateList changes an existing adlist.
func (c *Client) UpdateList(ctx context.Context, typ, address string, b ListBody) error {
	defer c.invalidate()
	return c.do(ctx, http.MethodPut, "/lists/"+url.PathEscape(address), url.Values{"type": {typ}}, b, nil)
}

// DeleteList removes an adlist.
func (c *Client) DeleteList(ctx context.Context, typ, address string) error {
	defer c.invalidate()
	return c.do(ctx, http.MethodDelete, "/lists/"+url.PathEscape(address), url.Values{"type": {typ}}, nil, nil)
}
