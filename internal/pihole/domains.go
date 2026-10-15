package pihole

import (
	"context"
	"net/http"
	"net/url"
)

// Domains returns domain rules. typ is "allow"/"deny" and kind "exact"/"regex";
// an empty value lists all.
func (c *Client) Domains(ctx context.Context, typ, kind string) ([]DomainRule, error) {
	p := "/domains"
	if typ != "" {
		p += "/" + typ
		if kind != "" {
			p += "/" + kind
		}
	}
	return cached(c, "domains:"+p, func() ([]DomainRule, error) {
		var out struct {
			Domains []DomainRule `json:"domains"`
		}
		if err := c.get(ctx, p, nil, &out); err != nil {
			return nil, err
		}
		return out.Domains, nil
	})
}

// DomainBody is the writable part of a domain rule.
type DomainBody struct {
	Domain  string `json:"domain,omitempty"`
	Comment string `json:"comment,omitempty"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
}

// AddDomain adds an allow/deny rule.
func (c *Client) AddDomain(ctx context.Context, typ, kind string, b DomainBody) error {
	defer c.invalidate()
	return c.do(ctx, http.MethodPost, "/domains/"+typ+"/"+kind, nil, b, nil)
}

// DeleteDomain removes an allow/deny rule.
func (c *Client) DeleteDomain(ctx context.Context, typ, kind, domain string) error {
	defer c.invalidate()
	return c.do(ctx, http.MethodDelete, "/domains/"+typ+"/"+kind+"/"+url.PathEscape(domain), nil, nil, nil)
}
