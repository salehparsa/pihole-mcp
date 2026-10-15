package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerResources(srv *mcp.Server, d *Deps) {
	srv.AddResource(&mcp.Resource{URI: "pihole://catalog/blocklists", Name: "blocklist-catalog", Title: "Well-known block lists",
		Description: "Curated catalog of well-known block lists (or the configured override file). Verify URLs before adding.", MIMEType: "application/json"},
		func(_ context.Context, r *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			b, err := json.MarshalIndent(d.Catalog, "", "  ")
			if err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: r.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
		})
	srv.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "pihole://{instance}/status", Name: "instance-status", Title: "Pi-hole status",
		Description: "Version, blocking state and 24h totals for one instance.", MIMEType: "application/json"},
		func(ctx context.Context, r *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			u, err := url.Parse(r.Params.URI)
			if err != nil || u.Scheme != "pihole" || !strings.HasSuffix(u.Path, "/status") {
				return nil, mcp.ResourceNotFoundError(r.Params.URI)
			}
			sum, _, err := d.getSummary(ctx, SummaryIn{Instance: u.Host})
			if err != nil {
				return nil, fmt.Errorf("status: %w", err)
			}
			_, c, _ := d.client(u.Host)
			status := map[string]any{"summary": sum}
			if v, err := c.FTLVersion(ctx); err == nil {
				status["ftl_version"] = v
			}
			if b, err := c.GetBlocking(ctx); err == nil {
				status["blocking"] = b.Blocking
			}
			b, _ := json.MarshalIndent(status, "", "  ")
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: r.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
		})
}
