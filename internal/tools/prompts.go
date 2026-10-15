package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func userPrompt(desc, text string) *mcp.GetPromptResult {
	return &mcp.GetPromptResult{Description: desc, Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}
}

func arg(r *mcp.GetPromptRequest, name, def string) string {
	if r != nil && r.Params != nil {
		if v := strings.TrimSpace(r.Params.Arguments[name]); v != "" {
			return v
		}
	}
	return def
}

const previewRule = "Never change Pi-hole without the user's explicit approval: change tools are two-step — call without confirm_token, show the user the preview (exact request, current vs new state, impact), and only call again with the token if they agree."

func registerPrompts(srv *mcp.Server, d *Deps) {
	instArg := &mcp.PromptArgument{Name: "instance", Description: "Pi-hole instance name (default: the first)"}
	srv.AddPrompt(&mcp.Prompt{Name: "weekly_report", Title: "Weekly DNS report",
		Description: "Summarize the last week of DNS activity, health and ad blocking.",
		Arguments:   []*mcp.PromptArgument{instArg, {Name: "period", Description: "Window, default 7d"}}},
		func(_ context.Context, r *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			inst, period := arg(r, "instance", ""), arg(r, "period", "7d")
			return userPrompt("Weekly DNS report", fmt.Sprintf(`Write a concise weekly report for my Pi-hole%s covering the last %s.
Use these tools: get_summary, top_clients (blocked=false and blocked=true), blocked_by_device, query_timeline, network_health, suggest_improvements.
Report: overall volume and block rate; the busiest devices; the most-blocked domains and which devices request them; any health findings; and the top 3 actionable suggestions.
Mention if any scan was truncated. %s Do not make any changes; only recommend.`, instSuffix(inst), period, previewRule)), nil
		})
	srv.AddPrompt(&mcp.Prompt{Name: "assess_blocklists", Title: "Assess block lists",
		Description: "Review installed block lists and recommend what to keep, remove or add.",
		Arguments:   []*mcp.PromptArgument{instArg}},
		func(_ context.Context, r *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return userPrompt("Assess block lists", fmt.Sprintf(`Assess the block lists on my Pi-hole%s.
Call list_blocklists, list_domain_rules and assess_blocklists. Explain each finding in plain language, rank them by importance, and for each say what you would do (remove, fix URL, update gravity, add a catalog list from the pihole://catalog/blocklists resource).
%s`, instSuffix(arg(r, "instance", "")), previewRule)), nil
		})
	srv.AddPrompt(&mcp.Prompt{Name: "investigate_device", Title: "Investigate a device",
		Description: "Profile one device's DNS behavior.",
		Arguments:   []*mcp.PromptArgument{{Name: "client", Description: "Device IP or name", Required: true}, instArg, {Name: "period", Description: "Window, default 7d"}}},
		func(_ context.Context, r *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			client := arg(r, "client", "")
			if client == "" {
				return nil, fmt.Errorf("client argument is required")
			}
			return userPrompt("Investigate "+client, fmt.Sprintf(`Investigate the device %q on my Pi-hole%s over the last %s.
Use client_activity, query_timeline (with client), top_domains (with client, both blocked and allowed) and explain_domain for anything suspicious.
Tell me what it talks to, when it is active, whether its block ratio is unusual, and whether anything looks like telemetry, malware or an ad-heavy app. %s`,
				client, instSuffix(arg(r, "instance", "")), arg(r, "period", "7d"), previewRule)), nil
		})
	srv.AddPrompt(&mcp.Prompt{Name: "improve_adblocking", Title: "Improve ad blocking",
		Description: "Find gaps in blocking and propose concrete changes.",
		Arguments:   []*mcp.PromptArgument{instArg}},
		func(_ context.Context, r *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return userPrompt("Improve ad blocking", fmt.Sprintf(`Help me improve ad blocking on my Pi-hole%s.
Call suggest_improvements, assess_blocklists and network_health. Propose a short prioritized plan of concrete changes (domain rules to add, lists to add/remove, devices to look at). For each proposed change name the tool you would use and its arguments, then wait for my go-ahead. %s`,
				instSuffix(arg(r, "instance", "")), previewRule)), nil
		})
}

func instSuffix(inst string) string {
	if inst == "" {
		return ""
	}
	return fmt.Sprintf(" (instance %q)", inst)
}
