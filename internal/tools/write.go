package tools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/pihole"
)

// writeArgs is implemented by the input of every change tool.
type writeArgs interface {
	instanceName() string
	token() string
	// canonical returns the arguments the confirm token is bound to
	// (without the instance and the token itself).
	canonical() any
}

// WriteOut is the output of every change tool.
type WriteOut struct {
	Instance     string   `json:"instance"`
	Tool         string   `json:"tool"`
	Mode         string   `json:"mode" jsonschema:"preview (nothing changed) or applied"`
	Action       string   `json:"action" jsonschema:"what the change does, in words"`
	Request      string   `json:"request" jsonschema:"the exact Pi-hole API request that will be / was sent"`
	Current      string   `json:"current" jsonschema:"state before the change"`
	Proposed     string   `json:"proposed" jsonschema:"state after the change"`
	Impact       string   `json:"impact,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	ConfirmToken string   `json:"confirm_token,omitempty" jsonschema:"pass this back as confirm_token (same arguments) to execute the change"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Result       string   `json:"result,omitempty"`
	Output       []string `json:"output,omitempty" jsonschema:"tail of streamed output (update_gravity)"`
}

// plan is what a change tool computed for a call: a preview plus how to apply it.
type plan struct {
	action, request, current, proposed, impact string
	warnings                                   []string
	apply                                      func(ctx context.Context, progress func(string)) (result string, output []string, err error)
}

type writeSpec[In writeArgs] struct {
	name, title, desc       string
	destructive, idempotent bool
	plan                    func(ctx context.Context, d *Deps, c *pihole.Client, in In) (*plan, error)
}

func (d *Deps) writeAllowed(tool string) bool {
	if !d.Cfg.Writes.Enabled {
		return false
	}
	al := d.Cfg.Writes.AllowedTools
	if len(al) == 0 {
		return true
	}
	for _, t := range al {
		if t == tool {
			return true
		}
	}
	return false
}

func addWrite[In writeArgs](srv *mcp.Server, d *Deps, spec writeSpec[In]) {
	if !d.writeAllowed(spec.name) {
		return
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name: spec.name, Title: spec.title,
		Description: spec.desc + " TWO-STEP: call without confirm_token to get a preview and a token (nothing changes); show the preview to the user and call again with the same arguments plus confirm_token only after they agree.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(spec.destructive), IdempotentHint: spec.idempotent, OpenWorldHint: ptr(false), Title: spec.title},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, WriteOut, error) {
		out, err := runWrite(ctx, d, req, spec, in)
		if err != nil {
			return nil, WriteOut{}, err
		}
		return textResult(out.Action+" — "+out.Mode+".", out), out, nil
	})
}

func runWrite[In writeArgs](ctx context.Context, d *Deps, req *mcp.CallToolRequest, spec writeSpec[In], in In) (WriteOut, error) {
	if !d.writeAllowed(spec.name) { // defense in depth; unregistered tools should never get here
		return WriteOut{}, errf("%s is disabled by configuration (writes.enabled / writes.allowed_tools)", spec.name)
	}
	name, c, err := d.client(in.instanceName())
	if err != nil {
		return WriteOut{}, err
	}
	p, err := spec.plan(ctx, d, c, in)
	if err != nil {
		return WriteOut{}, err
	}
	out := WriteOut{Instance: name, Tool: spec.name, Action: p.action, Request: p.request, Current: p.current, Proposed: p.proposed, Impact: p.impact, Warnings: p.warnings}
	session := ""
	if req != nil && req.Session != nil {
		session = req.Session.ID()
	}
	if in.token() == "" {
		tok, exp, err := d.Confirm.Issue(name, spec.name, in.canonical())
		if err != nil {
			return WriteOut{}, err
		}
		out.Mode, out.ConfirmToken, out.ExpiresAt = "preview", tok, d.ts(exp)
		out.Result = "NOT APPLIED. Nothing was changed. Repeat the call with the same arguments and confirm_token to apply."
		d.log().Debug("change previewed", "instance", name, "tool", spec.name, "session", session)
		return out, nil
	}
	if err := d.Confirm.Verify(in.token(), name, spec.name, in.canonical()); err != nil {
		d.log().Warn("change rejected", "instance", name, "tool", spec.name, "session", session, "reason", err.Error())
		return WriteOut{}, err
	}
	n := 0
	progress := func(line string) {
		n++
		if req == nil || req.Session == nil || req.Params == nil {
			return
		}
		if tok := req.Params.GetProgressToken(); tok != nil {
			_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: float64(n), Message: line})
		}
	}
	result, lines, err := p.apply(ctx, progress)
	if err != nil {
		d.log().Error("change failed", "event", "audit", "instance", name, "tool", spec.name, "args", mustJSON(in.canonical()), "session", session, "error", err.Error())
		return WriteOut{}, fmt.Errorf("%s failed: %w", spec.name, err)
	}
	d.log().Info("change applied", "event", "audit", "instance", name, "tool", spec.name, "args", mustJSON(in.canonical()), "result", result, "session", session)
	out.Mode, out.Result, out.Output = "applied", result, lines
	return out, nil
}

func registerWrites(srv *mcp.Server, d *Deps) {
	addWrite(srv, d, writeSpec[AddBlocklistIn]{name: "add_blocklist", title: "Add block list", idempotent: false,
		desc: "Subscribe to a new block list URL. Run update_gravity afterwards to download it.", plan: planAddBlocklist})
	addWrite(srv, d, writeSpec[RemoveBlocklistIn]{name: "remove_blocklist", title: "Remove block list", destructive: true, idempotent: true,
		desc: "Unsubscribe from a block list.", plan: planRemoveBlocklist})
	addWrite(srv, d, writeSpec[SetBlocklistEnabledIn]{name: "set_blocklist_enabled", title: "Enable/disable block list", idempotent: true,
		desc: "Enable or disable an installed block list without removing it.", plan: planSetBlocklistEnabled})
	addWrite(srv, d, writeSpec[AddDomainRuleIn]{name: "add_domain_rule", title: "Add allow/deny rule", idempotent: false,
		desc: "Add an exact or regex allow/deny rule. The preview estimates how many recent queries it would affect.", plan: planAddDomainRule})
	addWrite(srv, d, writeSpec[RemoveDomainRuleIn]{name: "remove_domain_rule", title: "Remove allow/deny rule", destructive: true, idempotent: true,
		desc: "Delete an allow/deny rule.", plan: planRemoveDomainRule})
	addWrite(srv, d, writeSpec[UpdateGravityIn]{name: "update_gravity", title: "Update gravity", idempotent: true,
		desc: "Download all block lists and rebuild the gravity database. Can take minutes and is CPU/IO heavy on small devices; streams progress.", plan: planUpdateGravity})
	addWrite(srv, d, writeSpec[SetBlockingIn]{name: "set_blocking", title: "Turn blocking on/off", idempotent: true, destructive: true,
		desc: "Enable or disable DNS blocking globally, optionally for a limited time.", plan: planSetBlocking})
}

// ---- block lists

// AddBlocklistIn is the input of add_blocklist.
type AddBlocklistIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Address      string `json:"address" jsonschema:"List URL (http or https)"`
	Type         string `json:"type,omitempty" jsonschema:"block (default) or allow"`
	Comment      string `json:"comment,omitempty" jsonschema:"Comment stored with the list"`
	Enabled      *bool  `json:"enabled,omitempty" jsonschema:"Enable immediately (default true)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a AddBlocklistIn) instanceName() string { return a.Instance }
func (a AddBlocklistIn) token() string        { return a.ConfirmToken }
func (a AddBlocklistIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func validListURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errf("address %q must be an http(s) URL", s)
	}
	return s, nil
}

func findList(ls []pihole.List, addr string) *pihole.List {
	want := catalog.NormalizeURL(addr)
	for i := range ls {
		if catalog.NormalizeURL(ls[i].Address) == want {
			return &ls[i]
		}
	}
	return nil
}

func planAddBlocklist(ctx context.Context, d *Deps, c *pihole.Client, in AddBlocklistIn) (*plan, error) {
	addr, err := validListURL(in.Address)
	if err != nil {
		return nil, err
	}
	typ := in.Type
	if typ == "" {
		typ = "block"
	}
	if typ != "block" && typ != "allow" {
		return nil, errf("type must be block or allow")
	}
	enabled := in.Enabled == nil || *in.Enabled
	ls, err := c.Lists(ctx)
	if err != nil {
		return nil, err
	}
	if l := findList(ls, addr); l != nil {
		return nil, errf("this list is already installed (id %d, enabled=%v); use set_blocklist_enabled instead", l.ID, l.Enabled)
	}
	body := pihole.ListBody{Address: addr, Comment: in.Comment, Groups: []int{0}, Enabled: enabled}
	p := &plan{
		action:   fmt.Sprintf("Add %s list %s", typ, addr),
		request:  fmt.Sprintf("POST /api/lists?type=%s %s", typ, mustJSON(body)),
		current:  fmt.Sprintf("%d lists installed; this one is not among them", len(ls)),
		proposed: fmt.Sprintf("List added (enabled=%v, group 0); its domains are unknown until gravity runs", enabled),
		impact:   "No blocking change until the next gravity update (run update_gravity). Domain count and download status will be visible in list_blocklists afterwards.",
	}
	for _, e := range d.Catalog {
		if catalog.NormalizeURL(e.URL) == catalog.NormalizeURL(addr) {
			p.warnings = append(p.warnings, "Known list: "+e.Name+". "+e.Notes)
		}
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		if err := c.AddList(ctx, typ, body); err != nil {
			return "", nil, err
		}
		return "List added. Run update_gravity to download it.", nil, nil
	}
	return p, nil
}

// RemoveBlocklistIn is the input of remove_blocklist.
type RemoveBlocklistIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Address      string `json:"address" jsonschema:"URL of the installed list to remove"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a RemoveBlocklistIn) instanceName() string { return a.Instance }
func (a RemoveBlocklistIn) token() string        { return a.ConfirmToken }
func (a RemoveBlocklistIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func planRemoveBlocklist(ctx context.Context, d *Deps, c *pihole.Client, in RemoveBlocklistIn) (*plan, error) {
	ls, err := c.Lists(ctx)
	if err != nil {
		return nil, err
	}
	l := findList(ls, in.Address)
	if l == nil {
		return nil, errf("no installed list matches %q (see list_blocklists)", in.Address)
	}
	typ := l.Type
	if typ == "" {
		typ = "block"
	}
	addr := l.Address
	p := &plan{
		action:   fmt.Sprintf("Remove %s list #%d %s", typ, l.ID, addr),
		request:  fmt.Sprintf("DELETE /api/lists/%s?type=%s", url.PathEscape(addr), typ),
		current:  fmt.Sprintf("Installed, enabled=%v, %d domains, status %s", l.Enabled, l.Number, listStatus(l.Status)),
		proposed: "List removed",
		impact:   fmt.Sprintf("Up to %d domains stop being blocked (those not also on another list). Takes effect after the next gravity update.", l.Number),
	}
	if !l.Enabled {
		p.impact = "The list is already disabled, so blocking does not change."
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		if err := c.DeleteList(ctx, typ, addr); err != nil {
			return "", nil, err
		}
		return "List removed.", nil, nil
	}
	return p, nil
}

// SetBlocklistEnabledIn is the input of set_blocklist_enabled.
type SetBlocklistEnabledIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Address      string `json:"address" jsonschema:"URL of the installed list"`
	Enabled      bool   `json:"enabled" jsonschema:"true to enable, false to disable"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a SetBlocklistEnabledIn) instanceName() string { return a.Instance }
func (a SetBlocklistEnabledIn) token() string        { return a.ConfirmToken }
func (a SetBlocklistEnabledIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func planSetBlocklistEnabled(ctx context.Context, d *Deps, c *pihole.Client, in SetBlocklistEnabledIn) (*plan, error) {
	ls, err := c.Lists(ctx)
	if err != nil {
		return nil, err
	}
	l := findList(ls, in.Address)
	if l == nil {
		return nil, errf("no installed list matches %q (see list_blocklists)", in.Address)
	}
	if l.Enabled == in.Enabled {
		return nil, errf("list #%d is already enabled=%v; nothing to do", l.ID, l.Enabled)
	}
	typ := l.Type
	if typ == "" {
		typ = "block"
	}
	body := pihole.ListBody{Comment: l.Comment, Groups: l.Groups, Enabled: in.Enabled}
	addr := l.Address
	verb := map[bool]string{true: "Enable", false: "Disable"}[in.Enabled]
	p := &plan{
		action:   fmt.Sprintf("%s list #%d %s", verb, l.ID, addr),
		request:  fmt.Sprintf("PUT /api/lists/%s?type=%s %s", url.PathEscape(addr), typ, mustJSON(body)),
		current:  fmt.Sprintf("enabled=%v", l.Enabled),
		proposed: fmt.Sprintf("enabled=%v", in.Enabled),
		impact:   fmt.Sprintf("%d domains %s after the next gravity update.", l.Number, map[bool]string{true: "start being blocked", false: "stop being blocked"}[in.Enabled]),
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		if err := c.UpdateList(ctx, typ, addr, body); err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("List enabled=%v. Run update_gravity to apply.", in.Enabled), nil, nil
	}
	return p, nil
}

// ---- domain rules

// AddDomainRuleIn is the input of add_domain_rule.
type AddDomainRuleIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Domain       string `json:"domain" jsonschema:"Domain (exact) or regular expression"`
	Type         string `json:"type" jsonschema:"allow or deny"`
	Kind         string `json:"kind,omitempty" jsonschema:"exact (default) or regex"`
	Comment      string `json:"comment,omitempty" jsonschema:"Comment stored with the rule"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a AddDomainRuleIn) instanceName() string { return a.Instance }
func (a AddDomainRuleIn) token() string        { return a.ConfirmToken }
func (a AddDomainRuleIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

var hostnameRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.\-]*[a-z0-9_])?$`)

// broadProbe domains: a regex that matches all of them is refused as over-broad.
var broadProbe = []string{"example.com", "ads.tracker.net", "a.b.c.example.org", "xn--mnchen-3ya.de"}

func normalizeRule(domain, kind string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", errf("domain is required")
	}
	if kind == "regex" {
		re, err := regexp.Compile(domain)
		if err != nil {
			return domain, nil // Pi-hole's engine differs from Go's; Pi-hole will validate it
		}
		hits := 0
		for _, p := range broadProbe {
			if re.MatchString(p) {
				hits++
			}
		}
		if hits == len(broadProbe) {
			return "", errf("refusing regex %q: it matches every probe domain (over-broad); anchor and narrow it", domain)
		}
		return domain, nil
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !hostnameRE.MatchString(domain) {
		return "", errf("%q is not a valid host name for an exact rule (use kind=regex for patterns)", domain)
	}
	return domain, nil
}

func planAddDomainRule(ctx context.Context, d *Deps, c *pihole.Client, in AddDomainRuleIn) (*plan, error) {
	kind := in.Kind
	if kind == "" {
		kind = "exact"
	}
	if in.Type != "allow" && in.Type != "deny" {
		return nil, errf("type must be allow or deny")
	}
	if kind != "exact" && kind != "regex" {
		return nil, errf("kind must be exact or regex")
	}
	dom, err := normalizeRule(in.Domain, kind)
	if err != nil {
		return nil, err
	}
	rules, err := c.Domains(ctx, "", "")
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.Domain == dom && r.Type == in.Type && r.Kind == kind {
			return nil, errf("an identical %s %s rule already exists (id %d, enabled=%v)", in.Type, kind, r.ID, r.Enabled)
		}
	}
	body := pihole.DomainBody{Domain: dom, Comment: in.Comment, Groups: []int{0}, Enabled: true}
	imp, err := d.ruleImpact(ctx, c, in.Type, kind, dom, true)
	p := &plan{
		action:   fmt.Sprintf("Add %s %s rule %s", in.Type, kind, dom),
		request:  fmt.Sprintf("POST /api/domains/%s/%s %s", in.Type, kind, mustJSON(body)),
		current:  "No such rule",
		proposed: fmt.Sprintf("%s %s rule active for group 0", in.Type, kind),
		impact:   imp,
	}
	if err != nil {
		p.impact = "Could not estimate impact: " + err.Error()
	}
	if kind == "exact" && in.Type == "deny" {
		p.warnings = append(p.warnings, "An exact deny rule does not cover subdomains; use kind=regex for that.")
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		if err := c.AddDomain(ctx, in.Type, kind, body); err != nil {
			return "", nil, err
		}
		return "Rule added; it takes effect immediately (no gravity update needed).", nil, nil
	}
	return p, nil
}

// RemoveDomainRuleIn is the input of remove_domain_rule.
type RemoveDomainRuleIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Domain       string `json:"domain" jsonschema:"Domain or regex exactly as stored"`
	Type         string `json:"type" jsonschema:"allow or deny"`
	Kind         string `json:"kind,omitempty" jsonschema:"exact (default) or regex"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a RemoveDomainRuleIn) instanceName() string { return a.Instance }
func (a RemoveDomainRuleIn) token() string        { return a.ConfirmToken }
func (a RemoveDomainRuleIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func planRemoveDomainRule(ctx context.Context, d *Deps, c *pihole.Client, in RemoveDomainRuleIn) (*plan, error) {
	kind := in.Kind
	if kind == "" {
		kind = "exact"
	}
	if in.Type != "allow" && in.Type != "deny" {
		return nil, errf("type must be allow or deny")
	}
	if kind != "exact" && kind != "regex" {
		return nil, errf("kind must be exact or regex")
	}
	dom := strings.TrimSpace(in.Domain)
	if kind == "exact" {
		dom = strings.ToLower(dom)
	}
	rules, err := c.Domains(ctx, in.Type, kind)
	if err != nil {
		return nil, err
	}
	var found *pihole.DomainRule
	for i := range rules {
		if rules[i].Domain == dom {
			found = &rules[i]
		}
	}
	if found == nil {
		return nil, errf("no %s %s rule %q exists (see list_domain_rules)", in.Type, kind, dom)
	}
	imp, ierr := d.ruleImpact(ctx, c, in.Type, kind, dom, false)
	if ierr != nil {
		imp = "Could not estimate impact: " + ierr.Error()
	}
	p := &plan{
		action:   fmt.Sprintf("Remove %s %s rule %s", in.Type, kind, dom),
		request:  fmt.Sprintf("DELETE /api/domains/%s/%s/%s", in.Type, kind, url.PathEscape(dom)),
		current:  fmt.Sprintf("Rule #%d enabled=%v comment=%q", found.ID, found.Enabled, found.Comment),
		proposed: "Rule removed",
		impact:   imp,
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		if err := c.DeleteDomain(ctx, in.Type, kind, dom); err != nil {
			return "", nil, err
		}
		return "Rule removed.", nil, nil
	}
	return p, nil
}

// ruleImpact estimates, from the last 24h of queries, what a rule change affects.
func (d *Deps) ruleImpact(ctx context.Context, c *pihole.Client, typ, kind, dom string, adding bool) (string, error) {
	r, err := d.window("24h", "", "")
	if err != nil {
		return "", err
	}
	var match func(string) bool
	f := pihole.QueryFilter{}
	if kind == "exact" {
		f.Domain = dom
		match = func(q string) bool { return q == dom }
	} else {
		re, err := regexp.Compile(dom)
		if err != nil {
			return "Cannot estimate impact: the regex is not valid RE2 syntax (Pi-hole will validate it itself).", nil
		}
		match = re.MatchString
	}
	allowed, blocked := 0, 0
	devices := map[string]bool{}
	info, err := d.scan(ctx, c, r, f, func(q pihole.Query) {
		if !match(q.Domain) {
			return
		}
		if pihole.IsBlocked(q.Status) {
			blocked++
			if typ == "deny" && !adding || typ == "allow" && adding {
				devices[q.Client.IP] = true
			}
		} else {
			allowed++
			if typ == "deny" && adding || typ == "allow" && !adding {
				devices[q.Client.IP] = true
			}
		}
	})
	if err != nil {
		return "", err
	}
	note := ""
	if info.Truncated {
		note = " (estimate is partial: scan cap reached)"
	}
	switch {
	case typ == "deny" && adding:
		return fmt.Sprintf("In the last 24h, %d allowed queries from %d device(s) matched and would start being blocked%s.", allowed, len(devices), note), nil
	case typ == "allow" && adding:
		return fmt.Sprintf("In the last 24h, %d blocked queries from %d device(s) matched and would start being allowed%s.", blocked, len(devices), note), nil
	case typ == "deny":
		return fmt.Sprintf("In the last 24h, %d blocked queries from %d device(s) matched; they would be allowed unless a list or another rule blocks them%s.", blocked, len(devices), note), nil
	default:
		return fmt.Sprintf("In the last 24h, %d allowed queries from %d device(s) matched; they would be blocked if a list or rule blocks the domain%s.", allowed, len(devices), note), nil
	}
}

// ---- gravity

// UpdateGravityIn is the input of update_gravity.
type UpdateGravityIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a UpdateGravityIn) instanceName() string { return a.Instance }
func (a UpdateGravityIn) token() string        { return a.ConfirmToken }
func (a UpdateGravityIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func planUpdateGravity(ctx context.Context, d *Deps, c *pihole.Client, _ UpdateGravityIn) (*plan, error) {
	ls, err := c.Lists(ctx)
	if err != nil {
		return nil, err
	}
	enabled := 0
	for _, l := range ls {
		if l.Enabled {
			enabled++
		}
	}
	cur := fmt.Sprintf("%d enabled lists", enabled)
	if s, err := c.Summary(ctx, pihole.TimeRange{}); err == nil {
		cur += fmt.Sprintf(", %d domains blocked", s.Gravity.DomainsBeingBlocked)
		if s.Gravity.LastUpdate > 0 {
			cur += ", last update " + d.unix(float64(s.Gravity.LastUpdate))
		}
	}
	p := &plan{
		action:   "Update gravity (download all lists and rebuild the block database)",
		request:  "POST /api/action/gravity (streamed)",
		current:  cur,
		proposed: "Lists re-downloaded; gravity database rebuilt",
		impact:   "Can take several minutes and uses noticeable CPU, memory and network on small devices. DNS keeps working during the update.",
	}
	p.apply = func(ctx context.Context, progress func(string)) (string, []string, error) {
		var tail []string
		err := c.UpdateGravity(ctx, func(line string) {
			progress(line)
			tail = append(tail, line)
			if len(tail) > 50 {
				tail = tail[1:]
			}
		})
		if err != nil {
			return "", tail, err
		}
		res := "Gravity update finished."
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if s, err := c.Summary(cctx, pihole.TimeRange{}); err == nil {
			res += fmt.Sprintf(" %d domains are now blocked.", s.Gravity.DomainsBeingBlocked)
		}
		return res, tail, nil
	}
	return p, nil
}

// ---- blocking

// SetBlockingIn is the input of set_blocking.
type SetBlockingIn struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Pi-hole instance name (default: the first configured instance)"`
	Enabled      bool   `json:"enabled" jsonschema:"true = turn blocking on, false = turn it off"`
	TimerSeconds int    `json:"timer_seconds,omitempty" jsonschema:"Revert after this many seconds (strongly recommended when disabling)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"Token from the preview call; omit to get a preview"`
}

func (a SetBlockingIn) instanceName() string { return a.Instance }
func (a SetBlockingIn) token() string        { return a.ConfirmToken }
func (a SetBlockingIn) canonical() any       { a.Instance, a.ConfirmToken = "", ""; return a }

func planSetBlocking(ctx context.Context, d *Deps, c *pihole.Client, in SetBlockingIn) (*plan, error) {
	if in.TimerSeconds < 0 {
		return nil, errf("timer_seconds must not be negative")
	}
	cur, err := c.GetBlocking(ctx)
	if err != nil {
		return nil, err
	}
	want := map[bool]string{true: "enabled", false: "disabled"}[in.Enabled]
	if cur.Blocking == want && cur.Timer == nil {
		return nil, errf("blocking is already %s; nothing to do", want)
	}
	p := &plan{
		action:   fmt.Sprintf("Set DNS blocking to %s", want),
		request:  fmt.Sprintf("POST /api/dns/blocking {\"blocking\":%v,\"timer\":%s}", in.Enabled, timerJSON(in.TimerSeconds)),
		current:  "blocking " + cur.Blocking,
		proposed: "blocking " + want,
	}
	if in.Enabled {
		p.impact = "Ad and tracker blocking resumes for every client."
		if in.TimerSeconds > 0 {
			p.warnings = append(p.warnings, "A timer on enable means blocking will switch OFF again afterwards.")
		}
	} else {
		p.impact = "ALL DNS filtering stops for every client of this Pi-hole."
		if in.TimerSeconds == 0 {
			p.warnings = append(p.warnings, "No timer set: blocking stays off until someone turns it back on. Prefer timer_seconds.")
		}
	}
	p.apply = func(ctx context.Context, _ func(string)) (string, []string, error) {
		b, err := c.SetBlocking(ctx, in.Enabled, in.TimerSeconds)
		if err != nil {
			return "", nil, err
		}
		return "Blocking is now " + b.Blocking + ".", nil, nil
	}
	return p, nil
}

func timerJSON(s int) string {
	if s <= 0 {
		return "null"
	}
	return fmt.Sprint(s)
}
