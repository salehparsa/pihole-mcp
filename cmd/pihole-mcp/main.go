// Command pihole-mcp is an MCP server for Pi-hole v6.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"

	"github.com/salehparsa/pihole-mcp/internal/analysis"
	"github.com/salehparsa/pihole-mcp/internal/catalog"
	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/confirm"
	"github.com/salehparsa/pihole-mcp/internal/instances"
	"github.com/salehparsa/pihole-mcp/internal/server"
	"github.com/salehparsa/pihole-mcp/internal/tools"
)

// Set at build time with -ldflags "-X main.version=… -X main.commit=… -X main.date=…".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `pihole-mcp — MCP server for Pi-hole v6

Usage:
  pihole-mcp [serve] [--config FILE] [--transport stdio|http] [--listen ADDR]
  pihole-mcp config validate|print [--config FILE]
  pihole-mcp docs                 print the tool reference (markdown)
  pihole-mcp healthcheck [--url URL]   probe /healthz (for container health checks)
  pihole-mcp version

Configuration: flags > environment > YAML file > defaults. See docs/configuration.md.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	} else if len(args) > 0 && (args[0] == "--version" || args[0] == "-version") {
		cmd = "version"
	} else if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		cmd = "help"
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args, stderr)
	case "config":
		err = configCmd(args, stdout)
	case "docs":
		var md string
		if md, err = tools.Markdown(context.Background()); err == nil {
			_, _ = fmt.Fprint(stdout, md)
		}
	case "healthcheck":
		err = healthcheck(args, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "pihole-mcp %s (commit %s, built %s)\n", version, commit, date)
	case "help":
		_, _ = fmt.Fprint(stdout, usage)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pihole-mcp: %v\n", err)
		return 1
	}
	return 0
}

func loadConfig(name string, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var o config.Options
	fs.StringVar(&o.ConfigPath, "config", "", "path to the YAML config file (or PIHOLE_MCP_CONFIG)")
	fs.StringVar(&o.Transport, "transport", "", "stdio or http (or MCP_TRANSPORT)")
	fs.StringVar(&o.Listen, "listen", "", "listen address for the http transport (or MCP_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(o, nil)
}

func newLogger(cfg *config.Config, w io.Writer) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.Log.Level))
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.Log.Format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func configCmd(args []string, stdout io.Writer) error {
	if len(args) == 0 || (args[0] != "validate" && args[0] != "print") {
		return errors.New("usage: pihole-mcp config validate|print [--config FILE]")
	}
	cfg, err := loadConfig("config "+args[0], args[1:])
	if err != nil {
		return err
	}
	if args[0] == "validate" {
		_, _ = fmt.Fprintf(stdout, "configuration OK: %d instance(s), transport %s, writes %s\n", len(cfg.Instances), cfg.Server.Transport,
			map[bool]string{true: "ENABLED", false: "disabled"}[cfg.Writes.Enabled])
		return nil
	}
	red := cfg.Redacted()
	b, err := yaml.Marshal(&red)
	if err != nil {
		return err
	}
	_, err = stdout.Write(b)
	return err
}

func serve(args []string, stderr io.Writer) error {
	cfg, err := loadConfig("serve", args)
	if err != nil {
		return err
	}
	log := newLogger(cfg, stderr) // never stdout: it carries the stdio protocol
	slog.SetDefault(log)

	reg, err := instances.New(cfg.Instances)
	if err != nil {
		return err
	}
	cat, err := catalog.Load(cfg.Analysis.CatalogFile)
	if err != nil {
		return err
	}
	var extra string
	if cfg.Analysis.AdPatternsFile != "" {
		b, err := os.ReadFile(cfg.Analysis.AdPatternsFile)
		if err != nil {
			return fmt.Errorf("ad patterns: %w", err)
		}
		extra = string(b)
	}
	ads, err := analysis.NewAdMatcher(extra)
	if err != nil {
		return err
	}
	cm, err := confirm.New(cfg.Writes.ConfirmSecret, cfg.Writes.ConfirmTTL)
	if err != nil {
		return err
	}
	srv := tools.New(&tools.Deps{Cfg: cfg, Reg: reg, Confirm: cm, Catalog: cat, Ads: ads, Log: log, Version: version})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reg.Close(cctx) // release Pi-hole API session slots
	}()

	log.Info("starting", "version", version, "transport", cfg.Server.Transport, "instances", reg.Names(), "writes_enabled", cfg.Writes.Enabled)
	if cfg.Writes.Enabled && cfg.Writes.ConfirmSecret == "" {
		log.Warn("writes.confirm_secret is not set: confirm tokens use a random per-process secret and do not survive a restart")
	}
	go checkInstances(ctx, reg, log)

	if cfg.Server.Transport == "stdio" {
		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}
	hs := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           server.Handler(cfg, srv, reg, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen, "path", cfg.Server.Path, "tls", cfg.Server.TLSCertFile != "")
		if cfg.Server.TLSCertFile != "" {
			errc <- hs.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}

// checkInstances logs reachability and the minimum supported FTL version.
func checkInstances(ctx context.Context, reg *instances.Registry, log *slog.Logger) {
	for _, n := range reg.Names() {
		_, c, _ := reg.Get(n)
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		v, err := c.FTLVersion(cctx)
		cancel()
		switch {
		case err != nil:
			log.Warn("Pi-hole not reachable yet (will retry on use)", "instance", n, "url", c.BaseURL(), "error", err.Error())
		case majorVersion(v) < 6:
			log.Warn("FTL older than v6: the v6 REST API is required", "instance", n, "ftl", v)
		default:
			log.Info("Pi-hole reachable", "instance", n, "ftl", v)
		}
	}
}

func majorVersion(v string) int {
	v = strings.TrimPrefix(v, "v")
	n, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return n
}

func healthcheck(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "", "URL to probe (default: derived from MCP_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target := *url
	if target == "" {
		listen := os.Getenv("MCP_LISTEN")
		if listen == "" {
			listen = ":8765"
		}
		host, port, ok := strings.Cut(listen, ":")
		_ = ok
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		scheme := "http"
		if os.Getenv("MCP_TLS_CERT_FILE") != "" {
			scheme = "https"
		}
		target = fmt.Sprintf("%s://%s:%s/healthz", scheme, host, port)
	}
	// local probe: a self-signed certificate must not make the container unhealthy
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := hc.Get(target)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", target, resp.Status)
	}
	return nil
}
