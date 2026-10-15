// Package server wires the MCP server to its HTTP transport: bearer-token auth,
// Origin checks, body limits and health endpoints.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/config"
	"github.com/salehparsa/pihole-mcp/internal/instances"
)

// MaxBodyBytes caps MCP request bodies.
const MaxBodyBytes = 1 << 20

// Handler returns the HTTP handler for the "http" transport.
func Handler(cfg *config.Config, srv *mcp.Server, reg *instances.Registry, log *slog.Logger) http.Handler {
	mcpH := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Logger:              log,
		MaxRequestBodyBytes: MaxBodyBytes,
		SessionTimeout:      30 * time.Minute,
	})
	protected := originCheck(cfg.Server.AllowedOrigins, log, bearer(cfg.Server.AuthToken, log, limitBody(mcpH)))

	mux := http.NewServeMux()
	mux.Handle(cfg.Server.Path, protected)
	if !strings.HasSuffix(cfg.Server.Path, "/") {
		mux.Handle(cfg.Server.Path+"/", protected)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	ready := &readiness{reg: reg}
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if ready.ok(r.Context()) {
			_, _ = w.Write([]byte("ready\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("no Pi-hole instance reachable\n"))
	})
	return mux
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func bearer(token string, log *slog.Logger, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
			log.Warn("rejected request: bad or missing bearer token", "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="pihole-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originCheck rejects browser requests from origins that are not allowed. Native
// MCP clients send no Origin header and are unaffected.
func originCheck(allowed []string, log *slog.Logger, next http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allowed {
		set[strings.TrimRight(o, "/")] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !set[strings.TrimRight(o, "/")] {
			log.Warn("rejected request: origin not allowed", "origin", o)
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readiness caches the "can we reach a Pi-hole" probe so /readyz is cheap.
type readiness struct {
	reg *instances.Registry
	mu  sync.Mutex
	at  time.Time
	val bool
}

func (r *readiness) ok(ctx context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.at) < 10*time.Second {
		return r.val
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	r.val = false
	for _, n := range r.reg.Names() {
		_, c, _ := r.reg.Get(n)
		if _, err := c.FTLVersion(ctx); err == nil {
			r.val = true
			break
		}
	}
	r.at = time.Now()
	return r.val
}
