// Package pihole is a typed client for the Pi-hole v6 REST API.
// It has no knowledge of MCP.
package pihole

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options configure a Client.
type Options struct {
	BaseURL       string
	Password      string
	Timeout       time.Duration
	TLSSkipVerify bool
	HTTPClient    *http.Client // optional, for tests
}

// Client talks to one Pi-hole. It is safe for concurrent use.
type Client struct {
	base     string
	password string
	hc       *http.Client // has a timeout
	stream   *http.Client // no timeout, for long-running actions

	mu      sync.Mutex
	sid     string
	expires time.Time

	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	at  time.Time
	val any
}

const cacheTTL = 30 * time.Second

// New creates a Client. No network traffic happens until the first call.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("pihole: invalid base URL %q", o.BaseURL)
	}
	base := strings.TrimRight(o.BaseURL, "/")
	base = strings.TrimSuffix(base, "/api")
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: o.TLSSkipVerify}, //nolint:gosec // opt-in for self-signed Pi-hole HTTPS
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c := &Client{base: base, password: o.Password, cache: map[string]cacheEntry{}}
	if o.HTTPClient != nil {
		c.hc, c.stream = o.HTTPClient, o.HTTPClient
	} else {
		c.hc = &http.Client{Transport: tr, Timeout: timeout}
		c.stream = &http.Client{Transport: tr}
	}
	return c, nil
}

// BaseURL returns the configured Pi-hole URL.
func (c *Client) BaseURL() string { return c.base }

type authResponse struct {
	Session struct {
		Valid    bool   `json:"valid"`
		SID      string `json:"sid"`
		Validity int    `json:"validity"`
		Message  string `json:"message"`
	} `json:"session"`
}

// login creates a session. Caller must hold c.mu.
func (c *Client) login(ctx context.Context) error {
	b, _ := json.Marshal(map[string]string{"password": c.password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/auth", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("pihole: login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return parseAPIError(resp.StatusCode, body)
	}
	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("pihole: login: decode: %w", err)
	}
	if !ar.Session.Valid || ar.Session.SID == "" {
		return fmt.Errorf("pihole: login rejected: %s", ar.Session.Message)
	}
	c.sid = ar.Session.SID
	validity := time.Duration(ar.Session.Validity) * time.Second
	if validity <= 0 {
		validity = 5 * time.Minute
	}
	// renew a little early
	c.expires = time.Now().Add(validity - validity/10)
	return nil
}

func (c *Client) session(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if force || c.sid == "" || time.Now().After(c.expires) {
		if err := c.login(ctx); err != nil {
			return "", err
		}
	}
	return c.sid, nil
}

// Close logs out so the session slot is released.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	sid := c.sid
	c.sid = ""
	c.mu.Unlock()
	if sid == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+"/api/auth", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-FTL-SID", sid)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func parseAPIError(status int, body []byte) error {
	var e struct {
		Error struct {
			Key     string `json:"key"`
			Message string `json:"message"`
			Hint    any    `json:"hint"`
		} `json:"error"`
	}
	ae := &APIError{Status: status}
	if json.Unmarshal(body, &e) == nil && e.Error.Key != "" {
		ae.Key, ae.Message = e.Error.Key, e.Error.Message
		if e.Error.Hint != nil {
			ae.Hint = fmt.Sprint(e.Error.Hint)
		}
	} else if s := strings.TrimSpace(string(body)); s != "" {
		if len(s) > 200 {
			s = s[:200]
		}
		ae.Message = s
	}
	return ae
}

// do performs an authenticated request, re-authenticating once on 401.
// out may be nil. A 204/empty body is not an error.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		sid, err := c.session(ctx, attempt > 0)
		if err != nil {
			return err
		}
		u := c.base + "/api" + path
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("X-FTL-SID", sid)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("pihole: %s %s: %w", method, path, err)
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("pihole: read response: %w", rerr)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode/100 != 2 {
			return parseAPIError(resp.StatusCode, data)
		}
		if out == nil || len(bytes.TrimSpace(data)) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("pihole: decode %s: %w", path, err)
		}
		return nil
	}
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, nil, out)
}

// cached memoises a read for cacheTTL. Mutations call invalidate.
func cached[T any](c *Client, key string, fn func() (T, error)) (T, error) {
	c.cacheMu.Lock()
	if e, ok := c.cache[key]; ok && time.Since(e.at) < cacheTTL {
		c.cacheMu.Unlock()
		return e.val.(T), nil
	}
	c.cacheMu.Unlock()
	v, err := fn()
	if err != nil {
		var zero T
		return zero, err
	}
	c.cacheMu.Lock()
	c.cache[key] = cacheEntry{at: time.Now(), val: v}
	c.cacheMu.Unlock()
	return v, nil
}

func (c *Client) invalidate() {
	c.cacheMu.Lock()
	c.cache = map[string]cacheEntry{}
	c.cacheMu.Unlock()
}

// IsAuthError reports whether err is a Pi-hole authentication failure.
func IsAuthError(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}
