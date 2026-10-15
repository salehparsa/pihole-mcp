package pihole

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
)

// GetBlocking returns whether DNS blocking is enabled.
func (c *Client) GetBlocking(ctx context.Context) (*Blocking, error) {
	var b Blocking
	if err := c.get(ctx, "/dns/blocking", nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// SetBlocking enables/disables blocking, optionally for timerSeconds (0 = indefinitely).
func (c *Client) SetBlocking(ctx context.Context, enabled bool, timerSeconds int) (*Blocking, error) {
	body := map[string]any{"blocking": enabled, "timer": nil}
	if timerSeconds > 0 {
		body["timer"] = timerSeconds
	}
	var b Blocking
	if err := c.do(ctx, http.MethodPost, "/dns/blocking", nil, body, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// UpdateGravity runs a gravity update, calling line for each line of streamed output.
// It uses no HTTP timeout; cancel via ctx.
func (c *Client) UpdateGravity(ctx context.Context, line func(string)) error {
	defer c.invalidate()
	retry, err := c.gravityOnce(ctx, false, line)
	if retry {
		_, err = c.gravityOnce(ctx, true, line)
	}
	return err
}

// gravityOnce makes one attempt; retry is true when the session was rejected (401).
func (c *Client) gravityOnce(ctx context.Context, forceLogin bool, line func(string)) (retry bool, err error) {
	sid, err := c.session(ctx, forceLogin)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/action/gravity", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-FTL-SID", sid)
	resp, err := c.stream.Do(req)
	if err != nil {
		return false, fmt.Errorf("pihole: gravity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized && !forceLogin {
		return true, nil
	}
	if resp.StatusCode/100 != 2 {
		buf := make([]byte, 2048)
		n, _ := resp.Body.Read(buf)
		return false, parseAPIError(resp.StatusCode, buf[:n])
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line(sc.Text())
	}
	return false, sc.Err()
}
