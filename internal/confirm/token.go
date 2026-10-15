// Package confirm issues and verifies stateless preview/confirm tokens.
//
// A token binds (instance, tool, canonical args, expiry) with HMAC-SHA256, so a
// change can only be executed with exactly the arguments that were previewed,
// within the TTL, and the check works across HTTP sessions and replicas that
// share the secret.
package confirm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Errors returned by Verify.
var (
	ErrMalformed = errors.New("confirm token is malformed")
	ErrExpired   = errors.New("confirm token has expired; run the preview again")
	ErrMismatch  = errors.New("confirm token does not match this instance, tool or arguments; run the preview again")
)

// Manager issues and verifies tokens.
type Manager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// New returns a Manager. An empty secret generates a random one for this process.
func New(secret string, ttl time.Duration) (*Manager, error) {
	m := &Manager{ttl: ttl, now: time.Now}
	if secret == "" {
		m.secret = make([]byte, 32)
		if _, err := rand.Read(m.secret); err != nil {
			return nil, err
		}
	} else {
		m.secret = []byte(secret)
	}
	return m, nil
}

// SetClock overrides the clock (tests).
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// TTL returns the token lifetime.
func (m *Manager) TTL() time.Duration { return m.ttl }

func (m *Manager) mac(instance, tool string, args any, exp int64) ([]byte, error) {
	canon, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, m.secret)
	_, _ = fmt.Fprintf(h, "%d\x00%s\x00%s\x00", exp, instance, tool)
	h.Write(canon)
	return h.Sum(nil), nil
}

// Issue returns a token for the given call and its expiry time.
func (m *Manager) Issue(instance, tool string, args any) (string, time.Time, error) {
	expires := m.now().Add(m.ttl)
	sum, err := m.mac(instance, tool, args, expires.Unix())
	if err != nil {
		return "", time.Time{}, err
	}
	tok := strconv.FormatInt(expires.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(sum)
	return tok, expires, nil
}

// Verify checks a token against the call about to be executed.
func (m *Manager) Verify(token, instance, tool string, args any) error {
	expStr, sigStr, ok := strings.Cut(token, ".")
	if !ok {
		return ErrMalformed
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return ErrMalformed
	}
	want, err := m.mac(instance, tool, args, exp)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, want) {
		return ErrMismatch
	}
	if m.now().Unix() > exp {
		return ErrExpired
	}
	return nil
}
