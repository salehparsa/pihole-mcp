package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvOnlySingleInstance(t *testing.T) {
	c, err := Load(Options{}, env(map[string]string{"PIHOLE_URL": "http://pi.hole", "PIHOLE_APP_PASSWORD": "pw"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].Name != "default" || c.Instances[0].Timeout != 10*time.Second || c.Server.Transport != "stdio" {
		t.Fatalf("unexpected %+v", c)
	}
	if c.Writes.Enabled {
		t.Fatal("writes must default to off")
	}
}

func TestPrecedenceFlagsEnvFile(t *testing.T) {
	f := write(t, "c.yaml", `
instances:
  - name: home
    url: http://file.example
    password: filepw
server:
  transport: http
  listen: ":1111"
  auth_token: filetoken
`)
	c, err := Load(Options{ConfigPath: f, Listen: ":3333"}, env(map[string]string{"MCP_LISTEN": ":2222", "PIHOLE_URL": "http://env.example"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].URL != "http://env.example" {
		t.Errorf("env should beat file, got %s", c.Instances[0].URL)
	}
	if c.Server.Listen != ":3333" {
		t.Errorf("flag should beat env, got %s", c.Server.Listen)
	}
	if c.Server.Transport != "http" || c.Instances[0].Password != "filepw" {
		t.Errorf("file values lost: %+v", c)
	}
}

func TestSecretFiles(t *testing.T) {
	pw := write(t, "pw", "  secret\n")
	tok := write(t, "tok", "tok123\n")
	c, err := Load(Options{}, env(map[string]string{
		"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD_FILE": pw,
		"MCP_TRANSPORT": "http", "MCP_TOKEN_FILE": tok,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].Password != "secret" || c.Server.AuthToken != "tok123" {
		t.Fatalf("secrets not read: %+v", c.Redacted())
	}
}

func TestValidationFailures(t *testing.T) {
	pwf := write(t, "pw", "x")
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"no instance":      {map[string]string{}, "no Pi-hole instance"},
		"bad url":          {map[string]string{"PIHOLE_URL": "::nope", "PIHOLE_APP_PASSWORD": "p"}, "must be an http(s) URL"},
		"no password":      {map[string]string{"PIHOLE_URL": "http://x"}, "app password is required"},
		"http without tok": {map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "p", "MCP_TRANSPORT": "http"}, "requires an auth token"},
		"both pw":          {map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "p", "PIHOLE_APP_PASSWORD_FILE": pwf}, "only one of password"},
		"zero ttl":         {map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "p", "PIHOLE_MCP_CONFIRM_TTL": "0s"}, "confirm_ttl"},
		"bad transport":    {map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "p", "MCP_TRANSPORT": "ws"}, "transport must be"},
		"bad tz":           {map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "p", "TZ": "Mars/Base"}, "unknown timezone"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(Options{}, env(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestUnknownYAMLFieldRejected(t *testing.T) {
	f := write(t, "c.yaml", "bogus: 1\n")
	if _, err := Load(Options{ConfigPath: f}, env(nil)); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestRedacted(t *testing.T) {
	c, err := Load(Options{}, env(map[string]string{"PIHOLE_URL": "http://x", "PIHOLE_APP_PASSWORD": "hunter2", "MCP_TRANSPORT": "http", "MCP_TOKEN": "tok"}))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Redacted()
	if r.Instances[0].Password != "***" || r.Server.AuthToken != "***" {
		t.Fatal("not redacted")
	}
	if c.Instances[0].Password != "hunter2" {
		t.Fatal("Redacted mutated original")
	}
}
