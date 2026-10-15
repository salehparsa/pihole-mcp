package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/salehparsa/pihole-mcp/internal/testutil/fakepihole"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pihole-mcp-e2e")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "pihole-mcp")
	out, err := exec.Command("go", "build", "-ldflags", "-X main.version=e2e", "-o", binPath, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func baseEnv(fake *fakepihole.Server) []string {
	return append(os.Environ(), "PIHOLE_URL="+fake.URL, "PIHOLE_APP_PASSWORD="+fakepihole.Password)
}

func TestVersionAndHelp(t *testing.T) {
	out, err := exec.Command(binPath, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "pihole-mcp e2e") {
		t.Fatalf("%v %s", err, out)
	}
	out, _ = exec.Command(binPath, "help").CombinedOutput()
	if !strings.Contains(string(out), "healthcheck") {
		t.Fatalf("%s", out)
	}
	if err := exec.Command(binPath, "bogus").Run(); err == nil {
		t.Fatal("unknown command must fail")
	}
}

func TestConfigValidateAndPrintRedacts(t *testing.T) {
	cmd := exec.Command(binPath, "config", "print")
	cmd.Env = append(os.Environ(), "PIHOLE_URL=http://pi.example", "PIHOLE_APP_PASSWORD=hunter2", "MCP_TRANSPORT=http", "MCP_TOKEN=tok-123")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	s := string(out)
	if strings.Contains(s, "hunter2") || strings.Contains(s, "tok-123") || !strings.Contains(s, "***") || !strings.Contains(s, "http://pi.example") {
		t.Fatalf("print must redact secrets:\n%s", s)
	}
	cmd = exec.Command(binPath, "config", "validate")
	cmd.Env = append(os.Environ(), "PIHOLE_URL=http://pi.example", "PIHOLE_APP_PASSWORD=x", "MCP_TRANSPORT=http")
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires an auth token") {
		t.Fatalf("http without token must fail clearly: %v %s", err, out)
	}
	cmd = exec.Command(binPath, "config", "validate")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if out, err = cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "no Pi-hole instance") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestDocsCommand(t *testing.T) {
	out, err := exec.Command(binPath, "docs").Output()
	if err != nil || !strings.Contains(string(out), "## add_domain_rule") || !strings.Contains(string(out), "## get_summary") {
		t.Fatalf("%v %.200s", err, out)
	}
}

func TestStdioEndToEnd(t *testing.T) {
	fake := fakepihole.New(t)
	cmd := exec.Command(binPath, "serve")
	cmd.Env = append(baseEnv(fake), "MCP_TRANSPORT=stdio", "LOG_LEVEL=debug")
	var stderr syncBuf
	cmd.Stderr = &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "blocked_by_device", Arguments: map[string]any{"period": "24h"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "queries blocked across") {
		t.Fatalf("%s", res.Content[0].(*mcp.TextContent).Text)
	}
	names := 0
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names++
		if strings.HasPrefix(tool.Name, "add_") || tool.Name == "update_gravity" || tool.Name == "set_blocking" {
			t.Errorf("write tool %s exposed by default", tool.Name)
		}
	}
	if names != 16 {
		t.Errorf("want 16 read tools, got %d", names)
	}
	_ = cs.Close()
	if fake.Logouts() < 1 {
		t.Errorf("session should be released on shutdown; stderr:\n%s", stderr.String())
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

func TestHTTPEndToEndAndHealthcheck(t *testing.T) {
	fake := fakepihole.New(t)
	port := freePort(t)
	cmd := exec.Command(binPath, "serve")
	cmd.Env = append(baseEnv(fake), "MCP_TRANSPORT=http", "MCP_LISTEN=127.0.0.1:"+port, "MCP_TOKEN=e2e-token", "PIHOLE_MCP_ALLOW_WRITES=true")
	var stderr syncBuf
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	base := "http://127.0.0.1:" + port
	deadline := time.Now().Add(15 * time.Second)
	for {
		if r, err := http.Get(base + "/healthz"); err == nil {
			_ = r.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start:\n%s", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	hc := exec.Command(binPath, "healthcheck")
	hc.Env = append(os.Environ(), "MCP_LISTEN=127.0.0.1:"+port)
	if out, err := hc.CombinedOutput(); err != nil {
		t.Fatalf("healthcheck: %v %s", err, out)
	}
	bad := exec.Command(binPath, "healthcheck", "--url", "http://127.0.0.1:1/healthz")
	if bad.Run() == nil {
		t.Fatal("healthcheck must fail when nothing listens")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer e2e-token")
		return http.DefaultTransport.RoundTrip(r)
	})}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: client}, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	defer func() { _ = cs.Close() }()
	n := 0
	for _, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 23 {
		t.Fatalf("writes enabled should expose 23 tools, got %d", n)
	}
	resp, err := http.Post(base+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated request must be rejected, got %d", resp.StatusCode)
	}
	if !strings.Contains(stderr.String(), "writes_enabled=true") {
		t.Errorf("startup log should state writes_enabled:\n%s", stderr.String())
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// syncBuf is a bytes.Buffer safe for use as a child process's stderr while tests read it.
type syncBuf struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}
