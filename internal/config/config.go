// Package config loads, merges and validates pihole-mcp configuration.
//
// Precedence: flags > environment variables > YAML file > defaults.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Instance is one Pi-hole.
type Instance struct {
	Name          string        `yaml:"name"`
	URL           string        `yaml:"url"`
	Password      string        `yaml:"password"`
	PasswordFile  string        `yaml:"password_file"`
	TLSSkipVerify bool          `yaml:"tls_skip_verify"`
	Timeout       time.Duration `yaml:"timeout"`
}

// Server configures the MCP transport.
type Server struct {
	Transport      string   `yaml:"transport"`
	Listen         string   `yaml:"listen"`
	Path           string   `yaml:"path"`
	AuthToken      string   `yaml:"auth_token"`
	AuthTokenFile  string   `yaml:"auth_token_file"`
	TLSCertFile    string   `yaml:"tls_cert_file"`
	TLSKeyFile     string   `yaml:"tls_key_file"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// Writes gates every tool that changes Pi-hole.
type Writes struct {
	Enabled           bool          `yaml:"enabled"`
	ConfirmSecret     string        `yaml:"confirm_secret"`
	ConfirmSecretFile string        `yaml:"confirm_secret_file"`
	ConfirmTTL        time.Duration `yaml:"confirm_ttl"`
	AllowedTools      []string      `yaml:"allowed_tools"`
}

// Analysis tunes the read-only analysis tools.
type Analysis struct {
	Timezone       string        `yaml:"timezone"`
	DefaultPeriod  time.Duration `yaml:"default_period"`
	MaxScan        int           `yaml:"max_scan"`
	StaleListDays  int           `yaml:"stale_list_days"`
	HighBlockRatio float64       `yaml:"high_block_ratio"`
	AdPatternsFile string        `yaml:"ad_patterns_file"`
	CatalogFile    string        `yaml:"catalog_file"`
}

// Log configures logging.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Config is the full configuration.
type Config struct {
	Instances []Instance `yaml:"instances"`
	Server    Server     `yaml:"server"`
	Writes    Writes     `yaml:"writes"`
	Analysis  Analysis   `yaml:"analysis"`
	Log       Log        `yaml:"log"`
}

// Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		Server: Server{Transport: "stdio", Listen: ":8765", Path: "/mcp"},
		Writes: Writes{ConfirmTTL: 5 * time.Minute},
		Analysis: Analysis{
			Timezone: "UTC", DefaultPeriod: 24 * time.Hour, MaxScan: 50000,
			StaleListDays: 7, HighBlockRatio: 0.5,
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// Options are the command-line overrides. Empty values mean "not set".
type Options struct {
	ConfigPath string
	Transport  string
	Listen     string
}

// Getenv abstracts os.Getenv so tests can inject an environment.
type Getenv func(string) string

// Load builds the configuration from a file, the environment and flag options.
func Load(opts Options, getenv Getenv) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := Defaults()
	path := opts.ConfigPath
	if path == "" {
		path = getenv("PIHOLE_MCP_CONFIG")
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, errEOF) {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, getenv); err != nil {
		return nil, err
	}
	if opts.Transport != "" {
		cfg.Server.Transport = opts.Transport
	}
	if opts.Listen != "" {
		cfg.Server.Listen = opts.Listen
	}
	if err := resolveSecrets(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyEnv(cfg *Config, getenv Getenv) error {
	if u := getenv("PIHOLE_URL"); u != "" {
		if len(cfg.Instances) == 0 {
			cfg.Instances = []Instance{{Name: "default"}}
		}
		cfg.Instances[0].URL = u
	}
	if len(cfg.Instances) > 0 {
		in := &cfg.Instances[0]
		if v := getenv("PIHOLE_APP_PASSWORD"); v != "" {
			in.Password = v
		}
		if v := getenv("PIHOLE_APP_PASSWORD_FILE"); v != "" {
			in.PasswordFile = v
		}
		if v := getenv("PIHOLE_TLS_SKIP_VERIFY"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("PIHOLE_TLS_SKIP_VERIFY: %w", err)
			}
			in.TLSSkipVerify = b
		}
	}
	setStr := func(dst *string, key string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	setStr(&cfg.Server.Transport, "MCP_TRANSPORT")
	setStr(&cfg.Server.Listen, "MCP_LISTEN")
	setStr(&cfg.Server.Path, "MCP_PATH")
	setStr(&cfg.Server.AuthToken, "MCP_TOKEN")
	setStr(&cfg.Server.AuthTokenFile, "MCP_TOKEN_FILE")
	setStr(&cfg.Server.TLSCertFile, "MCP_TLS_CERT_FILE")
	setStr(&cfg.Server.TLSKeyFile, "MCP_TLS_KEY_FILE")
	if v := getenv("MCP_ALLOWED_ORIGINS"); v != "" {
		cfg.Server.AllowedOrigins = splitList(v)
	}
	if v := getenv("PIHOLE_MCP_ALLOW_WRITES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("PIHOLE_MCP_ALLOW_WRITES: %w", err)
		}
		cfg.Writes.Enabled = b
	}
	setStr(&cfg.Writes.ConfirmSecret, "PIHOLE_MCP_CONFIRM_SECRET")
	setStr(&cfg.Writes.ConfirmSecretFile, "PIHOLE_MCP_CONFIRM_SECRET_FILE")
	if v := getenv("PIHOLE_MCP_ALLOWED_TOOLS"); v != "" {
		cfg.Writes.AllowedTools = splitList(v)
	}
	if v := getenv("PIHOLE_MCP_CONFIRM_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("PIHOLE_MCP_CONFIRM_TTL: %w", err)
		}
		cfg.Writes.ConfirmTTL = d
	}
	tz := getenv("PIHOLE_MCP_TIMEZONE")
	if tz == "" {
		tz = getenv("TZ")
	}
	if tz != "" {
		cfg.Analysis.Timezone = tz
	}
	setStr(&cfg.Log.Level, "LOG_LEVEL")
	setStr(&cfg.Log.Format, "LOG_FORMAT")
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func resolveSecrets(cfg *Config) error {
	for i := range cfg.Instances {
		in := &cfg.Instances[i]
		if in.PasswordFile != "" {
			if in.Password != "" {
				return fmt.Errorf("instance %q: set only one of password and password_file", in.Name)
			}
			v, err := readSecret(in.PasswordFile)
			if err != nil {
				return fmt.Errorf("instance %q: %w", in.Name, err)
			}
			in.Password = v
		}
	}
	s := &cfg.Server
	if s.AuthTokenFile != "" {
		if s.AuthToken != "" {
			return errors.New("server: set only one of auth_token and auth_token_file")
		}
		v, err := readSecret(s.AuthTokenFile)
		if err != nil {
			return fmt.Errorf("server: %w", err)
		}
		s.AuthToken = v
	}
	w := &cfg.Writes
	if w.ConfirmSecretFile != "" {
		if w.ConfirmSecret != "" {
			return errors.New("writes: set only one of confirm_secret and confirm_secret_file")
		}
		v, err := readSecret(w.ConfirmSecretFile)
		if err != nil {
			return fmt.Errorf("writes: %w", err)
		}
		w.ConfirmSecret = v
	}
	return nil
}

// Validate checks the configuration and fails with a clear message.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Instances) == 0 {
		errs = append(errs, errors.New("no Pi-hole instance configured (set PIHOLE_URL or instances: in the config file)"))
	}
	seen := map[string]bool{}
	for i := range c.Instances {
		in := &c.Instances[i]
		if in.Name == "" {
			if i == 0 {
				in.Name = "default"
			} else {
				errs = append(errs, fmt.Errorf("instances[%d]: name is required", i))
			}
		}
		if seen[in.Name] {
			errs = append(errs, fmt.Errorf("instances: duplicate name %q", in.Name))
		}
		seen[in.Name] = true
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("instance %q: url %q must be an http(s) URL", in.Name, in.URL))
		}
		if in.Password == "" {
			errs = append(errs, fmt.Errorf("instance %q: an app password is required (password, password_file or PIHOLE_APP_PASSWORD)", in.Name))
		}
		if in.Timeout == 0 {
			in.Timeout = 10 * time.Second
		}
		if in.Timeout < 0 {
			errs = append(errs, fmt.Errorf("instance %q: timeout must be positive", in.Name))
		}
	}
	switch c.Server.Transport {
	case "stdio":
	case "http":
		if c.Server.AuthToken == "" {
			errs = append(errs, errors.New("server: http transport requires an auth token (MCP_TOKEN or MCP_TOKEN_FILE)"))
		}
		if !strings.HasPrefix(c.Server.Path, "/") {
			errs = append(errs, errors.New("server: path must start with /"))
		}
		if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
			errs = append(errs, errors.New("server: tls_cert_file and tls_key_file must be set together"))
		}
	default:
		errs = append(errs, fmt.Errorf("server: transport must be stdio or http, got %q", c.Server.Transport))
	}
	if c.Writes.ConfirmTTL <= 0 {
		errs = append(errs, errors.New("writes: confirm_ttl must be greater than 0"))
	}
	if _, err := time.LoadLocation(c.Analysis.Timezone); err != nil {
		errs = append(errs, fmt.Errorf("analysis: unknown timezone %q", c.Analysis.Timezone))
	}
	if c.Analysis.MaxScan <= 0 {
		errs = append(errs, errors.New("analysis: max_scan must be positive"))
	}
	if c.Analysis.DefaultPeriod <= 0 {
		errs = append(errs, errors.New("analysis: default_period must be positive"))
	}
	if c.Analysis.HighBlockRatio <= 0 || c.Analysis.HighBlockRatio > 1 {
		errs = append(errs, errors.New("analysis: high_block_ratio must be in (0,1]"))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log: unknown level %q", c.Log.Level))
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("log: unknown format %q", c.Log.Format))
	}
	return errors.Join(errs...)
}

// Location returns the analysis time zone.
func (c *Config) Location() *time.Location {
	loc, err := time.LoadLocation(c.Analysis.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// Redacted returns a copy safe to print: all secrets replaced.
func (c *Config) Redacted() Config {
	r := *c
	r.Instances = append([]Instance(nil), c.Instances...)
	for i := range r.Instances {
		if r.Instances[i].Password != "" {
			r.Instances[i].Password = "***"
		}
	}
	if r.Server.AuthToken != "" {
		r.Server.AuthToken = "***"
	}
	if r.Writes.ConfirmSecret != "" {
		r.Writes.ConfirmSecret = "***"
	}
	return r
}
