package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsWithEnvSecrets(t *testing.T) {
	t.Setenv("VULNERS_API_KEY", "KEY123")
	t.Setenv("ZABBIX_TOKEN", "TOK")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vulners.APIKey != "KEY123" {
		t.Errorf("api key = %q, want KEY123", cfg.Vulners.APIKey)
	}
	if cfg.Entities.HostsHost != "vulners.hosts" {
		t.Errorf("default HostsHost = %q", cfg.Entities.HostsHost)
	}
	if cfg.Zabbix.ServerPort != 10051 {
		t.Errorf("default port = %d", cfg.Zabbix.ServerPort)
	}
}

func TestLoadYAMLOverEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	yaml := `
vulners:
  api_key: from_file
zabbix:
  url: https://zbx.example.com
  user: admin
  password: secret
  server_port: 20051
min_cvss: 5
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	// Env overrides the file value.
	t.Setenv("VULNERS_API_KEY", "from_env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vulners.APIKey != "from_env" {
		t.Errorf("env should win: got %q", cfg.Vulners.APIKey)
	}
	if cfg.Zabbix.URL != "https://zbx.example.com" {
		t.Errorf("url = %q", cfg.Zabbix.URL)
	}
	if cfg.Zabbix.ServerPort != 20051 {
		t.Errorf("port = %d, want 20051", cfg.Zabbix.ServerPort)
	}
	if cfg.MinCVSS != 5 {
		t.Errorf("min_cvss = %v", cfg.MinCVSS)
	}
}

func TestDurationParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	yaml := `
vulners:
  api_key: k
  timeout: 45s
zabbix:
  token: t
schedule: 12h
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vulners.Timeout.D().Seconds() != 45 {
		t.Errorf("timeout = %v, want 45s", cfg.Vulners.Timeout.D())
	}
	if cfg.Schedule.D().Hours() != 12 {
		t.Errorf("schedule = %v, want 12h", cfg.Schedule.D())
	}
}

// F9/F15: the installer and the compose files hand ztc no YAML file, so every
// knob an operator has to reach for must have an env form.
func TestEnvOnlyKnobs(t *testing.T) {
	t.Setenv("VULNERS_API_KEY", "k")
	t.Setenv("ZABBIX_TOKEN", "t")
	t.Setenv("ZABBIX_TRAPPER_HOSTS", "10.0.0.5")
	t.Setenv("ZTC_TRUSTED_USERS", "Admin, ops")
	t.Setenv("ZTC_MIN_CVSS", "7.5")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MinCVSS != 7.5 {
		t.Errorf("min_cvss = %v, want 7.5 (ZTC_MIN_CVSS)", cfg.MinCVSS)
	}
	if cfg.Zabbix.TrapperHosts != "10.0.0.5" {
		t.Errorf("trapper_hosts = %q", cfg.Zabbix.TrapperHosts)
	}
	if len(cfg.Fix.TrustedUsers) != 2 || cfg.Fix.TrustedUsers[1] != "ops" {
		t.Errorf("trusted_users = %v, want [Admin ops]", cfg.Fix.TrustedUsers)
	}
}

// A typo in a numeric override must fail loudly: silently falling back would run
// a scan at the default min_cvss and materialise every finding as a Zabbix object.
func TestEnvRejectsMalformedNumbers(t *testing.T) {
	for _, tc := range []struct{ env, value string }{
		{"ZTC_MIN_CVSS", "hgh"},
		{"ZTC_SCHEDULE", "1 hour"},
		{"ZABBIX_SERVER_PORT", "10051x"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("VULNERS_API_KEY", "k")
			t.Setenv("ZABBIX_TOKEN", "t")
			t.Setenv(tc.env, tc.value)
			if _, err := Load(""); err == nil {
				t.Fatalf("%s=%q accepted, want an error", tc.env, tc.value)
			}
		})
	}
}

// Out-of-range values parse fine but fail silently later: min_cvss 42 provisions
// objects whose {$SCORE.MIN} no finding can reach, and schedule 0 panics
// time.NewTicker inside the daemon. Both paths (YAML and env) go through Validate.
func TestValidateRejectsOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutit func(*Config)
	}{
		{"min_cvss above 10", func(c *Config) { c.MinCVSS = 42 }},
		{"min_cvss negative", func(c *Config) { c.MinCVSS = -5 }},
		{"schedule zero", func(c *Config) { c.Schedule = 0 }},
		{"schedule negative", func(c *Config) { c.Schedule = Duration(-time.Second) }},
		{"server port zero", func(c *Config) { c.Zabbix.ServerPort = 0 }},
		{"server port above 65535", func(c *Config) { c.Zabbix.ServerPort = 70000 }},
		{"agent port above 65535", func(c *Config) { c.Fix.AgentPort = 70000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Vulners.APIKey = "k"
			cfg.Zabbix.Token = "t"
			tc.mutit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("accepted an out-of-range value, want an error")
			}
		})
	}
	// The boundaries themselves are legal: 0 keeps everything, 10 keeps only a
	// perfect-score finding.
	for _, v := range []float64{0, 10} {
		cfg := Defaults()
		cfg.Vulners.APIKey, cfg.Zabbix.Token = "k", "t"
		cfg.MinCVSS = v
		if err := cfg.Validate(); err != nil {
			t.Errorf("min_cvss %v rejected: %v", v, err)
		}
	}
}

// Same check reached through the environment, which is the only path the
// installer and the compose files have.
func TestEnvRejectsOutOfRangeMinCVSS(t *testing.T) {
	for _, v := range []string{"42", "-5"} {
		t.Setenv("VULNERS_API_KEY", "k")
		t.Setenv("ZABBIX_TOKEN", "t")
		t.Setenv("ZTC_MIN_CVSS", v)
		if _, err := Load(""); err == nil {
			t.Errorf("ZTC_MIN_CVSS=%s accepted, want an error", v)
		}
	}
}

func TestValidateMissingSecrets(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing api key")
	}
	cfg.Vulners.APIKey = "x"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing zabbix auth")
	}
	cfg.Zabbix.Token = "t"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
