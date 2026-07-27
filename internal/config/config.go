// Package config loads runtime configuration from a YAML file with environment
// variable overrides. It replaces the Python config.py / ztc.conf pair.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a YAML string ("30s") or a
// bare number of seconds. gopkg.in/yaml.v3 cannot decode either into a plain
// time.Duration.
type Duration time.Duration

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML accepts "30s"/"24h" strings and bare integer seconds.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		parsed, perr := time.ParseDuration(s)
		if perr != nil {
			return fmt.Errorf("invalid duration %q: %w", s, perr)
		}
		*d = Duration(parsed)
		return nil
	}
	var secs int64
	if err := value.Decode(&secs); err != nil {
		return fmt.Errorf("duration must be a string or number of seconds")
	}
	*d = Duration(time.Duration(secs) * time.Second)
	return nil
}

// Vulners holds credentials and transport options for the Vulners API.
type Vulners struct {
	APIKey   string   `yaml:"api_key"`
	BaseURL  string   `yaml:"base_url"` // optional proxy / self-hosted endpoint
	Timeout  Duration `yaml:"timeout"`
	Retries  int      `yaml:"retries"`
	Insecure bool     `yaml:"insecure"` // skip TLS verification (proxies)

	// Client TLS certificate (PEM) for mutual-TLS endpoints (e.g. beta).
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
}

// Zabbix holds Zabbix API + zabbix-sender connection settings.
type Zabbix struct {
	URL       string `yaml:"url"`  // frontend URL for the JSON-RPC API
	User      string `yaml:"user"` // API user (ignored when token is set)
	Password  string `yaml:"password"`
	Token     string `yaml:"token"` // API token (preferred on Zabbix 7.2+)
	VerifySSL bool   `yaml:"verify_ssl"`
	Version   string `yaml:"version"` // "" = autodetect via apiinfo.version

	ServerFQDN string `yaml:"server_fqdn"` // zabbix-sender target
	ServerPort int    `yaml:"server_port"`
}

// Entities maps the virtual hosts / template / dashboard names created by the
// provision command and referenced by the scan command.
type Entities struct {
	Group string `yaml:"group"`
	// Two collection templates so a host only receives the keys its platform
	// supports (a single mixed template leaves the other platform's items in
	// "Not supported" / "Unknown metric").
	Template        string `yaml:"template"`      // Linux collection template
	TemplateName    string `yaml:"template_name"` // Linux template visible name
	TemplateWin     string `yaml:"template_win"`  // Windows collection template
	TemplateWinName string `yaml:"template_win_name"`
	TemplateGroup   string `yaml:"template_group"`
	HostsHost       string `yaml:"hosts_host"`
	HostsName       string `yaml:"hosts_name"`
	BulletinsHost   string `yaml:"bulletins_host"`
	BulletinsName   string `yaml:"bulletins_name"`
	PackagesHost    string `yaml:"packages_host"`
	PackagesName    string `yaml:"packages_name"`
	StatisticsHost  string `yaml:"statistics_host"`
	StatisticsName  string `yaml:"statistics_name"`
	Dashboard       string `yaml:"dashboard"`
	Application     string `yaml:"application"`
}

// Fix configures remediation (see docs/adr/0001-remediation-mechanism.md).
type Fix struct {
	// Key is the whitelisted agent UserParameter used to upgrade a package,
	// invoked as Key[<package>] (e.g. "vulners.fix").
	Key string `yaml:"key"`
	// TrustedUsers are Zabbix usernames whose acknowledgement authorises
	// automatic remediation (--auto-fix).
	TrustedUsers []string `yaml:"trusted_users"`
	// AgentPort is the passive agent port used to reach hosts for remediation.
	AgentPort int `yaml:"agent_port"`
	// AgentTimeout bounds each passive-agent request.
	AgentTimeout Duration `yaml:"agent_timeout"`
}

// Config is the full runtime configuration.
type Config struct {
	Vulners  Vulners  `yaml:"vulners"`
	Zabbix   Zabbix   `yaml:"zabbix"`
	Entities Entities `yaml:"entities"`
	Fix      Fix      `yaml:"fix"`
	MinCVSS  float64  `yaml:"min_cvss"`
	Schedule Duration `yaml:"schedule"` // daemon scan interval
	LogLevel string   `yaml:"log_level"`
}

// Defaults returns a Config pre-populated with the same fallbacks the Python
// implementation used, so a minimal YAML file (just the API secrets) works.
func Defaults() Config {
	return Config{
		Vulners: Vulners{
			Timeout: Duration(30 * time.Second),
			Retries: 3,
		},
		Zabbix: Zabbix{
			URL:        "http://localhost",
			VerifySSL:  true,
			ServerFQDN: "localhost",
			ServerPort: 10051,
		},
		Entities: Entities{
			Group:           "Vulners",
			Template:        "tmpl.vulners.os-report.linux",
			TemplateName:    "Template Vulners OS-Report Linux",
			TemplateWin:     "tmpl.vulners.os-report.windows",
			TemplateWinName: "Template Vulners OS-Report Windows",
			TemplateGroup:   "Templates",
			HostsHost:       "vulners.hosts",
			HostsName:       "Vulners - Hosts",
			BulletinsHost:   "vulners.bulletins",
			BulletinsName:   "Vulners - Bulletins",
			PackagesHost:    "vulners.packages",
			PackagesName:    "Vulners - Packages",
			StatisticsHost:  "vulners.statistics",
			StatisticsName:  "Vulners - Statistics",
			Dashboard:       "Vulners",
			Application:     "Vulnerabilities",
		},
		Fix: Fix{
			Key:          "vulners.fix",
			AgentPort:    10050,
			AgentTimeout: Duration(60 * time.Second),
		},
		MinCVSS:  1,
		Schedule: Duration(24 * time.Hour),
		LogLevel: "info",
	}
}

// Load reads the YAML file at path (if non-empty) over the defaults, then
// applies environment overrides for secrets. Environment variables always win.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("VULNERS_API_KEY"); v != "" {
		cfg.Vulners.APIKey = v
	}
	if v := os.Getenv("VULNERS_BASE_URL"); v != "" {
		cfg.Vulners.BaseURL = v
	}
	if v := os.Getenv("VULNERS_CLIENT_CERT"); v != "" {
		cfg.Vulners.ClientCertFile = v
	}
	if v := os.Getenv("VULNERS_CLIENT_KEY"); v != "" {
		cfg.Vulners.ClientKeyFile = v
	}
	if v := os.Getenv("ZABBIX_URL"); v != "" {
		cfg.Zabbix.URL = v
	}
	if v := os.Getenv("ZABBIX_USER"); v != "" {
		cfg.Zabbix.User = v
	}
	if v := os.Getenv("ZABBIX_PASSWORD"); v != "" {
		cfg.Zabbix.Password = v
	}
	if v := os.Getenv("ZABBIX_TOKEN"); v != "" {
		cfg.Zabbix.Token = v
	}
	if v := os.Getenv("ZABBIX_SERVER_FQDN"); v != "" {
		cfg.Zabbix.ServerFQDN = v
	}
	if v := os.Getenv("ZABBIX_SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Zabbix.ServerPort = p
		}
	}
	if v := os.Getenv("ZTC_SCHEDULE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Schedule = Duration(d)
		}
	}
	if v := os.Getenv("ZTC_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

// Validate checks that the minimum required secrets are present.
func (c Config) Validate() error {
	if c.Vulners.APIKey == "" {
		return fmt.Errorf("vulners api_key is required (set vulners.api_key or VULNERS_API_KEY)")
	}
	if c.Zabbix.Token == "" && (c.Zabbix.User == "" || c.Zabbix.Password == "") {
		return fmt.Errorf("zabbix auth is required (set zabbix.token or zabbix.user+password)")
	}
	return nil
}
