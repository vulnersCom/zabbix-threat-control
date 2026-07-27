package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

func linuxItems() []zabbix.ItemBrief {
	pkgs := strings.Join([]string{"bash 4.4", "openssl 1.1", "curl 7.6", "vim 8.0", "sudo 1.8", "libc 2.3"}, "\n")
	return []zabbix.ItemBrief{
		{Key: "vulners.os", LastValue: "ol"},
		{Key: "vulners.version", LastValue: "8"},
		{Key: "vulners.arch", LastValue: "x86_64"},
		{Key: "vulners.packages", LastValue: pkgs},
	}
}

func TestCollectLinuxHost(t *testing.T) {
	mock := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "10", nil },
		HostsFunc: func(ctx context.Context, tid string, limit int) ([]zabbix.HostBrief, error) {
			return []zabbix.HostBrief{{HostID: "1", Host: "h1", Name: "linux-one"}}, nil
		},
		ItemsFunc: func(ctx context.Context, hostID, key string) ([]zabbix.ItemBrief, error) {
			return linuxItems(), nil
		},
	}
	hosts, err := New(mock, []string{"tmpl"}, 0).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.Platform != model.PlatformLinux {
		t.Errorf("platform = %v", h.Platform)
	}
	if h.OSName != "oraclelinux" {
		t.Errorf("os normalize failed: %q", h.OSName)
	}
	if len(h.Packages) != 6 {
		t.Errorf("packages = %d, want 6", len(h.Packages))
	}
}

func TestCollectWindowsHost(t *testing.T) {
	mock := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "10", nil },
		HostsFunc: func(ctx context.Context, tid string, limit int) ([]zabbix.HostBrief, error) {
			return []zabbix.HostBrief{{HostID: "2", Host: "w1", Name: "win-one"}}, nil
		},
		ItemsFunc: func(ctx context.Context, hostID, key string) ([]zabbix.ItemBrief, error) {
			return []zabbix.ItemBrief{
				{Key: "vulners.os", LastValue: "Windows 10"},
				{Key: "vulners.win.software", LastValue: "Google Chrome 100.0\n7-Zip 19.0"},
				{Key: "vulners.win.kb", LastValue: "KB5031354\nKB5030211"},
			}, nil
		},
	}
	hosts, err := New(mock, []string{"tmpl"}, 0).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	h := hosts[0]
	if h.Platform != model.PlatformWindows {
		t.Errorf("platform = %v", h.Platform)
	}
	if len(h.Software) != 2 || len(h.KBList) != 2 {
		t.Errorf("software=%d kb=%d", len(h.Software), len(h.KBList))
	}
}

func TestCollectExcludesInvalid(t *testing.T) {
	mock := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "10", nil },
		HostsFunc: func(ctx context.Context, tid string, limit int) ([]zabbix.HostBrief, error) {
			return []zabbix.HostBrief{{HostID: "3", Host: "bad", Name: "bad"}}, nil
		},
		ItemsFunc: func(ctx context.Context, hostID, key string) ([]zabbix.ItemBrief, error) {
			return []zabbix.ItemBrief{
				{Key: "vulners.os", LastValue: "ubuntu"},
				{Key: "vulners.version", LastValue: "0.0"}, // invalid version
				{Key: "vulners.packages", LastValue: "a\nb"},
			}, nil
		},
	}
	hosts, err := New(mock, []string{"tmpl"}, 0).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected invalid host excluded, got %d", len(hosts))
	}
}

func TestCollectMissingTemplate(t *testing.T) {
	mock := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "", nil },
	}
	if _, err := New(mock, []string{"tmpl"}, 0).Hosts(context.Background()); err == nil {
		t.Fatal("expected error for missing template")
	}
}
