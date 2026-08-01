package scan

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	gv "github.com/kidoz/go-vulners"

	"github.com/vulnersCom/zabbix-threat-control/internal/aggregate"
	"github.com/vulnersCom/zabbix-threat-control/internal/collect"
	"github.com/vulnersCom/zabbix-threat-control/internal/vulners"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix/sender"
)

type fakePusher struct {
	batches [][]sender.Metric
}

func (f *fakePusher) Send(ctx context.Context, metrics []sender.Metric) (*sender.Response, error) {
	f.batches = append(f.batches, metrics)
	return &sender.Response{Response: "success"}, nil
}

func TestRunOncePushesTwoBatches(t *testing.T) {
	pkgs := "bash 4.4\nopenssl 1.1\ncurl 7.6\nvim 8.0\nsudo 1.8\nlibc 2.3"
	zbx := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "10", nil },
		HostsFunc: func(ctx context.Context, tid string, limit int) ([]zabbix.HostBrief, error) {
			return []zabbix.HostBrief{{HostID: "1", Host: "h1", Name: "linux-one"}}, nil
		},
		ItemsFunc: func(ctx context.Context, hostID, key string) ([]zabbix.ItemBrief, error) {
			return []zabbix.ItemBrief{
				{Key: "vulners.os", LastValue: "ubuntu"},
				{Key: "vulners.version", LastValue: "22.04"},
				{Key: "vulners.packages", LastValue: pkgs},
			}, nil
		},
	}
	aud := &vulners.Mock{
		LinuxFunc: func(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error) {
			return &gv.PackageAuditResult{Issues: []gv.PackageAuditIssue{
				{Package: "bash", ApplicableAdvisories: []gv.AuditApplicableAdvisory{
					{ID: "USN-1", CVEListMetrics: []map[string]interface{}{{"cvss": map[string]interface{}{"score": 7.5}}}},
				}},
			}}, nil
		},
	}
	push := &fakePusher{}
	col := collect.New(zbx, []string{"tmpl"}, 0)
	r := New(col, aud, push, Options{
		Entities:  aggregate.Entities{HostsHost: "vulners.hosts", PackagesHost: "vulners.packages", BulletinsHost: "vulners.bulletins", StatisticsHost: "vulners.statistics"},
		PushDelay: time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(push.batches) != 2 {
		t.Fatalf("push batches = %d, want 2 (LLD + data)", len(push.batches))
	}
	if len(push.batches[0]) == 0 || len(push.batches[1]) == 0 {
		t.Error("batches should be non-empty")
	}
}

func TestRunOnceNoHosts(t *testing.T) {
	zbx := &zabbix.Mock{
		TemplateIDFunc: func(ctx context.Context, name string) (string, error) { return "10", nil },
		HostsFunc: func(ctx context.Context, tid string, limit int) ([]zabbix.HostBrief, error) {
			return nil, nil
		},
	}
	push := &fakePusher{}
	r := New(collect.New(zbx, []string{"tmpl"}, 0), &vulners.Mock{}, push, Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(push.batches) != 0 {
		t.Error("should not push when no hosts")
	}
}
