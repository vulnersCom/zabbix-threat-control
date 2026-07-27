package fix

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

type mockGetter struct {
	calls []string // "addr key"
	err   error
}

func (m *mockGetter) Get(ctx context.Context, addr, key string) (string, error) {
	m.calls = append(m.calls, addr+" "+key)
	if m.err != nil {
		return "", m.err
	}
	return "started", nil
}

func testFixer(getter AgentGetter, call func(ctx context.Context, method string, params interface{}) (json.RawMessage, error)) *Fixer {
	cfg := config.Defaults().Fix
	return New(&zabbix.Mock{CallFunc: call}, getter, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func ifaceResponder() func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	return func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		if method == "hostinterface.get" {
			return json.RawMessage(`[{"ip":"10.0.0.5","dns":"","useip":"1","port":"10050"}]`), nil
		}
		return json.RawMessage(`[]`), nil
	}
}

func TestApplyInvokesFixKey(t *testing.T) {
	getter := &mockGetter{}
	f := testFixer(getter, ifaceResponder())

	applied, failed := f.Apply(context.Background(), []Target{
		{HostID: "1", Name: "h1", Packages: []string{"openssl", "bash"}},
	})
	if applied != 2 || failed != 0 {
		t.Fatalf("applied=%d failed=%d, want 2/0", applied, failed)
	}
	want := []string{"10.0.0.5:10050 vulners.fix[openssl]", "10.0.0.5:10050 vulners.fix[bash]"}
	if len(getter.calls) != 2 || getter.calls[0] != want[0] || getter.calls[1] != want[1] {
		t.Errorf("calls = %v, want %v", getter.calls, want)
	}
}

func TestApplyDNSInterface(t *testing.T) {
	getter := &mockGetter{}
	f := testFixer(getter, func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		return json.RawMessage(`[{"ip":"","dns":"host.example","useip":"0","port":"10050"}]`), nil
	})
	f.Apply(context.Background(), []Target{{HostID: "1", Name: "h1", Packages: []string{"curl"}}})
	if len(getter.calls) != 1 || getter.calls[0] != "host.example:10050 vulners.fix[curl]" {
		t.Errorf("calls = %v", getter.calls)
	}
}

func TestApplyNoInterface(t *testing.T) {
	getter := &mockGetter{}
	f := testFixer(getter, func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		return json.RawMessage(`[]`), nil
	})
	applied, failed := f.Apply(context.Background(), []Target{{HostID: "1", Name: "h1", Packages: []string{"curl"}}})
	if applied != 0 || failed != 1 {
		t.Errorf("applied=%d failed=%d, want 0/1", applied, failed)
	}
	if len(getter.calls) != 0 {
		t.Error("should not call agent when interface missing")
	}
}

func TestTargetForHostDedupsAndUsesManagerName(t *testing.T) {
	r := model.HostResult{
		Host: model.Host{HostID: "1", Name: "h1"},
		Packages: []model.Package{
			{Name: "openssl 3.0.2 amd64"},
			{Name: "openssl 3.0.2 amd64"}, // duplicate manager name
			{Name: "bash-5.1-6.el8"},
		},
	}
	got := TargetForHost(r)
	if got.HostID != "1" {
		t.Errorf("hostid = %q", got.HostID)
	}
	if len(got.Packages) != 2 {
		t.Fatalf("packages = %v, want 2 unique", got.Packages)
	}
	if got.Packages[0] != "openssl" || got.Packages[1] != "bash-5.1-6.el8" {
		t.Errorf("packages = %v", got.Packages)
	}
}

func TestManagerName(t *testing.T) {
	cases := map[string]string{
		"openssl 3.0.2-0ubuntu1 amd64": "openssl",                 // deb (space-separated)
		"busybox-1.37.0-r31":           "busybox",                 // apk (hyphen NVR)
		"py3-foo-1.2-r0":               "py3-foo",                 // apk with hyphenated name
		"bash-5.1.8-6.el8.x86_64":      "bash-5.1.8-6.el8.x86_64", // rpm NVRA left intact (no -rN)
		"openssl":                      "openssl",
	}
	for in, want := range cases {
		if got := managerName(in); got != want {
			t.Errorf("managerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTargetsForPackage(t *testing.T) {
	results := []model.HostResult{
		{Host: model.Host{HostID: "1", Name: "h1"}, Packages: []model.Package{{Name: "openssl 3.0 amd64"}}},
		{Host: model.Host{HostID: "2", Name: "h2"}, Packages: []model.Package{{Name: "bash 5 amd64"}}},
		{Host: model.Host{HostID: "3", Name: "h3"}, Packages: []model.Package{{Name: "openssl 3.0 amd64"}}},
	}
	targets := TargetsForPackage(results, "openssl")
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	for _, tg := range targets {
		if len(tg.Packages) != 1 || tg.Packages[0] != "openssl" {
			t.Errorf("target %+v", tg)
		}
	}
}

func TestAckedByTrusted(t *testing.T) {
	trusted := map[string]bool{"7": true}
	p := problem{}
	p.Acknowledges = append(p.Acknowledges, struct {
		UserID string `json:"userid"`
		Action string `json:"action"`
	}{UserID: "9", Action: "2"})
	if ackedByTrusted(p, trusted) {
		t.Error("untrusted user should not authorise")
	}
	p.Acknowledges = append(p.Acknowledges, struct {
		UserID string `json:"userid"`
		Action string `json:"action"`
	}{UserID: "7", Action: "2"})
	if !ackedByTrusted(p, trusted) {
		t.Error("trusted ack should authorise")
	}
}

func TestTargetsFromProblems(t *testing.T) {
	f := &Fixer{}
	results := []model.HostResult{
		{Host: model.Host{HostID: "1", Name: "web-1"}, Packages: []model.Package{{Name: "openssl 3.0 amd64"}, {Name: "bash 5 amd64"}}},
		{Host: model.Host{HostID: "2", Name: "web-2"}, Packages: []model.Package{{Name: "openssl 3.0 amd64"}}},
	}
	problems := []problem{
		{Tags: []struct{ Tag, Value string }{{Tag: "vulners.target", Value: "web-1"}}},
		{Tags: []struct{ Tag, Value string }{{Tag: "vulners.package", Value: "openssl 3.0 amd64"}}},
	}
	targets := f.targetsFromProblems(problems, results)
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2 hosts", len(targets))
	}
	// web-1 acknowledged as whole host (openssl+bash) merged with openssl package
	byID := map[string]Target{}
	for _, tg := range targets {
		byID[tg.HostID] = tg
	}
	if len(byID["1"].Packages) != 2 {
		t.Errorf("web-1 packages = %v, want openssl+bash", byID["1"].Packages)
	}
	if len(byID["2"].Packages) != 1 || byID["2"].Packages[0] != "openssl" {
		t.Errorf("web-2 packages = %v", byID["2"].Packages)
	}
}
