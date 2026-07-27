package provision

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

func testProvisioner(mock *zabbix.Mock) *Provisioner {
	cfg := config.Defaults()
	return New(mock, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// createResponder returns canned ids for *.create and empty arrays for *.get.
func createResponder() func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	return func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		switch method {
		case "hostgroup.create":
			return json.RawMessage(`{"groupids":["1"]}`), nil
		case "templategroup.create":
			return json.RawMessage(`{"groupids":["2"]}`), nil
		case "template.create":
			return json.RawMessage(`{"templateids":["10"]}`), nil
		case "host.create":
			return json.RawMessage(`{"hostids":["20"]}`), nil
		case "discoveryrule.create":
			return json.RawMessage(`{"itemids":["30"]}`), nil
		case "item.create":
			return json.RawMessage(`{"itemids":["40"]}`), nil
		case "itemprototype.create":
			return json.RawMessage(`{"itemids":["50"]}`), nil
		case "triggerprototype.create":
			return json.RawMessage(`{"triggerids":["60"]}`), nil
		case "dashboard.create":
			return json.RawMessage(`{"dashboardids":["70"]}`), nil
		default: // *.get
			return json.RawMessage(`[]`), nil
		}
	}
}

func countCalls(calls []zabbix.MockCall, method string) int {
	n := 0
	for _, c := range calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

func TestProvisionTemplateCreatesItems(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: createResponder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{Template: true}); err != nil {
		t.Fatal(err)
	}
	// Two platform templates (Linux + Windows).
	if countCalls(mock.Calls, "template.create") != 2 {
		t.Errorf("template.create calls = %d, want 2", countCalls(mock.Calls, "template.create"))
	}
	// Linux 4 items (os/version/arch/packages) + Windows 4 (os/version/software/kb).
	if got := countCalls(mock.Calls, "item.create"); got != 8 {
		t.Errorf("item.create calls = %d, want 8", got)
	}
}

func TestProvisionVirtualHosts(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: createResponder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{VHosts: true}); err != nil {
		t.Fatal(err)
	}
	// 3 vulnerability hosts + 1 statistics host
	if got := countCalls(mock.Calls, "host.create"); got != 4 {
		t.Errorf("host.create = %d, want 4", got)
	}
	// 3 discovery rules (hosts/bulletins/packages)
	if got := countCalls(mock.Calls, "discoveryrule.create"); got != 3 {
		t.Errorf("discoveryrule.create = %d, want 3", got)
	}
	// 3 hosts x 4 severity bands (Disaster/High/Average/Warning).
	if got := countCalls(mock.Calls, "triggerprototype.create"); got != 12 {
		t.Errorf("triggerprototype.create = %d, want 12", got)
	}
	// statistics: 5 aggregate items + 11 histogram buckets = 16
	if got := countCalls(mock.Calls, "item.create"); got != 16 {
		t.Errorf("statistics item.create = %d, want 16", got)
	}
}

func TestProvisionDashboard(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: createResponder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{Dashboard: true}); err != nil {
		t.Fatal(err)
	}
	if countCalls(mock.Calls, "dashboard.create") != 1 {
		t.Error("expected one dashboard.create")
	}
}
