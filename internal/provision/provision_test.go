package provision

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
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

// Regression for F2: on Zabbix 8.0 a trapper item/LLD rule created without an
// explicit trapper_hosts inherits {$TRAPPER.ALLOWED_HOSTS} (127.0.0.1,::1) and
// silently rejects sender data from a remote ztc. Every trapper create must
// carry a non-empty trapper_hosts.
func TestProvisionTrapperHostsSet(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: createResponder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{VHosts: true}); err != nil {
		t.Fatal(err)
	}
	trapperMethods := map[string]bool{
		"discoveryrule.create": true, // trapper LLD rule
		"itemprototype.create": true, // trapper item prototype
		"item.create":          true, // statistics trapper items
	}
	checked := 0
	for _, c := range mock.Calls {
		if !trapperMethods[c.Method] {
			continue
		}
		params, ok := c.Params.(map[string]interface{})
		if !ok {
			t.Fatalf("%s params not a map: %T", c.Method, c.Params)
		}
		th, _ := params["trapper_hosts"].(string)
		if th == "" {
			t.Errorf("%s created without trapper_hosts (empty rejects everyone on Zabbix 8.0)", c.Method)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no trapper create calls seen")
	}
}

// Regression for F6: a second `provision --all` must not fail on duplicate
// names. When objects already exist, template/host creates are skipped and the
// dashboard is updated in place (not re-created).
func TestProvisionIdempotent(t *testing.T) {
	responder := func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		if strings.HasSuffix(method, ".get") {
			// One row carrying every id field getID might ask for.
			return json.RawMessage(`[{"templateid":"10","hostid":"20","dashboardid":"70","groupid":"1","graphid":"5"}]`), nil
		}
		return createResponder()(ctx, method, params)
	}
	mock := &zabbix.Mock{CallFunc: responder}
	if err := testProvisioner(mock).Run(context.Background(), Flags{Template: true, VHosts: true, Dashboard: true}); err != nil {
		t.Fatalf("re-provision must be idempotent, got: %v", err)
	}
	for _, m := range []string{"template.create", "host.create", "discoveryrule.create", "dashboard.create"} {
		if got := countCalls(mock.Calls, m); got != 0 {
			t.Errorf("%s called %d times on re-provision, want 0 (should skip existing)", m, got)
		}
	}
	if got := countCalls(mock.Calls, "dashboard.update"); got != 1 {
		t.Errorf("dashboard.update = %d, want 1 (refresh in place)", got)
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
