package provision

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestProvisionWarnsOnAcceptAnyTrapper: leaving trapper_hosts unset is a
// deliberate default (Zabbix 8.0 rejects ztc's pushes otherwise), but it turns off
// 8.0's safe default on every ztc object, so the operator must be told.
func TestProvisionWarnsOnAcceptAnyTrapper(t *testing.T) {
	for _, tc := range []struct {
		name, trapperHosts string
		wantWarn           bool
	}{
		{"unset", "", true},
		{"narrowed", "10.0.0.7", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log strings.Builder
			cfg := config.Defaults()
			cfg.Zabbix.TrapperHosts = tc.trapperHosts
			p := New(&zabbix.Mock{CallFunc: createResponder()}, cfg,
				slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelWarn})))
			if err := p.Run(context.Background(), Flags{VHosts: true}); err != nil {
				t.Fatal(err)
			}
			gotWarn := strings.Contains(log.String(), "accepting trapper data from any host")
			if gotWarn != tc.wantWarn {
				t.Errorf("warning logged = %v, want %v (log: %s)", gotWarn, tc.wantWarn, log.String())
			}
		})
	}
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
	// One trigger prototype per report host; severity is set by LLD overrides
	// (F3), not by a prototype-per-band, so 3 not 12.
	if got := countCalls(mock.Calls, "triggerprototype.create"); got != 3 {
		t.Errorf("triggerprototype.create = %d, want 3", got)
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

// F3: each discovery rule carries one LLD override per severity band that sets
// the discovered trigger's severity, so a single trigger prototype (not four)
// still yields per-CVSS Disaster/High/Average/Warning.
func TestProvisionSeverityOverrides(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: createResponder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{VHosts: true}); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range mock.Calls {
		if c.Method != "discoveryrule.create" {
			continue
		}
		seen++
		params := c.Params.(map[string]interface{})
		ov, ok := params["overrides"].([]map[string]interface{})
		if !ok || len(ov) != 4 {
			t.Fatalf("discoveryrule overrides = %v, want 4 bands", params["overrides"])
		}
		for _, o := range ov {
			ops := o["operations"].([]map[string]interface{})
			if _, hasSev := ops[0]["opseverity"]; !hasSev {
				t.Errorf("override %v missing opseverity", o["name"])
			}
		}
	}
	if seen != 3 {
		t.Errorf("discoveryrule.create = %d, want 3", seen)
	}
}

// installState renders the *.get responses of an already-provisioned Zabbix.
// trapperHosts / statValueType / overrides / triggerDescs describe the shape the
// existing objects are in, so a test can present either a current install or one
// left behind by an older ztc.
type installState struct {
	trapperHosts  string // on the LLD rule, item prototype and statistics items
	statValueType string // value_type of the CVSS aggregate items
	overrides     string // JSON array of the LLD rule's overrides
	winTimeout    string // timeout on the Windows template items
	// triggerDescs holds one entry per triggerprototype.get call, in provisioning
	// order (hosts, bulletins, packages) — the rules are indistinguishable by
	// params here, since the mock hands out a single LLD rule id.
	triggerDescs [][]string
}

func currentInstall() installState {
	ov := make([]string, len(severityOverrides("{#X}")))
	for i := range ov {
		ov[i] = `{}`
	}
	return installState{
		trapperHosts:  "0.0.0.0/0,::/0",
		statValueType: "0",
		overrides:     "[" + strings.Join(ov, ",") + "]",
		triggerDescs: [][]string{
			{"Score {#H.SCORE}. Host = {#H.VNAME}"},
			{"Score {#BULLETIN.SCORE}. Bulletin = {#BULLETIN.ID} on {#BULLETIN.HOST}"},
			{"Score {#PKG.SCORE}. Package = {#PKG.ID} on {#PKG.HOST}"},
		},
		winTimeout: "30s",
	}
}

// legacyInstall is what commit 0e45599 left on a Zabbix 8.0: trapper_hosts at
// 8.0's default macro (so sender data is rejected), unsigned CVSS statistics
// items, no LLD severity overrides and four band trigger prototypes per rule.
func legacyInstall() installState {
	return installState{
		trapperHosts:  "{$TRAPPER.ALLOWED_HOSTS}",
		statValueType: "3",
		overrides:     "[]",
		triggerDescs: [][]string{
			{"[Disaster] Score …", "[High] Score …", "[Average] Score …", "[Warning] Score …"},
			{"[Disaster] Score …", "[High] Score …", "[Average] Score …", "[Warning] Score …"},
			{"[Disaster] Score …", "[High] Score …", "[Average] Score …", "[Warning] Score …"},
		},
		winTimeout: "3s",
	}
}

// responder serves *.get from the state and *.create from createResponder.
// item.get and itemprototype.get return the union of every key ztc looks for —
// each caller indexes the reply by its own key_.
func (s installState) responder() func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	rows := func(parts ...string) json.RawMessage {
		return json.RawMessage("[" + strings.Join(parts, ",") + "]")
	}
	tpCall := 0
	return func(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
		switch method {
		case "hostgroup.get", "templategroup.get":
			return rows(`{"groupid":"1"}`), nil
		case "template.get":
			return rows(`{"templateid":"10"}`), nil
		case "host.get":
			return rows(`{"hostid":"20"}`), nil
		case "dashboard.get":
			return rows(`{"dashboardid":"70"}`), nil
		case "graph.get":
			return rows(`{"graphid":"5"}`), nil
		case "usermacro.get":
			return rows(`{"hostmacroid":"80","value":"1"}`), nil
		case "item.get":
			var out []string
			// Collection-template items (their value_type was always correct; only
			// the Windows per-item timeout was added later).
			for key, vt := range map[string]string{
				"vulners.os": "1", "vulners.version": "1", "vulners.arch": "1",
				"vulners.packages": "4", "vulners.win.software": "4", "vulners.win.kb": "4",
			} {
				out = append(out, fmt.Sprintf(`{"itemid":"41","key_":%q,"value_type":%q,"timeout":%q}`, key, vt, s.winTimeout))
			}
			// Statistics items: the CVSS aggregates carry the state's value_type,
			// the counters are always unsigned.
			for _, st := range statItems() {
				vt := s.statValueType
				if st.valueType == 3 {
					vt = "3"
				}
				out = append(out, fmt.Sprintf(`{"itemid":"42","key_":%q,"value_type":%q,"trapper_hosts":%q}`,
					st.key, vt, s.trapperHosts))
			}
			return rows(out...), nil
		case "discoveryrule.get":
			return rows(fmt.Sprintf(`{"itemid":"30","trapper_hosts":%q,"overrides":%s}`, s.trapperHosts, s.overrides)), nil
		case "itemprototype.get":
			var out []string
			for _, key := range []string{
				"vulners.hosts[{#H.ID}]",
				"vulners.bulletins[{#BULLETIN.ID},{#BULLETIN.HOSTID}]",
				"vulners.packages[{#PKG.ID},{#PKG.HOSTID}]",
			} {
				out = append(out, fmt.Sprintf(`{"itemid":"50","key_":%q,"value_type":"0","trapper_hosts":%q}`, key, s.trapperHosts))
			}
			return rows(out...), nil
		case "triggerprototype.get":
			var descs []string
			if tpCall < len(s.triggerDescs) {
				descs = s.triggerDescs[tpCall]
			}
			tpCall++
			var out []string
			for i, d := range descs {
				out = append(out, fmt.Sprintf(`{"triggerid":"%d","description":%q}`, 61+i, d))
			}
			return rows(out...), nil
		default:
			return createResponder()(ctx, method, params)
		}
	}
}

// Regression for F6: a second `provision --all` against an install that is
// already in the current shape creates nothing, updates nothing except the
// dashboard (refreshed in place), and does not fail on duplicate names.
func TestProvisionIdempotent(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: currentInstall().responder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{Template: true, VHosts: true, Dashboard: true}); err != nil {
		t.Fatalf("re-provision must be idempotent, got: %v", err)
	}
	for _, m := range []string{
		"template.create", "host.create", "discoveryrule.create", "dashboard.create",
		"item.create", "itemprototype.create", "triggerprototype.create",
		"item.update", "discoveryrule.update", "itemprototype.update", "triggerprototype.delete",
	} {
		if got := countCalls(mock.Calls, m); got != 0 {
			t.Errorf("%s called %d times on an up-to-date install, want 0", m, got)
		}
	}
	if got := countCalls(mock.Calls, "dashboard.update"); got != 1 {
		t.Errorf("dashboard.update = %d, want 1 (refresh in place)", got)
	}
}

// Regression for F14: re-provisioning an install created by an older ztc must
// rewrite the fields ztc owns. Skipping existing objects (the first take on F6)
// left an upgraded Zabbix 8.0 silently broken — trapper_hosts still at the
// default macro, so every sender push was rejected.
func TestProvisionUpgradesLegacyInstall(t *testing.T) {
	mock := &zabbix.Mock{CallFunc: legacyInstall().responder()}
	if err := testProvisioner(mock).Run(context.Background(), Flags{Template: true, VHosts: true, Dashboard: true}); err != nil {
		t.Fatal(err)
	}

	updated := map[string]map[string]interface{}{} // method -> merged update payloads
	for _, c := range mock.Calls {
		if !strings.HasSuffix(c.Method, ".update") {
			continue
		}
		params, ok := c.Params.(map[string]interface{})
		if !ok {
			continue
		}
		if updated[c.Method] == nil {
			updated[c.Method] = map[string]interface{}{}
		}
		for k, v := range params {
			updated[c.Method][k] = v
		}
	}

	// The LLD rules get both the working trapper_hosts and the severity overrides
	// they were provisioned without.
	lld := updated["discoveryrule.update"]
	if lld == nil {
		t.Fatal("discoveryrule.update never called: stale trapper_hosts/overrides left in place")
	}
	if lld["trapper_hosts"] != "0.0.0.0/0,::/0" {
		t.Errorf("discoveryrule.update trapper_hosts = %v, want the accept-any CIDRs", lld["trapper_hosts"])
	}
	if ov, ok := lld["overrides"].([]map[string]interface{}); !ok || len(ov) != 4 {
		t.Errorf("discoveryrule.update overrides = %v, want 4 severity bands", lld["overrides"])
	}
	// Item prototypes and statistics items get the same trapper_hosts...
	for _, m := range []string{"itemprototype.update", "item.update"} {
		if updated[m] == nil {
			t.Fatalf("%s never called on a legacy install", m)
		}
		if updated[m]["trapper_hosts"] != "0.0.0.0/0,::/0" && m == "itemprototype.update" {
			t.Errorf("%s trapper_hosts = %v", m, updated[m]["trapper_hosts"])
		}
	}
	// ...and the CVSS aggregates flip from unsigned to float (F7 on an upgrade).
	sawFloat := false
	for _, c := range mock.Calls {
		if c.Method != "item.update" {
			continue
		}
		if p, ok := c.Params.(map[string]interface{}); ok && p["value_type"] == 0 {
			sawFloat = true
		}
	}
	if !sawFloat {
		t.Error("no item.update set value_type=0: CVSS statistics stay unsigned after an upgrade")
	}
	// The four band trigger prototypes per rule are replaced by the single
	// override-driven one.
	if got := countCalls(mock.Calls, "triggerprototype.delete"); got != 3 {
		t.Errorf("triggerprototype.delete = %d, want 3 (one per report host)", got)
	}
	if got := countCalls(mock.Calls, "triggerprototype.create"); got != 3 {
		t.Errorf("triggerprototype.create = %d, want 3", got)
	}
	// Nothing is re-created: the hosts, templates and rules already exist.
	for _, m := range []string{"host.create", "template.create", "discoveryrule.create"} {
		if got := countCalls(mock.Calls, m); got != 0 {
			t.Errorf("%s called %d times, want 0", m, got)
		}
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
