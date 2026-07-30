// Package provision creates the Zabbix entities the scanner writes into: the
// collection template, the four virtual hosts (Hosts/Bulletins/Packages/
// Statistics) with their LLD rules, prototypes and triggers, and the dashboard.
// It is a port of prepare.py targeting the Zabbix 7.x API.
//
// Provisioning is a reconciliation, not a one-shot create: re-running it against
// an installation set up by an older ztc rewrites the fields ztc owns
// (trapper_hosts, value_type, LLD overrides, trigger prototypes) instead of
// reporting "already exists" and leaving the install broken (F14).
package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

// scoreMinMacro gates trigger firing on the report hosts; its value tracks
// min_cvss.
const scoreMinMacro = "{$SCORE.MIN}"

// acceptAnyTrapperHosts is the "Allowed hosts" value that means "accept trapper
// data from anywhere" on every supported Zabbix (see trapperHosts).
const acceptAnyTrapperHosts = "0.0.0.0/0,::/0"

// severityOverrides builds LLD override rules that set each discovered trigger's
// severity from the finding's band label ({#...SEVERITY}). A single trigger
// prototype plus these overrides replaces the old one-prototype-per-band scheme,
// which materialised 4x as many trigger objects (F3). operationobject 1 =
// trigger prototype; operator 8 = "matches"; value ".*" targets the sole
// prototype on the rule.
func severityOverrides(severityMacro string) []map[string]interface{} {
	ov := make([]map[string]interface{}, 0, len(model.SeverityBands))
	for i, b := range model.SeverityBands {
		ov = append(ov, map[string]interface{}{
			"name": b.Label,
			"step": i + 1,
			"stop": "0",
			"filter": map[string]interface{}{
				"evaltype": 0,
				"conditions": []map[string]interface{}{
					{"macro": severityMacro, "operator": 8, "value": "^" + b.Label + "$"},
				},
			},
			"operations": []map[string]interface{}{
				{"operationobject": 1, "operator": 8, "value": ".*", "opseverity": map[string]interface{}{"severity": b.Priority}},
			},
		})
	}
	return ov
}

// Flags selects which entities to create (mirrors prepare.py -uvtd).
type Flags struct {
	VHosts    bool
	Template  bool
	Dashboard bool
}

// Provisioner creates entities via the Zabbix client.
type Provisioner struct {
	c        zabbix.Client
	cfg      config.Config
	log      *slog.Logger
	verMajor int // cached Zabbix version (0 until first ensureVersion)
	verMinor int
}

// New builds a Provisioner.
func New(c zabbix.Client, cfg config.Config, log *slog.Logger) *Provisioner {
	return &Provisioner{c: c, cfg: cfg, log: log}
}

// atLeast reports whether the target Zabbix API is at least major.minor. Used to
// shape write payloads that differ by version (template groups, item timeouts).
func (p *Provisioner) atLeast(ctx context.Context, major, minor int) bool {
	if p.verMajor == 0 {
		if v, err := p.c.Version(ctx); err == nil {
			parts := strings.SplitN(v, ".", 3)
			p.verMajor, _ = strconv.Atoi(parts[0])
			if len(parts) > 1 {
				p.verMinor, _ = strconv.Atoi(parts[1])
			}
		}
	}
	return p.verMajor > major || (p.verMajor == major && p.verMinor >= minor)
}

// Run executes the selected provisioning steps.
func (p *Provisioner) Run(ctx context.Context, f Flags) error {
	// Materialising "any" is deliberate (Zabbix 8.0 would otherwise reject ztc's
	// sender data), but it does switch off 8.0's safe default, so say so out loud.
	if f.VHosts && p.cfg.Zabbix.TrapperHosts == "" {
		p.log.Warn("accepting trapper data from any host",
			"trapper_hosts", acceptAnyTrapperHosts,
			"hint", "set zabbix.trapper_hosts (env ZABBIX_TRAPPER_HOSTS) to ztc's source address to narrow this")
	}
	if f.Template {
		if err := p.createTemplate(ctx); err != nil {
			return fmt.Errorf("template: %w", err)
		}
	}
	if f.VHosts {
		if err := p.createVirtualHosts(ctx); err != nil {
			return fmt.Errorf("virtual hosts: %w", err)
		}
	}
	if f.Dashboard {
		if err := p.createDashboard(ctx); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}
	return nil
}

// --- host group / template group ---

func (p *Provisioner) ensureHostGroup(ctx context.Context) (string, error) {
	id, err := p.getID(ctx, "hostgroup.get", map[string]interface{}{
		"filter": map[string]interface{}{"name": p.cfg.Entities.Group},
		"output": []string{"groupid"},
	}, "groupid")
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	res, err := p.c.Call(ctx, "hostgroup.create", map[string]interface{}{"name": p.cfg.Entities.Group})
	if err != nil {
		return "", err
	}
	return firstID(res, "groupids")
}

func (p *Provisioner) templateGroupID(ctx context.Context) (string, error) {
	// Zabbix 6.2+ splits template groups from host groups; 6.0/5.x attach
	// templates to a regular host group (no templategroup.* API).
	api := "templategroup"
	if !p.atLeast(ctx, 6, 2) {
		api = "hostgroup"
	}
	id, err := p.getID(ctx, api+".get", map[string]interface{}{
		"filter": map[string]interface{}{"name": p.cfg.Entities.TemplateGroup},
		"output": []string{"groupid"},
	}, "groupid")
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	res, err := p.c.Call(ctx, api+".create", map[string]interface{}{"name": p.cfg.Entities.TemplateGroup})
	if err != nil {
		return "", err
	}
	return firstID(res, "groupids")
}

// --- collection template ---

type tmplItem struct {
	name, key string
	valueType int    // 1=char, 4=text
	timeout   string // per-item timeout ("" = global default)
}

// createTemplate creates two platform-specific collection templates so a host
// only receives the keys its agent supports (avoiding "Unknown metric" on the
// other platform's items).
func (p *Provisioner) createTemplate(ctx context.Context) error {
	groupID, err := p.templateGroupID(ctx)
	if err != nil {
		return err
	}
	linux := []tmplItem{
		{"OS - Name", "vulners.os", 1, ""},
		{"OS - Version", "vulners.version", 1, ""},
		{"OS - Arch", "vulners.arch", 1, ""},
		{"OS - Packages", "vulners.packages", 4, ""},
	}
	// Windows keys shell out to PowerShell (slow startup); vulners.win.kb runs
	// Get-HotFix (WMI) which routinely exceeds the 3s default, so give them 30s.
	windows := []tmplItem{
		{"OS - Name", "vulners.os", 1, "30s"},
		{"OS - Version", "vulners.version", 1, "30s"},
		{"Windows - Software", "vulners.win.software", 4, "30s"},
		{"Windows - KB", "vulners.win.kb", 4, "30s"},
	}
	if err := p.createOneTemplate(ctx, groupID, p.cfg.Entities.Template, p.cfg.Entities.TemplateName, linux); err != nil {
		return err
	}
	return p.createOneTemplate(ctx, groupID, p.cfg.Entities.TemplateWin, p.cfg.Entities.TemplateWinName, windows)
}

func (p *Provisioner) createOneTemplate(ctx context.Context, groupID, host, name string, items []tmplItem) error {
	templateID, err := p.existing(ctx, "template", "host", host)
	if err != nil {
		return err
	}
	verb := "reconciled"
	if templateID == "" {
		res, cerr := p.c.Call(ctx, "template.create", map[string]interface{}{
			"host":   host,
			"name":   name,
			"groups": []map[string]string{{"groupid": groupID}},
		})
		if cerr != nil {
			return cerr
		}
		if templateID, err = firstID(res, "templateids"); err != nil {
			return err
		}
		verb = "created"
	}
	have, err := p.fetchByKey(ctx, "item.get", map[string]interface{}{
		"hostids": templateID,
		"output":  "extend",
	})
	if err != nil {
		return err
	}
	for _, it := range items {
		// Fields ztc owns and therefore rewrites on an existing item; delay/name/
		// tags are left alone so an operator's tuning survives re-provisioning.
		owned := map[string]interface{}{"value_type": it.valueType}
		// Per-item timeouts are a Zabbix 7.0 feature; older APIs reject the field.
		if it.timeout != "" && p.atLeast(ctx, 7, 0) {
			owned["timeout"] = it.timeout
		}
		cur, ok := have[it.key]
		if !ok {
			params := map[string]interface{}{
				"name":   it.name,
				"key_":   it.key,
				"hostid": templateID,
				"type":   0, // Zabbix agent
				"delay":  "1d",
				"tags":   []map[string]string{{"tag": "vulners", "value": p.cfg.Entities.Application}},
			}
			for k, v := range owned {
				params[k] = v
			}
			if _, err := p.c.Call(ctx, "item.create", params); err != nil {
				return fmt.Errorf("template item %q: %w", it.key, err)
			}
			continue
		}
		if d := drift(cur, owned); len(d) > 0 {
			d["itemid"] = cur.str("itemid")
			if _, err := p.c.Call(ctx, "item.update", d); err != nil {
				return fmt.Errorf("template item %q: %w", it.key, err)
			}
			p.log.Info("updated template item", "key", it.key, "fields", changedFields(d))
		}
	}
	p.log.Info(verb+" collection template", "name", name, "id", templateID)
	return nil
}

// --- virtual hosts ---

type vhostSpec struct {
	host, name      string
	lldKey          string
	itemProtoName   string
	itemProtoKey    string
	triggerItemExpr string // the "last(...)>0" part; the score gate is appended
	scoreMacro      string // LLD macro holding the CVSS score, e.g. "{#BULLETIN.SCORE}"
	severityMacro   string // LLD macro holding the band label, e.g. "{#BULLETIN.SEVERITY}"
	triggerDesc     string
	triggerURL      string
	triggerComment  string
	triggerTags     []map[string]string // carry host/package identity into events (for fix)
}

func (p *Provisioner) createVirtualHosts(ctx context.Context) error {
	groupID, err := p.ensureHostGroup(ctx)
	if err != nil {
		return err
	}
	e := p.cfg.Entities

	specs := []vhostSpec{
		{
			host: e.HostsHost, name: e.HostsName, lldKey: "vulners.hosts_lld",
			itemProtoName:   "CVSS Score on {#H.HOST} [{#H.VNAME}]",
			itemProtoKey:    "vulners.hosts[{#H.ID}]",
			triggerItemExpr: fmt.Sprintf("last(/%s/vulners.hosts[{#H.ID}])>0", e.HostsHost),
			scoreMacro:      "{#H.SCORE}",
			severityMacro:   "{#H.SEVERITY}",
			triggerDesc:     "Score {#H.SCORE}. Host = {#H.VNAME}",
			triggerComment:  "Cumulative fix:\r\n\r\n{#H.FIX}",
			triggerTags: []map[string]string{
				{"tag": "vulners.target", "value": "{#H.VNAME}"},
				{"tag": "vulners.host", "value": "{#H.VNAME}"},
			},
		},
		{
			host: e.BulletinsHost, name: e.BulletinsName, lldKey: "vulners.bulletins_lld",
			itemProtoName:   "[{#BULLETIN.SCORE}] {#BULLETIN.ID} on {#BULLETIN.HOST}",
			itemProtoKey:    "vulners.bulletins[{#BULLETIN.ID},{#BULLETIN.HOSTID}]",
			triggerItemExpr: fmt.Sprintf("last(/%s/vulners.bulletins[{#BULLETIN.ID},{#BULLETIN.HOSTID}])>0", e.BulletinsHost),
			scoreMacro:      "{#BULLETIN.SCORE}",
			severityMacro:   "{#BULLETIN.SEVERITY}",
			triggerDesc:     "Score {#BULLETIN.SCORE}. Bulletin = {#BULLETIN.ID} on {#BULLETIN.HOST}",
			triggerURL:      "https://vulners.com/info/{#BULLETIN.ID}",
			triggerComment:  "Affected host: {#BULLETIN.HOST}",
			triggerTags:     []map[string]string{{"tag": "vulners.host", "value": "{#BULLETIN.HOST}"}},
		},
		{
			host: e.PackagesHost, name: e.PackagesName, lldKey: "vulners.packages_lld",
			itemProtoName:   "[{#PKG.SCORE}] {#PKG.ID} on {#PKG.HOST}",
			itemProtoKey:    "vulners.packages[{#PKG.ID},{#PKG.HOSTID}]",
			triggerItemExpr: fmt.Sprintf("last(/%s/vulners.packages[{#PKG.ID},{#PKG.HOSTID}])>0", e.PackagesHost),
			scoreMacro:      "{#PKG.SCORE}",
			severityMacro:   "{#PKG.SEVERITY}",
			triggerDesc:     "Score {#PKG.SCORE}. Package = {#PKG.ID} on {#PKG.HOST}",
			triggerURL:      "https://vulners.com/info/{#PKG.URL}",
			triggerComment:  "Affected host: {#PKG.HOST}\r\n----\r\n{#PKG.FIX}",
			triggerTags: []map[string]string{
				{"tag": "vulners.package", "value": "{#PKG.ID}"},
				{"tag": "vulners.host", "value": "{#PKG.HOST}"},
			},
		},
	}
	for _, s := range specs {
		if err := p.createVirtualHost(ctx, groupID, s); err != nil {
			return fmt.Errorf("vhost %q: %w", s.name, err)
		}
	}
	return p.createStatisticsHost(ctx, groupID)
}

func (p *Provisioner) createVirtualHost(ctx context.Context, groupID string, s vhostSpec) error {
	hostID, err := p.existing(ctx, "host", "host", s.host)
	if err != nil {
		return err
	}
	if hostID == "" {
		if hostID, err = p.createBareHost(ctx, s.host, s.name, groupID, true); err != nil {
			return err
		}
		p.log.Info("created virtual host", "name", s.name, "id", hostID)
	} else if err := p.syncScoreMacro(ctx, hostID); err != nil {
		return fmt.Errorf("%s macro: %w", scoreMinMacro, err)
	}

	lldID, err := p.ensureDiscoveryRule(ctx, hostID, s)
	if err != nil {
		return fmt.Errorf("discovery rule: %w", err)
	}
	if err := p.ensureItemPrototype(ctx, hostID, lldID, s); err != nil {
		return fmt.Errorf("item prototype: %w", err)
	}
	if err := p.ensureTriggerPrototype(ctx, lldID, s); err != nil {
		return fmt.Errorf("trigger prototype: %w", err)
	}
	return nil
}

// syncScoreMacro keeps {$SCORE.MIN} on an existing report host in step with
// min_cvss. It goes through usermacro.* rather than host.update so that macros an
// operator added to the host are not wiped.
func (p *Provisioner) syncScoreMacro(ctx context.Context, hostID string) error {
	want := fmt.Sprintf("%g", p.cfg.MinCVSS)
	rows, err := p.fetch(ctx, "usermacro.get", map[string]interface{}{
		"hostids": hostID,
		"filter":  map[string]interface{}{"macro": scoreMinMacro},
		"output":  []string{"hostmacroid", "value"},
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		_, err = p.c.Call(ctx, "usermacro.create", map[string]interface{}{
			"hostid": hostID, "macro": scoreMinMacro, "value": want,
		})
		return err
	}
	have := rows[0].str("value")
	if have == want {
		return nil
	}
	if _, err := p.c.Call(ctx, "usermacro.update", map[string]interface{}{
		"hostmacroid": rows[0].str("hostmacroid"), "value": want,
	}); err != nil {
		return err
	}
	p.log.Info("updated macro", "macro", scoreMinMacro, "from", have, "to", want)
	return nil
}

// ensureDiscoveryRule creates the host's trapper LLD rule or brings an existing
// one up to date, and returns its id.
func (p *Provisioner) ensureDiscoveryRule(ctx context.Context, hostID string, s vhostSpec) (string, error) {
	rows, err := p.fetch(ctx, "discoveryrule.get", map[string]interface{}{
		"hostids":         hostID,
		"filter":          map[string]interface{}{"key_": s.lldKey},
		"output":          []string{"itemid", "trapper_hosts"},
		"selectOverrides": "extend",
	})
	if err != nil {
		return "", err
	}
	overrides := severityOverrides(s.severityMacro)
	if len(rows) == 0 {
		res, err := p.c.Call(ctx, "discoveryrule.create", map[string]interface{}{
			"type":          2, // trapper
			"hostid":        hostID,
			"name":          s.name,
			"key_":          s.lldKey,
			"lifetime":      "0",
			"trapper_hosts": p.trapperHosts(), // explicit: Zabbix 8.0 else defaults to 127.0.0.1,::1 and drops sender data
			"overrides":     overrides,
		})
		if err != nil {
			return "", err
		}
		return firstID(res, "itemids")
	}
	cur := rows[0]
	lldID := cur.str("itemid")
	upd := drift(cur, map[string]interface{}{"trapper_hosts": p.trapperHosts()})
	// A rule provisioned before F3 has no severity overrides at all; without them
	// the single trigger prototype would leave every discovered trigger at Warning.
	if cur.count("overrides") != len(overrides) {
		upd["overrides"] = overrides
	}
	if len(upd) > 0 {
		upd["itemid"] = lldID
		if _, err := p.c.Call(ctx, "discoveryrule.update", upd); err != nil {
			return "", err
		}
		p.log.Info("updated discovery rule", "key", s.lldKey, "fields", changedFields(upd))
	}
	return lldID, nil
}

func (p *Provisioner) ensureItemPrototype(ctx context.Context, hostID, lldID string, s vhostSpec) error {
	have, err := p.fetchByKey(ctx, "itemprototype.get", map[string]interface{}{
		"discoveryids": lldID,
		"output":       "extend",
	})
	if err != nil {
		return err
	}
	owned := map[string]interface{}{
		"value_type":    0, // float
		"trapper_hosts": p.trapperHosts(),
	}
	cur, ok := have[s.itemProtoKey]
	if !ok {
		params := map[string]interface{}{
			"hostid": hostID,
			"ruleid": lldID,
			"name":   s.itemProtoName,
			"key_":   s.itemProtoKey,
			"type":   2, // trapper
		}
		for k, v := range owned {
			params[k] = v
		}
		_, err := p.c.Call(ctx, "itemprototype.create", params)
		return err
	}
	if d := drift(cur, owned); len(d) > 0 {
		d["itemid"] = cur.str("itemid")
		if _, err := p.c.Call(ctx, "itemprototype.update", d); err != nil {
			return err
		}
		p.log.Info("updated item prototype", "key", s.itemProtoKey, "fields", changedFields(d))
	}
	return nil
}

// ensureTriggerPrototype leaves exactly one trigger prototype on the rule; its
// severity is set at discovery by the rule's LLD overrides (from the finding's
// {#...SEVERITY} band). Pre-F3 installs carry four band prototypes
// ("[Disaster] Score …", each with its own score window); any shape other than
// the current one is replaced wholesale rather than patched field by field.
func (p *Provisioner) ensureTriggerPrototype(ctx context.Context, lldID string, s vhostSpec) error {
	rows, err := p.fetch(ctx, "triggerprototype.get", map[string]interface{}{
		"discoveryids": lldID,
		"output":       []string{"triggerid", "description"},
	})
	if err != nil {
		return err
	}
	if len(rows) == 1 && rows[0].str("description") == s.triggerDesc {
		return nil
	}
	if len(rows) > 0 {
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.str("triggerid"))
		}
		sort.Strings(ids)
		if _, err := p.c.Call(ctx, "triggerprototype.delete", ids); err != nil {
			return err
		}
		p.log.Info("replaced stale trigger prototypes", "rule", s.lldKey, "deleted", len(ids))
	}
	trigger := map[string]interface{}{
		"expression":   fmt.Sprintf("%s and %s>=%s", s.triggerItemExpr, s.scoreMacro, scoreMinMacro),
		"description":  s.triggerDesc,
		"manual_close": 1,
		"priority":     model.SeverityFor(0).Priority, // fallback; overrides set the real severity
		"comments":     s.triggerComment,
	}
	if s.triggerURL != "" {
		trigger["url"] = s.triggerURL
	}
	if len(s.triggerTags) > 0 {
		trigger["tags"] = s.triggerTags
	}
	_, err = p.c.Call(ctx, "triggerprototype.create", trigger)
	return err
}

// statItem is one item on the statistics host.
type statItem struct {
	name, key string
	valueType int
}

// statItems lists the statistics host's items. TotalHosts and the per-score
// buckets are counts; the CVSS aggregates are decimals ("9.8") and must be float
// (value_type 0) — as unsigned (3) they land in NOT SUPPORTED on 6.0 and are
// silently truncated to "9" on 7.x (F7).
func statItems() []statItem {
	items := []statItem{
		{"CVSS Score - Total Hosts", "vulners.TotalHosts", 3},
		{"CVSS Score - Maximum", "vulners.scoreMaximum", 0},
		{"CVSS Score - Average", "vulners.scoreAverage", 0},
		{"CVSS Score - Minimum", "vulners.scoreMinimum", 0},
		{"CVSS Score - Median", "vulners.scoreMedian", 0},
	}
	for i := 0; i <= 10; i++ {
		items = append(items, statItem{
			fmt.Sprintf("CVSS Score - Hosts with a score ~ %d", i),
			fmt.Sprintf("vulners.hostsCountScore%d", i), 3,
		})
	}
	return items
}

func (p *Provisioner) createStatisticsHost(ctx context.Context, groupID string) error {
	e := p.cfg.Entities
	hostID, err := p.existing(ctx, "host", "host", e.StatisticsHost)
	if err != nil {
		return err
	}
	if hostID == "" {
		if hostID, err = p.createBareHost(ctx, e.StatisticsHost, e.StatisticsName, groupID, false); err != nil {
			return err
		}
		p.log.Info("created statistics host", "name", e.StatisticsName, "id", hostID)
	}
	have, err := p.fetchByKey(ctx, "item.get", map[string]interface{}{
		"hostids": hostID,
		"output":  "extend",
	})
	if err != nil {
		return err
	}
	for _, s := range statItems() {
		owned := map[string]interface{}{
			"value_type":    s.valueType,
			"trapper_hosts": p.trapperHosts(),
		}
		cur, ok := have[s.key]
		if !ok {
			params := map[string]interface{}{
				"name":   s.name,
				"key_":   s.key,
				"hostid": hostID,
				"type":   2, // trapper
				"tags":   []map[string]string{{"tag": "vulners", "value": e.Application}},
			}
			for k, v := range owned {
				params[k] = v
			}
			if _, err := p.c.Call(ctx, "item.create", params); err != nil {
				return fmt.Errorf("statistics item %q: %w", s.key, err)
			}
			continue
		}
		if d := drift(cur, owned); len(d) > 0 {
			d["itemid"] = cur.str("itemid")
			if _, err := p.c.Call(ctx, "item.update", d); err != nil {
				return fmt.Errorf("statistics item %q: %w", s.key, err)
			}
			p.log.Info("updated statistics item", "key", s.key, "fields", changedFields(d))
		}
	}
	return nil
}

// createBareHost creates a host with a single agent interface and the SCORE.MIN
// macro (for the vulnerability hosts) or without it (statistics).
func (p *Provisioner) createBareHost(ctx context.Context, host, name, groupID string, withMacro bool) (string, error) {
	params := map[string]interface{}{
		"host":   host,
		"name":   name,
		"groups": []map[string]string{{"groupid": groupID}},
		"tags":   []map[string]string{{"tag": "vulners", "value": p.cfg.Entities.Application}},
		"interfaces": []map[string]interface{}{{
			"type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "", "port": "10050",
		}},
	}
	if withMacro {
		params["macros"] = []map[string]string{{"macro": scoreMinMacro, "value": fmt.Sprintf("%g", p.cfg.MinCVSS)}}
	}
	res, err := p.c.Call(ctx, "host.create", params)
	if err != nil {
		return "", err
	}
	return firstID(res, "hostids")
}

// --- graphs (CVSS trend + score distribution) ---

// scoreColors is a green→red palette for the 11 score buckets (0..10).
var scoreColors = [11]string{
	"1A7C11", "3BAB2E", "5CBA00", "8EC31F", "C3D600",
	"E0C810", "F0A30A", "F07B00", "E85D00", "D64000", "C00000",
}

// statItemIDs maps the statistics host's item keys to their ids.
func (p *Provisioner) statItemIDs(ctx context.Context, hostID string) map[string]string {
	m := map[string]string{}
	res, err := p.c.Call(ctx, "item.get", map[string]interface{}{
		"hostids": hostID,
		"output":  []string{"itemid", "key_"},
	})
	if err != nil {
		return m
	}
	var rows []struct {
		ItemID string `json:"itemid"`
		Key    string `json:"key_"`
	}
	_ = json.Unmarshal(res, &rows)
	for _, r := range rows {
		m[r.Key] = r.ItemID
	}
	return m
}

// ensureGraph returns the id of a graph by name, creating it if absent. gitems
// reference statistics-host items. Classic graphs are used (not svggraph) as
// they render identically on Zabbix 6.0, 7.0 and 8.0, including the pie graphtype.
func (p *Provisioner) ensureGraph(ctx context.Context, name string, graphType int, gitems []map[string]interface{}) string {
	if id, _ := p.getID(ctx, "graph.get", map[string]interface{}{
		"filter": map[string]interface{}{"name": name}, "output": []string{"graphid"},
	}, "graphid"); id != "" {
		return id
	}
	res, err := p.c.Call(ctx, "graph.create", map[string]interface{}{
		"name": name, "width": 900, "height": 200, "graphtype": graphType, "gitems": gitems,
	})
	if err != nil {
		p.log.Warn("graph create failed", "name", name, "err", err)
		return ""
	}
	id, _ := firstID(res, "graphids")
	return id
}

// createGraphs builds the Median CVSS line graph and the score-distribution pie
// from the statistics host items; returns their ids ("" if unavailable).
func (p *Provisioner) createGraphs(ctx context.Context) (median, ratio string) {
	statID, _ := p.hostID(ctx, p.cfg.Entities.StatisticsHost)
	if statID == "" {
		return "", ""
	}
	items := p.statItemIDs(ctx, statID)
	if id := items["vulners.scoreMedian"]; id != "" {
		median = p.ensureGraph(ctx, "Median CVSS Score", 0, []map[string]interface{}{
			{"itemid": id, "color": "1E87F0", "drawtype": 5, "sortorder": 0},
		})
	}
	var gitems []map[string]interface{}
	for i := 0; i <= 10; i++ {
		id := items[fmt.Sprintf("vulners.hostsCountScore%d", i)]
		if id == "" {
			continue
		}
		gitems = append(gitems, map[string]interface{}{"itemid": id, "color": scoreColors[i], "sortorder": i})
	}
	if len(gitems) > 0 {
		ratio = p.ensureGraph(ctx, "CVSS Score ratio by hosts", 2, gitems) // graphtype 2 = pie
	}
	return median, ratio
}

// --- dashboard ---

func (p *Provisioner) createDashboard(ctx context.Context) error {
	e := p.cfg.Entities
	// Dashboard column count went from 24 (<=6.2) to 72 (>=6.4). Widget x/width
	// are authored in the 24-column grid; scale them so the layout stays full-
	// width on newer Zabbix instead of collapsing to a third (F5).
	cols := 1
	if p.atLeast(ctx, 6, 4) {
		cols = 3
	}
	problems := func(name, hostID string, x, y int) map[string]interface{} {
		return map[string]interface{}{
			"type": "problems", "name": name, "x": x * cols, "y": y, "width": 12 * cols, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "show_lines", "value": 100},
				{"type": 3, "name": "hostids.0", "value": hostID},
			},
		}
	}
	graphWidget := func(name, graphID string, x, y int) map[string]interface{} {
		return map[string]interface{}{
			"type": "graph", "name": name, "x": x * cols, "y": y, "width": 12 * cols, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "source_type", "value": 0}, // 0 = graph
				{"type": 6, "name": "graphid", "value": graphID},
			},
		}
	}

	hostsID, _ := p.hostID(ctx, e.HostsHost)
	bulletinsID, _ := p.hostID(ctx, e.BulletinsHost)
	packagesID, _ := p.hostID(ctx, e.PackagesHost)
	groupID, _ := p.getID(ctx, "hostgroup.get", map[string]interface{}{
		"filter": map[string]interface{}{"name": e.Group}, "output": []string{"groupid"},
	}, "groupid")
	medianGraph, ratioGraph := p.createGraphs(ctx)

	var widgets []map[string]interface{}
	// Severity overview across the whole Vulners group (works now that triggers
	// carry real CVSS-based priorities).
	if groupID != "" {
		widgets = append(widgets, map[string]interface{}{
			"type": "problemsbysv", "name": "Problems by severity", "x": 0, "y": 0, "width": 24 * cols, "height": 4,
			"fields": []map[string]interface{}{{"type": 2, "name": "groupids.0", "value": groupID}},
		})
	}
	widgets = append(widgets,
		problems(e.HostsName, hostsID, 0, 4),
		problems(e.PackagesName, packagesID, 12, 4),
		problems(e.BulletinsName, bulletinsID, 0, 12),
	)
	if medianGraph != "" {
		widgets = append(widgets, graphWidget("Median CVSS Score", medianGraph, 12, 12))
	}
	if ratioGraph != "" {
		widgets = append(widgets, graphWidget("CVSS Score ratio by hosts", ratioGraph, 0, 20))
	}

	dashParams := map[string]interface{}{
		"name":    e.Dashboard,
		"private": 0,
		"pages":   []map[string]interface{}{{"widgets": widgets}},
	}
	// Idempotent: refresh an existing dashboard in place rather than failing on
	// the duplicate name, so re-provisioning picks up new widgets/graphs (F6).
	existingDash, err := p.existing(ctx, "dashboard", "name", e.Dashboard)
	if err != nil {
		return err
	}
	verb := "created"
	if existingDash != "" {
		dashParams["dashboardid"] = existingDash
		_, err = p.c.Call(ctx, "dashboard.update", dashParams)
		verb = "updated"
	} else {
		_, err = p.c.Call(ctx, "dashboard.create", dashParams)
	}
	if err != nil {
		return err
	}
	p.log.Info(verb+" dashboard", "name", e.Dashboard, "graphs", medianGraph != "" && ratioGraph != "")
	return nil
}

// --- helpers ---

// trapperHosts is the "Allowed hosts" value set on every trapper item and LLD
// rule. Empty config means accept from any host — but on Zabbix 8.0 an empty
// string means the opposite (reject everyone), so we materialise "any" as the
// all-addresses CIDRs, which behave as accept-any on 6.0/7.0/7.4/8.0 alike.
func (p *Provisioner) trapperHosts() string {
	if p.cfg.Zabbix.TrapperHosts != "" {
		return p.cfg.Zabbix.TrapperHosts
	}
	return acceptAnyTrapperHosts
}

// objectState is one Zabbix object as returned by a *.get with output=extend.
// Provision compares only the handful of fields it owns, so a raw map avoids
// version-specific structs (item "timeout", for instance, exists only on 7.0+).
type objectState map[string]json.RawMessage

// str returns a field as a string ("" when absent). The API renders every scalar
// as a string, so this is what comparisons run on.
func (o objectState) str(field string) string {
	raw, ok := o[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// count returns the length of an array field (0 when absent or not an array).
func (o objectState) count(field string) int {
	raw, ok := o[field]
	if !ok {
		return 0
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return 0
	}
	return len(rows)
}

// fetch runs a *.get and decodes its rows.
func (p *Provisioner) fetch(ctx context.Context, method string, params map[string]interface{}) ([]objectState, error) {
	res, err := p.c.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	var rows []objectState
	if err := json.Unmarshal(res, &rows); err != nil {
		return nil, nil // non-array result: treat as absent
	}
	return rows, nil
}

// fetchByKey indexes the result of a *.get by the objects' key_.
func (p *Provisioner) fetchByKey(ctx context.Context, method string, params map[string]interface{}) (map[string]objectState, error) {
	rows, err := p.fetch(ctx, method, params)
	if err != nil {
		return nil, err
	}
	m := make(map[string]objectState, len(rows))
	for _, r := range rows {
		m[r.str("key_")] = r
	}
	return m, nil
}

// drift returns the subset of want whose value differs from the object's current
// one — the update payload needed to bring an existing object back in line.
func drift(cur objectState, want map[string]interface{}) map[string]interface{} {
	d := make(map[string]interface{}, len(want))
	for k, v := range want {
		if cur.str(k) != fmt.Sprintf("%v", v) {
			d[k] = v
		}
	}
	return d
}

// changedFields lists an update payload's field names (minus the object id) for
// logging, so the operator can see what re-provisioning actually touched.
func changedFields(upd map[string]interface{}) []string {
	names := make([]string, 0, len(upd))
	for k := range upd {
		if strings.HasSuffix(k, "id") {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (p *Provisioner) hostID(ctx context.Context, host string) (string, error) {
	return p.getID(ctx, "host.get", map[string]interface{}{
		"filter": map[string]interface{}{"host": host},
		"output": []string{"hostid"},
	}, "hostid")
}

// existing returns the id of an object that already exists (by field=value), or
// "" if none. Provision uses it to stay idempotent — callers skip or update
// instead of blindly *.create-ing and failing on a duplicate name (F6).
func (p *Provisioner) existing(ctx context.Context, obj, field, value string) (string, error) {
	return p.getID(ctx, obj+".get", map[string]interface{}{
		"filter": map[string]interface{}{field: value},
		"output": []string{obj + "id"},
	}, obj+"id")
}

func (p *Provisioner) getID(ctx context.Context, method string, params interface{}, idField string) (string, error) {
	res, err := p.c.Call(ctx, method, params)
	if err != nil {
		return "", err
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(res, &rows); err != nil {
		return "", nil // non-array result: treat as absent
	}
	if len(rows) == 0 {
		return "", nil
	}
	var id string
	if raw, ok := rows[0][idField]; ok {
		_ = json.Unmarshal(raw, &id)
	}
	return id, nil
}

// firstID extracts the first id from a create response like {"hostids":["42"]}.
func firstID(res json.RawMessage, field string) (string, error) {
	var m map[string][]string
	if err := json.Unmarshal(res, &m); err != nil {
		return "", fmt.Errorf("parse %s: %w", field, err)
	}
	ids := m[field]
	if len(ids) == 0 {
		return "", fmt.Errorf("no %s in response", field)
	}
	return ids[0], nil
}
