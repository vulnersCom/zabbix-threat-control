// Package provision creates the Zabbix entities the scanner writes into: the
// collection template, the four virtual hosts (Hosts/Bulletins/Packages/
// Statistics) with their LLD rules, prototypes and triggers, and the dashboard.
// It is a port of prepare.py targeting the Zabbix 7.x API.
package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

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
	if err := p.backupIfExists(ctx, "template", "host", host); err != nil {
		return err
	}
	res, err := p.c.Call(ctx, "template.create", map[string]interface{}{
		"host":   host,
		"name":   name,
		"groups": []map[string]string{{"groupid": groupID}},
	})
	if err != nil {
		return err
	}
	templateID, err := firstID(res, "templateids")
	if err != nil {
		return err
	}
	for _, it := range items {
		params := map[string]interface{}{
			"name":       it.name,
			"key_":       it.key,
			"hostid":     templateID,
			"type":       0, // Zabbix agent
			"value_type": it.valueType,
			"delay":      "1d",
			"tags":       []map[string]string{{"tag": "vulners", "value": p.cfg.Entities.Application}},
		}
		// Per-item timeouts are a Zabbix 7.0 feature; older APIs reject the field.
		if it.timeout != "" && p.atLeast(ctx, 7, 0) {
			params["timeout"] = it.timeout
		}
		if _, err := p.c.Call(ctx, "item.create", params); err != nil {
			return fmt.Errorf("template item %q: %w", it.key, err)
		}
	}
	p.log.Info("created collection template", "name", name, "id", templateID)
	return nil
}

// --- virtual hosts ---

type vhostSpec struct {
	host, name      string
	lldKey          string
	itemProtoName   string
	itemProtoKey    string
	triggerItemExpr string // the "last(...)>0" part; severity bands append the score condition
	scoreMacro      string // LLD macro holding the CVSS score, e.g. "{#BULLETIN.SCORE}"
	triggerDesc     string
	triggerURL      string
	triggerComment  string
	triggerTags     []map[string]string // carry host/package identity into events (for fix)
}

// severityBands map CVSS score ranges [lo, hi) to Zabbix trigger priorities so
// "Problems by Severity" reflects the score. hi==0 means no upper bound. A
// prototype is created per band; only the one whose constant score condition
// holds ever fires for a given discovered entity.
var severityBands = []struct {
	label    string
	priority int
	lo, hi   float64
}{
	{"Disaster", 5, 9, 0},
	{"High", 4, 7, 9},
	{"Average", 3, 4, 7},
	{"Warning", 2, 0, 4},
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
	if err := p.backupIfExists(ctx, "host", "host", s.host); err != nil {
		return err
	}
	hostID, err := p.createBareHost(ctx, s.host, s.name, groupID, true)
	if err != nil {
		return err
	}

	res, err := p.c.Call(ctx, "discoveryrule.create", map[string]interface{}{
		"type":          2, // trapper
		"hostid":        hostID,
		"name":          s.name,
		"key_":          s.lldKey,
		"lifetime":      "0",
		"trapper_hosts": p.trapperHosts(), // explicit: Zabbix 8.0 else defaults to 127.0.0.1,::1 and drops sender data
	})
	if err != nil {
		return fmt.Errorf("discovery rule: %w", err)
	}
	lldID, err := firstID(res, "itemids")
	if err != nil {
		return err
	}

	if _, err := p.c.Call(ctx, "itemprototype.create", map[string]interface{}{
		"hostid":        hostID,
		"ruleid":        lldID,
		"name":          s.itemProtoName,
		"key_":          s.itemProtoKey,
		"type":          2, // trapper
		"value_type":    0, // float
		"trapper_hosts": p.trapperHosts(),
	}); err != nil {
		return fmt.Errorf("item prototype: %w", err)
	}

	for _, b := range severityBands {
		cond := fmt.Sprintf("%s>=%g", s.scoreMacro, b.lo)
		if b.hi > 0 {
			cond += fmt.Sprintf(" and %s<%g", s.scoreMacro, b.hi)
		}
		trigger := map[string]interface{}{
			"expression":   fmt.Sprintf("%s and %s>={$SCORE.MIN} and %s", s.triggerItemExpr, s.scoreMacro, cond),
			"description":  fmt.Sprintf("[%s] %s", b.label, s.triggerDesc),
			"manual_close": 1,
			"priority":     b.priority,
			"comments":     s.triggerComment,
		}
		if s.triggerURL != "" {
			trigger["url"] = s.triggerURL
		}
		if len(s.triggerTags) > 0 {
			trigger["tags"] = s.triggerTags
		}
		if _, err := p.c.Call(ctx, "triggerprototype.create", trigger); err != nil {
			return fmt.Errorf("trigger prototype [%s]: %w", b.label, err)
		}
	}
	p.log.Info("created virtual host", "name", s.name, "id", hostID)
	return nil
}

func (p *Provisioner) createStatisticsHost(ctx context.Context, groupID string) error {
	e := p.cfg.Entities
	if err := p.backupIfExists(ctx, "host", "host", e.StatisticsHost); err != nil {
		return err
	}
	hostID, err := p.createBareHost(ctx, e.StatisticsHost, e.StatisticsName, groupID, false)
	if err != nil {
		return err
	}

	trapper := func(name, key string, valueType int) error {
		_, err := p.c.Call(ctx, "item.create", map[string]interface{}{
			"name":          name,
			"key_":          key,
			"hostid":        hostID,
			"type":          2, // trapper
			"value_type":    valueType,
			"trapper_hosts": p.trapperHosts(),
			"tags":          []map[string]string{{"tag": "vulners", "value": e.Application}},
		})
		return err
	}
	for _, s := range []struct{ name, key string }{
		{"CVSS Score - Total Hosts", "vulners.TotalHosts"},
		{"CVSS Score - Maximum", "vulners.scoreMaximum"},
		{"CVSS Score - Average", "vulners.scoreAverage"},
		{"CVSS Score - Minimum", "vulners.scoreMinimum"},
	} {
		if err := trapper(s.name, s.key, 3); err != nil {
			return err
		}
	}
	if err := trapper("CVSS Score - Median", "vulners.scoreMedian", 0); err != nil {
		return err
	}
	for i := 0; i <= 10; i++ {
		if err := trapper(fmt.Sprintf("CVSS Score - Hosts with a score ~ %d", i), fmt.Sprintf("vulners.hostsCountScore%d", i), 3); err != nil {
			return err
		}
	}
	p.log.Info("created statistics host", "name", e.StatisticsName, "id", hostID)
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
		params["macros"] = []map[string]string{{"macro": "{$SCORE.MIN}", "value": fmt.Sprintf("%g", p.cfg.MinCVSS)}}
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
	problems := func(name, hostID string, x, y int) map[string]interface{} {
		return map[string]interface{}{
			"type": "problems", "name": name, "x": x, "y": y, "width": 12, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "show_lines", "value": 100},
				{"type": 3, "name": "hostids.0", "value": hostID},
			},
		}
	}
	graphWidget := func(name, graphID string, x, y int) map[string]interface{} {
		return map[string]interface{}{
			"type": "graph", "name": name, "x": x, "y": y, "width": 12, "height": 8,
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
			"type": "problemsbysv", "name": "Problems by severity", "x": 0, "y": 0, "width": 24, "height": 4,
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

	if err := p.backupIfExists(ctx, "dashboard", "name", e.Dashboard); err != nil {
		return err
	}
	_, err := p.c.Call(ctx, "dashboard.create", map[string]interface{}{
		"name":    e.Dashboard,
		"private": 0,
		"pages":   []map[string]interface{}{{"widgets": widgets}},
	})
	if err != nil {
		return err
	}
	p.log.Info("created dashboard", "name", e.Dashboard, "graphs", medianGraph != "" && ratioGraph != "")
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
	return "0.0.0.0/0,::/0"
}

func (p *Provisioner) hostID(ctx context.Context, host string) (string, error) {
	return p.getID(ctx, "host.get", map[string]interface{}{
		"filter": map[string]interface{}{"host": host},
		"output": []string{"hostid"},
	}, "hostid")
}

// backupIfExists renames+disables an existing object so re-provisioning is safe,
// mirroring prepare.py's .bkp behaviour (best-effort; only rename is attempted).
func (p *Provisioner) backupIfExists(ctx context.Context, obj, field, value string) error {
	id, err := p.getID(ctx, obj+".get", map[string]interface{}{
		"filter": map[string]interface{}{field: value},
		"output": []string{obj + "id"},
	}, obj+"id")
	if err != nil || id == "" {
		return err
	}
	p.log.Warn("object already exists, leaving as-is (manual cleanup recommended)", "type", obj, field, value, "id", id)
	return nil
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
