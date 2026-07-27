// Package collect reads the raw inventory the zabbix-agent2 UserParameter items
// gathered on each host and turns it into model.Host values ready for auditing.
// It replaces scan.py's create_hosts_matrix / update_with_zabbix_data.
package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

// Item keys populated by the agent-side UserParameters (see deploy/agent).
const (
	KeyOS       = "vulners.os"
	KeyVersion  = "vulners.version"
	KeyArch     = "vulners.arch"
	KeyPackages = "vulners.packages"
	KeyWinSoft  = "vulners.win.software"
	KeyWinKB    = "vulners.win.kb"
	KeyPrefix   = "vulners."
)

// Collector reads inventory from Zabbix.
type Collector struct {
	client        zabbix.Client
	templateNames []string
	limit         int
}

// New builds a Collector. templateNames are the collection templates (Linux and
// Windows); hosts linked to any of them are gathered.
func New(client zabbix.Client, templateNames []string, limit int) *Collector {
	return &Collector{client: client, templateNames: templateNames, limit: limit}
}

// Hosts returns the valid, auditable hosts linked to any collection template.
func (c *Collector) Hosts(ctx context.Context) ([]model.Host, error) {
	briefs, err := c.hostBriefs(ctx)
	if err != nil {
		return nil, err
	}

	var hosts []model.Host
	for _, b := range briefs {
		items, err := c.client.ItemsByKeySearch(ctx, b.HostID, KeyPrefix)
		if err != nil {
			return nil, fmt.Errorf("items for %q: %w", b.Name, err)
		}
		h := buildHost(b, items)
		if valid(h) {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// hostBriefs resolves every configured template and returns the union of their
// linked hosts, deduplicated by host id.
func (c *Collector) hostBriefs(ctx context.Context) ([]zabbix.HostBrief, error) {
	seen := map[string]bool{}
	var out []zabbix.HostBrief
	var resolved int
	for _, name := range c.templateNames {
		if name == "" {
			continue
		}
		templateID, err := c.client.TemplateID(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("resolve template %q: %w", name, err)
		}
		if templateID == "" {
			continue // template not provisioned; skip
		}
		resolved++
		briefs, err := c.client.HostsByTemplate(ctx, templateID, c.limit)
		if err != nil {
			return nil, fmt.Errorf("list hosts for %q: %w", name, err)
		}
		for _, b := range briefs {
			if !seen[b.HostID] {
				seen[b.HostID] = true
				out = append(out, b)
			}
		}
	}
	if resolved == 0 {
		return nil, fmt.Errorf("no collection template found (%v); run `ztc provision --template`", c.templateNames)
	}
	return out, nil
}

// buildHost maps item last values onto a model.Host and detects the platform.
func buildHost(b zabbix.HostBrief, items []zabbix.ItemBrief) model.Host {
	values := make(map[string]string, len(items))
	for _, it := range items {
		values[itemKeyBase(it.Key)] = it.LastValue
	}

	h := model.Host{
		HostID:    b.HostID,
		Host:      b.Host,
		Name:      b.Name,
		OSName:    normalizeOSName(values[KeyOS]),
		OSVersion: values[KeyVersion],
		OSArch:    values[KeyArch],
	}
	h.Packages = nonEmptyLines(values[KeyPackages])
	h.Software = nonEmptyLines(values[KeyWinSoft])
	h.KBList = nonEmptyLines(values[KeyWinKB])

	if len(h.Software) > 0 || len(h.KBList) > 0 {
		h.Platform = model.PlatformWindows
	} else {
		h.Platform = model.PlatformLinux
	}
	return h
}

// valid ports verify_os_data: a host must carry enough inventory to audit.
func valid(h model.Host) bool {
	switch h.Platform {
	case model.PlatformWindows:
		return len(h.Software) > 0 || len(h.KBList) > 0
	default:
		return h.OSName != "" && h.OSVersion != "" && h.OSVersion != "0.0" && len(h.Packages) > 5
	}
}

// itemKeyBase strips any [params] suffix from an item key.
func itemKeyBase(key string) string {
	if i := strings.IndexByte(key, '['); i >= 0 {
		return key[:i]
	}
	return key
}

// normalizeOSName aligns agent-reported names with Vulners expectations.
func normalizeOSName(name string) string {
	name = strings.TrimSpace(name)
	if name == "ol" {
		return "oraclelinux"
	}
	return name
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
