// Package fix performs remediation: it invokes the whitelisted vulners.fix[<pkg>]
// UserParameter on a target host's zabbix-agent2 to upgrade a vulnerable package.
// See docs/adr/0001-remediation-mechanism.md for the design rationale.
package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/zabbix"
)

// AgentGetter invokes an item key on a host's passive agent (implemented by
// zabbix/agentget.Client).
type AgentGetter interface {
	Get(ctx context.Context, addr, key string) (string, error)
}

// Target is a host and the package-manager package names to upgrade on it.
type Target struct {
	HostID   string
	Name     string
	Packages []string
}

// Fixer applies remediation to hosts.
type Fixer struct {
	zbx    zabbix.Client
	getter AgentGetter
	cfg    config.Fix
	log    *slog.Logger
}

// New builds a Fixer.
func New(zbx zabbix.Client, getter AgentGetter, cfg config.Fix, log *slog.Logger) *Fixer {
	return &Fixer{zbx: zbx, getter: getter, cfg: cfg, log: log}
}

// Apply remediates every package on every target. It is best-effort: a failure
// on one package is logged and does not stop the rest. Returns counts.
func (f *Fixer) Apply(ctx context.Context, targets []Target) (applied, failed int) {
	for _, t := range targets {
		addr, err := f.agentAddr(ctx, t.HostID)
		if err != nil {
			f.log.Error("cannot resolve agent address, skipping host", "host", t.Name, "err", err)
			failed += len(t.Packages)
			continue
		}
		for _, pkg := range t.Packages {
			key := fmt.Sprintf("%s[%s]", f.cfg.Key, pkg)
			out, err := f.getter.Get(ctx, addr, key)
			if err != nil {
				f.log.Error("fix failed", "host", t.Name, "package", pkg, "key", key, "err", err)
				failed++
				continue
			}
			f.log.Info("fix triggered", "host", t.Name, "package", pkg, "response", out)
			applied++
		}
	}
	return applied, failed
}

// TargetForHost builds a whole-host Target (cumulative fix) from an audit result.
func TargetForHost(r model.HostResult) Target {
	seen := map[string]bool{}
	var pkgs []string
	for _, p := range r.Packages {
		name := managerName(p.Name)
		if name != "" && !seen[name] {
			seen[name] = true
			pkgs = append(pkgs, name)
		}
	}
	return Target{HostID: r.Host.HostID, Name: r.Host.Name, Packages: pkgs}
}

// TargetsForPackage builds one single-package Target per host whose audit result
// contains the given package (by manager name).
func TargetsForPackage(results []model.HostResult, pkg string) []Target {
	var targets []Target
	for _, r := range results {
		for _, p := range r.Packages {
			if managerName(p.Name) == pkg {
				targets = append(targets, Target{HostID: r.Host.HostID, Name: r.Host.Name, Packages: []string{pkg}})
				break
			}
		}
	}
	return targets
}

// FindHost returns the audit result for a host by its visible name.
func FindHost(results []model.HostResult, name string) (model.HostResult, bool) {
	for _, r := range results {
		if r.Host.Name == name {
			return r, true
		}
	}
	return model.HostResult{}, false
}

// apkNVR matches the trailing "-<version>-r<release>" of an Alpine apk package
// listing (e.g. "busybox-1.37.0-r31"), which has no spaces to split on.
var apkNVR = regexp.MustCompile(`-[^-\s]+-r[0-9]+$`)

// managerName reduces a raw package string to the bare name passed to
// vulners.fix[...]. deb/rpm audit output is space-separated ("openssl 3.0.2
// amd64") so the first field is the name; Alpine apk output is hyphen-joined
// ("busybox-1.37.0-r31") so the version/release tail is stripped instead.
func managerName(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	name := fields[0]
	if len(fields) == 1 {
		if loc := apkNVR.FindStringIndex(name); loc != nil {
			name = name[:loc[0]]
		}
	}
	return name
}

// agentAddr resolves a host's main agent interface into a "host:port" address.
func (f *Fixer) agentAddr(ctx context.Context, hostID string) (string, error) {
	res, err := f.zbx.Call(ctx, "hostinterface.get", map[string]interface{}{
		"hostids": hostID,
		"filter":  map[string]interface{}{"type": 1, "main": 1},
		"output":  []string{"ip", "dns", "useip", "port"},
	})
	if err != nil {
		return "", err
	}
	var rows []struct {
		IP    string `json:"ip"`
		DNS   string `json:"dns"`
		UseIP string `json:"useip"`
		Port  string `json:"port"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("host %s has no agent interface", hostID)
	}
	r := rows[0]
	host := r.DNS
	if r.UseIP == "1" {
		host = r.IP
	}
	if host == "" {
		return "", fmt.Errorf("host %s agent interface has no address", hostID)
	}
	port := r.Port
	if port == "" {
		port = fmt.Sprintf("%d", f.cfg.AgentPort)
	}
	return fmt.Sprintf("%s:%s", host, port), nil
}
