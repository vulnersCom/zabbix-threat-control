package fix

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
	"github.com/vulnersCom/zabbix-threat-control/internal/model"
)

// AutoRemediate fixes vulnerabilities whose Zabbix problem has been acknowledged
// by a trusted user. It reads open problems on the Hosts and Packages virtual
// hosts, matches them to fresh audit results via event tags, and applies fixes.
func (f *Fixer) AutoRemediate(ctx context.Context, results []model.HostResult, ent config.Entities) (applied, failed int, err error) {
	if len(f.cfg.TrustedUsers) == 0 {
		return 0, 0, fmt.Errorf("auto-fix requires fix.trusted_users to be configured")
	}
	trusted, err := f.trustedUserIDs(ctx)
	if err != nil {
		return 0, 0, err
	}
	if len(trusted) == 0 {
		return 0, 0, fmt.Errorf("none of fix.trusted_users resolved to Zabbix users")
	}

	vhostIDs, err := f.hostIDs(ctx, ent.HostsHost, ent.PackagesHost)
	if err != nil {
		return 0, 0, err
	}
	problems, err := f.acknowledgedProblems(ctx, vhostIDs, trusted)
	if err != nil {
		return 0, 0, err
	}

	targets := f.targetsFromProblems(problems, results)
	if len(targets) == 0 {
		f.log.Info("auto-fix: no acknowledged problems to remediate")
		return 0, 0, nil
	}
	applied, failed = f.Apply(ctx, targets)
	return applied, failed, nil
}

type problem struct {
	Tags         []struct{ Tag, Value string }
	Acknowledges []struct {
		UserID string `json:"userid"`
		Action string `json:"action"`
	}
	REventID string `json:"r_eventid"`
}

func (f *Fixer) trustedUserIDs(ctx context.Context) (map[string]bool, error) {
	res, err := f.zbx.Call(ctx, "user.get", map[string]interface{}{
		"filter": map[string]interface{}{"username": f.cfg.TrustedUsers},
		"output": []string{"userid"},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		UserID string `json:"userid"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(rows))
	for _, r := range rows {
		ids[r.UserID] = true
	}
	return ids, nil
}

func (f *Fixer) hostIDs(ctx context.Context, hosts ...string) ([]string, error) {
	res, err := f.zbx.Call(ctx, "host.get", map[string]interface{}{
		"filter": map[string]interface{}{"host": hosts},
		"output": []string{"hostid"},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		HostID string `json:"hostid"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return nil, err
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.HostID
	}
	return ids, nil
}

func (f *Fixer) acknowledgedProblems(ctx context.Context, hostIDs []string, trusted map[string]bool) ([]problem, error) {
	res, err := f.zbx.Call(ctx, "problem.get", map[string]interface{}{
		"hostids":            hostIDs,
		"acknowledged":       true,
		"recent":             false,
		"selectAcknowledges": []string{"userid", "action"},
		"selectTags":         "extend",
		"output":             []string{"eventid", "r_eventid"},
	})
	if err != nil {
		return nil, err
	}
	var all []problem
	if err := json.Unmarshal(res, &all); err != nil {
		return nil, err
	}
	var eligible []problem
	for _, p := range all {
		if p.REventID != "" && p.REventID != "0" {
			continue // already resolved
		}
		if ackedByTrusted(p, trusted) {
			eligible = append(eligible, p)
		}
	}
	return eligible, nil
}

// ackedByTrusted reports whether a trusted user acknowledged the problem with an
// action that is not a manual close (close bit = 1).
func ackedByTrusted(p problem, trusted map[string]bool) bool {
	for _, a := range p.Acknowledges {
		if !trusted[a.UserID] {
			continue
		}
		if a.Action == "1" { // pure manual close
			continue
		}
		return true
	}
	return false
}

// targetsFromProblems maps acknowledged problems (via their vulners.target /
// vulners.package tags) to remediation targets built from fresh audit results.
func (f *Fixer) targetsFromProblems(problems []problem, results []model.HostResult) []Target {
	byHost := map[string]Target{}
	add := func(t Target) {
		if len(t.Packages) == 0 {
			return
		}
		if existing, ok := byHost[t.HostID]; ok {
			existing.Packages = mergeUnique(existing.Packages, t.Packages)
			byHost[t.HostID] = existing
		} else {
			byHost[t.HostID] = t
		}
	}

	for _, p := range problems {
		for _, tag := range p.Tags {
			switch tag.Tag {
			case "vulners.target":
				if r, ok := FindHost(results, tag.Value); ok {
					add(TargetForHost(r))
				}
			case "vulners.package":
				for _, t := range TargetsForPackage(results, managerName(tag.Value)) {
					add(t)
				}
			}
		}
	}

	targets := make([]Target, 0, len(byHost))
	for _, t := range byHost {
		targets = append(targets, t)
	}
	return targets
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			seen[x] = true
			a = append(a, x)
		}
	}
	return a
}
