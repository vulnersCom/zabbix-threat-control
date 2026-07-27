// Package aggregate turns per-host audit results into the Zabbix trapper items
// and low-level-discovery payloads pushed via zabbix-sender. It is a port of
// scan.py's write_score_data / write_packages_data / write_bulletins_data /
// write_cvss_and_aggregation_data.
package aggregate

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
)

// Entities carries the virtual host names the data is addressed to.
type Entities struct {
	HostsHost      string
	PackagesHost   string
	BulletinsHost  string
	StatisticsHost string
}

// Item is a single value destined for zabbix-sender.
type Item struct {
	Host  string
	Key   string
	Value string
}

// Result holds the two batches sent to Zabbix: discovery first, then values.
type Result struct {
	LLD  []Item
	Data []Item
}

// Build produces the complete sender payload from host results.
func Build(results []model.HostResult, ent Entities) Result {
	var out Result
	buildHosts(&out, results, ent)
	buildPackages(&out, results, ent)
	buildBulletins(&out, results, ent)
	buildStatistics(&out, results, ent)
	return out
}

func buildHosts(out *Result, results []model.HostResult, ent Entities) {
	discovery := make([]map[string]interface{}, 0, len(results))
	for _, r := range results {
		out.Data = append(out.Data, Item{
			Host:  ent.HostsHost,
			Key:   fmt.Sprintf("vulners.hosts[%s]", r.Host.HostID),
			Value: formatScore(r.Score),
		})
		discovery = append(discovery, map[string]interface{}{
			"{#H.VNAME}": r.Host.Name,
			"{#H.HOST}":  r.Host.Host,
			"{#H.ID}":    r.Host.HostID,
			"{#H.FIX}":   r.CumulativeFix,
			"{#H.SCORE}": r.Score,
		})
	}
	out.LLD = append(out.LLD, Item{
		Host:  ent.HostsHost,
		Key:   "vulners.hosts_lld",
		Value: discoveryJSON(discovery),
	})
}

// buildPackages emits one discovery entity per (package, host) pair so each
// vulnerable package on each host becomes its own problem, tagged with exactly
// that host (vulners.host = {#PKG.HOST}).
func buildPackages(out *Result, results []model.HostResult, ent Entities) {
	seen := map[string]bool{}
	var discovery []map[string]interface{}
	for _, r := range results {
		for _, p := range r.Packages {
			key := p.Name + "\x00" + r.Host.HostID
			if seen[key] {
				continue
			}
			seen[key] = true
			out.Data = append(out.Data, Item{
				Host:  ent.PackagesHost,
				Key:   fmt.Sprintf("vulners.packages[%s,%s]", p.Name, r.Host.HostID),
				Value: "1",
			})
			discovery = append(discovery, map[string]interface{}{
				"{#PKG.ID}":     p.Name,
				"{#PKG.URL}":    p.BulletinID,
				"{#PKG.SCORE}":  p.Score,
				"{#PKG.FIX}":    p.Fix,
				"{#PKG.HOST}":   r.Host.Name,
				"{#PKG.HOSTID}": r.Host.HostID,
			})
		}
	}
	out.LLD = append(out.LLD, Item{
		Host:  ent.PackagesHost,
		Key:   "vulners.packages_lld",
		Value: discoveryJSON(discovery),
	})
}

// buildBulletins emits one discovery entity per (bulletin, host) pair so each
// advisory on each host becomes its own problem, tagged with exactly that host
// (vulners.host = {#BULLETIN.HOST}).
func buildBulletins(out *Result, results []model.HostResult, ent Entities) {
	seen := map[string]bool{}
	var discovery []map[string]interface{}
	for _, r := range results {
		for _, b := range r.Bulletins {
			key := b.Name + "\x00" + r.Host.HostID
			if seen[key] {
				continue
			}
			seen[key] = true
			out.Data = append(out.Data, Item{
				Host:  ent.BulletinsHost,
				Key:   fmt.Sprintf("vulners.bulletins[%s,%s]", b.Name, r.Host.HostID),
				Value: "1",
			})
			discovery = append(discovery, map[string]interface{}{
				"{#BULLETIN.ID}":     b.Name,
				"{#BULLETIN.SCORE}":  b.Score,
				"{#BULLETIN.HOST}":   r.Host.Name,
				"{#BULLETIN.HOSTID}": r.Host.HostID,
			})
		}
	}
	out.LLD = append(out.LLD, Item{
		Host:  ent.BulletinsHost,
		Key:   "vulners.bulletins_lld",
		Value: discoveryJSON(discovery),
	})
}

func buildStatistics(out *Result, results []model.HostResult, ent Entities) {
	scores := make([]float64, 0, len(results))
	histogram := make([]int, 11) // buckets 0..10
	for _, r := range results {
		scores = append(scores, r.Score)
		bucket := int(r.Score)
		if bucket < 0 {
			bucket = 0
		}
		if bucket > 10 {
			bucket = 10
		}
		histogram[bucket]++
	}

	for i := 0; i <= 10; i++ {
		out.Data = append(out.Data, Item{
			Host:  ent.StatisticsHost,
			Key:   fmt.Sprintf("vulners.hostsCountScore%d", i),
			Value: fmt.Sprintf("%d", histogram[i]),
		})
	}

	stat := func(key, value string) {
		out.Data = append(out.Data, Item{Host: ent.StatisticsHost, Key: key, Value: value})
	}
	stat("vulners.TotalHosts", fmt.Sprintf("%d", len(results)))
	stat("vulners.scoreMedian", formatScore(median(scores)))
	stat("vulners.scoreAverage", formatScore(mean(scores)))
	stat("vulners.scoreMaximum", formatScore(max(scores)))
	stat("vulners.scoreMinimum", formatScore(min(scores)))
}

// --- helpers ---

func discoveryJSON(data []map[string]interface{}) string {
	b, err := json.Marshal(map[string]interface{}{"data": data})
	if err != nil {
		return `{"data":[]}`
	}
	return string(b)
}

func formatScore(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%d", int(f))
	}
	return fmt.Sprintf("%g", f)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func max(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := v[0]
	for _, x := range v[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func min(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := v[0]
	for _, x := range v[1:] {
		if x < m {
			m = x
		}
	}
	return m
}
