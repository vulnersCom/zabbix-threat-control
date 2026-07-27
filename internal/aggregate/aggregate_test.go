package aggregate

import (
	"encoding/json"
	"testing"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
)

var ent = Entities{
	HostsHost:      "vulners.hosts",
	PackagesHost:   "vulners.packages",
	BulletinsHost:  "vulners.bulletins",
	StatisticsHost: "vulners.statistics",
}

func sample() []model.HostResult {
	return []model.HostResult{
		{
			Host:          model.Host{HostID: "1", Host: "h1", Name: "host-one"},
			Score:         9.8,
			CumulativeFix: "sudo apt-get upgrade bash",
			Packages: []model.Package{
				{Name: "bash", Score: 9.8, BulletinID: "USN-2", Fix: "fix bash"},
				{Name: "openssl", Score: 5.0, BulletinID: "USN-3", Fix: "fix openssl"},
			},
			Bulletins: []model.Bulletin{{Name: "USN-2", Score: 9.8}, {Name: "USN-3", Score: 5.0}},
		},
		{
			Host:          model.Host{HostID: "2", Host: "h2", Name: "host-two"},
			Score:         5.0,
			CumulativeFix: "sudo apt-get upgrade openssl",
			Packages: []model.Package{
				{Name: "openssl", Score: 5.0, BulletinID: "USN-3", Fix: "fix openssl"},
			},
			Bulletins: []model.Bulletin{{Name: "USN-3", Score: 5.0}},
		},
	}
}

func findData(items []Item, host, key string) (Item, bool) {
	for _, it := range items {
		if it.Host == host && it.Key == key {
			return it, true
		}
	}
	return Item{}, false
}

func TestBuildHostsData(t *testing.T) {
	res := Build(sample(), ent)

	it, ok := findData(res.Data, "vulners.hosts", "vulners.hosts[1]")
	if !ok || it.Value != "9.8" {
		t.Errorf("host1 score item = %+v ok=%v", it, ok)
	}
	if _, ok := findData(res.LLD, "vulners.hosts", "vulners.hosts_lld"); !ok {
		t.Error("missing hosts LLD")
	}
}

func TestBuildPackagesPerHost(t *testing.T) {
	res := Build(sample(), ent)

	// One item per (package, host) pair: openssl on both hosts, bash only host-one.
	for _, key := range []string{"vulners.packages[openssl,1]", "vulners.packages[openssl,2]", "vulners.packages[bash,1]"} {
		if it, ok := findData(res.Data, "vulners.packages", key); !ok || it.Value != "1" {
			t.Errorf("%s = %+v ok=%v, want value 1", key, it, ok)
		}
	}
	if _, ok := findData(res.Data, "vulners.packages", "vulners.packages[bash,2]"); ok {
		t.Error("bash should not have an item on host-two")
	}

	// LLD carries one row per (package, host), each with its single host + score.
	lld, _ := findData(res.LLD, "vulners.packages", "vulners.packages_lld")
	var payload struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(lld.Value), &payload); err != nil {
		t.Fatal(err)
	}
	opensslHosts := map[string]bool{}
	for _, d := range payload.Data {
		if d["{#PKG.ID}"] == "openssl" {
			opensslHosts[d["{#PKG.HOST}"].(string)] = true
			if d["{#PKG.SCORE}"].(float64) != 5.0 {
				t.Errorf("openssl score = %v, want 5", d["{#PKG.SCORE}"])
			}
		}
	}
	if !opensslHosts["host-one"] || !opensslHosts["host-two"] {
		t.Errorf("openssl LLD hosts = %v, want host-one and host-two", opensslHosts)
	}
}

func TestBuildBulletins(t *testing.T) {
	res := Build(sample(), ent)
	// USN-3 affects both hosts -> one item per (bulletin, host) pair.
	for _, key := range []string{"vulners.bulletins[USN-3,1]", "vulners.bulletins[USN-3,2]"} {
		if it, ok := findData(res.Data, "vulners.bulletins", key); !ok || it.Value != "1" {
			t.Errorf("%s = %+v ok=%v, want value 1", key, it, ok)
		}
	}
	// USN-2 only on host-one.
	if _, ok := findData(res.Data, "vulners.bulletins", "vulners.bulletins[USN-2,1]"); !ok {
		t.Error("missing vulners.bulletins[USN-2,1]")
	}
}

func TestBuildStatistics(t *testing.T) {
	res := Build(sample(), ent)

	if it, _ := findData(res.Data, "vulners.statistics", "vulners.TotalHosts"); it.Value != "2" {
		t.Errorf("total hosts = %q, want 2", it.Value)
	}
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.scoreMaximum"); it.Value != "9.8" {
		t.Errorf("max = %q, want 9.8", it.Value)
	}
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.scoreMinimum"); it.Value != "5" {
		t.Errorf("min = %q, want 5", it.Value)
	}
	// median of {9.8, 5.0} = 7.4
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.scoreMedian"); it.Value != "7.4" {
		t.Errorf("median = %q, want 7.4", it.Value)
	}
	// histogram: score 9.8 -> bucket 9, score 5.0 -> bucket 5
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.hostsCountScore9"); it.Value != "1" {
		t.Errorf("bucket9 = %q, want 1", it.Value)
	}
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.hostsCountScore5"); it.Value != "1" {
		t.Errorf("bucket5 = %q, want 1", it.Value)
	}
}

func TestBuildEmpty(t *testing.T) {
	res := Build(nil, ent)
	if it, _ := findData(res.Data, "vulners.statistics", "vulners.TotalHosts"); it.Value != "0" {
		t.Errorf("total = %q, want 0", it.Value)
	}
	// LLD payloads must still be present with empty data arrays
	if it, ok := findData(res.LLD, "vulners.hosts", "vulners.hosts_lld"); !ok || it.Value != `{"data":[]}` {
		t.Errorf("empty hosts LLD = %q ok=%v", it.Value, ok)
	}
}
