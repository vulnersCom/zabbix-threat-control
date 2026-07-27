package audit

import (
	"sort"
	"strings"

	gv "github.com/kidoz/go-vulners"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
)

// builder accumulates per-host findings from one or more audit responses and
// produces a model.HostResult. It mirrors the aggregation scan.py did inline in
// write_score_data.
type builder struct {
	host      model.Host
	packages  map[string]model.Package // keyed by package name, highest score wins
	bulletins map[string]float64       // bulletin id -> score
	fixes     []string                 // unique remediation commands, insertion order
	fixSeen   map[string]bool
	maxScore  float64
}

func newBuilder(h model.Host) *builder {
	return &builder{
		host:      h,
		packages:  make(map[string]model.Package),
		bulletins: make(map[string]float64),
		fixSeen:   make(map[string]bool),
	}
}

// add records one finding: a vulnerable package, the bulletin id it matched and
// the remediation command.
func (b *builder) add(pkgName, bulletinID, fix string, score float64) {
	if bulletinID == "" {
		return
	}
	if score > b.maxScore {
		b.maxScore = score
	}
	if s, ok := b.bulletins[bulletinID]; !ok || score > s {
		b.bulletins[bulletinID] = score
	}
	if pkgName != "" {
		if p, ok := b.packages[pkgName]; !ok || score > p.Score {
			b.packages[pkgName] = model.Package{
				Name:       pkgName,
				Score:      score,
				BulletinID: bulletinID,
				Fix:        fix,
			}
		}
	}
	if fix != "" && !b.fixSeen[fix] {
		b.fixSeen[fix] = true
		b.fixes = append(b.fixes, fix)
	}
}

// result finalises the accumulated findings into a HostResult with stable
// ordering (packages and bulletins sorted by name) for deterministic output.
func (b *builder) result() model.HostResult {
	packages := make([]model.Package, 0, len(b.packages))
	for _, p := range b.packages {
		packages = append(packages, p)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })

	bulletins := make([]model.Bulletin, 0, len(b.bulletins))
	for name, score := range b.bulletins {
		bulletins = append(bulletins, model.Bulletin{Name: name, Score: score})
	}
	sort.Slice(bulletins, func(i, j int) bool { return bulletins[i].Name < bulletins[j].Name })

	return model.HostResult{
		Host:          b.host,
		Score:         b.maxScore,
		CumulativeFix: strings.Join(b.fixes, "; "),
		Packages:      packages,
		Bulletins:     bulletins,
	}
}

// transformLinux converts a v4/audit/linux response into a HostResult.
func transformLinux(h model.Host, res *gv.PackageAuditResult) model.HostResult {
	b := newBuilder(h)
	if res != nil {
		for _, issue := range res.Issues {
			fix := fixCommand(h.OSName, issue.Package)
			for _, adv := range issue.ApplicableAdvisories {
				score := maxScoreFromMetrics(adv.CVEListMetrics)
				b.add(issue.Package, adv.ID, fix, score)
			}
		}
	}
	return b.result()
}

// transformWindows merges the smart (registry software) and KB audit responses
// into a single HostResult.
func transformWindows(h model.Host, software []gv.SmartAuditItem, kb *gv.AuditResult) model.HostResult {
	b := newBuilder(h)

	for _, item := range software {
		fix := "" // no automated remediation for Windows applications
		for _, v := range item.Vulnerabilities {
			score := 0.0
			if v.AIScore != nil {
				score = v.AIScore.Value
			}
			b.add(item.Input, v.ID, fix, score)
		}
	}

	if kb != nil {
		for _, v := range kb.Vulnerabilities {
			pkg := v.Package
			if pkg == "" {
				pkg = v.BulletinID
			}
			score := 0.0
			if v.CVSS != nil {
				score = v.CVSS.Score
			}
			b.add(pkg, v.BulletinID, v.Fix, score)
		}
	}

	return b.result()
}

// maxScoreFromMetrics extracts the highest CVSS base score from the
// cvelistMetrics blob attached to an advisory (see audit_service _tools.py:
// each entry carries a "cvss" object with a numeric "score").
func maxScoreFromMetrics(metrics []map[string]interface{}) float64 {
	var max float64
	for _, m := range metrics {
		if s, ok := scoreFromCVSSField(m["cvss"]); ok && s > max {
			max = s
		}
		if s, ok := scoreFromCVSSField(m["cvss3"]); ok && s > max {
			max = s
		}
	}
	return max
}

func scoreFromCVSSField(v interface{}) (float64, bool) {
	obj, ok := v.(map[string]interface{})
	if !ok {
		return 0, false
	}
	switch s := obj["score"].(type) {
	case float64:
		return s, true
	case int:
		return float64(s), true
	}
	return 0, false
}
