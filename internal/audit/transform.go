package audit

import (
	"fmt"
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
	packages  map[string]model.Package  // keyed by package name, worst finding wins
	bulletins map[string]model.Bulletin // bulletin id -> worst finding for it
	fixes     []string                  // unique remediation commands, insertion order
	fixSeen   map[string]bool
	maxScore  float64
	worst     model.Exploitation
}

func newBuilder(h model.Host) *builder {
	return &builder{
		host:      h,
		packages:  make(map[string]model.Package),
		bulletins: make(map[string]model.Bulletin),
		fixSeen:   make(map[string]bool),
	}
}

// add records one finding: a vulnerable package, the bulletin id it matched, the
// remediation command and how exploited the underlying CVEs are.
//
// "Worst" means exploitation first and score second, so an actively exploited
// finding represents its package even when something else scores higher. That is
// the whole point of carrying the axis: the highest CVSS is rarely the thing to
// fix first.
func (b *builder) add(pkgName, bulletinID, fix string, score float64, expl model.Exploitation) {
	if bulletinID == "" {
		return
	}
	if score > b.maxScore {
		b.maxScore = score
	}
	b.worst = b.worst.Worse(expl)

	if existing, ok := b.bulletins[bulletinID]; !ok || worseFinding(score, expl, existing.Score, existing.Exploitation) {
		b.bulletins[bulletinID] = model.Bulletin{Name: bulletinID, Score: score, Exploitation: expl}
	}
	if pkgName != "" {
		if p, ok := b.packages[pkgName]; !ok || worseFinding(score, expl, p.Score, p.Exploitation) {
			b.packages[pkgName] = model.Package{
				Name:         pkgName,
				Score:        score,
				BulletinID:   bulletinID,
				Fix:          fix,
				Exploitation: expl,
			}
		}
	}
	if fix != "" && !b.fixSeen[fix] {
		b.fixSeen[fix] = true
		b.fixes = append(b.fixes, fix)
	}
}

// worseFinding reports whether the first finding outranks the second: exploited
// beats merely high-scoring, and score breaks the tie.
func worseFinding(score float64, expl model.Exploitation, otherScore float64, otherExpl model.Exploitation) bool {
	if r, o := expl.Rank(), otherExpl.Rank(); r != o {
		return r > o
	}
	return score > otherScore
}

// result finalises the accumulated findings into a HostResult with stable
// ordering (packages and bulletins sorted by name) for deterministic output.
func (b *builder) result() model.HostResult {
	packages := make([]model.Package, 0, len(b.packages))
	active := 0
	for _, p := range b.packages {
		packages = append(packages, p)
		if p.Exploitation == model.ExploitationActive {
			active++
		}
	}
	// Worst first, so the top of the list is what to do next. Name breaks
	// remaining ties, which keeps the order stable between runs - Zabbix
	// discovery would otherwise churn on nothing.
	sort.Slice(packages, func(i, j int) bool {
		if worseFinding(packages[i].Score, packages[i].Exploitation,
			packages[j].Score, packages[j].Exploitation) {
			return true
		}
		if worseFinding(packages[j].Score, packages[j].Exploitation,
			packages[i].Score, packages[i].Exploitation) {
			return false
		}
		return packages[i].Name < packages[j].Name
	})

	bulletins := make([]model.Bulletin, 0, len(b.bulletins))
	for _, bulletin := range b.bulletins {
		bulletins = append(bulletins, bulletin)
	}
	sort.Slice(bulletins, func(i, j int) bool {
		if worseFinding(bulletins[i].Score, bulletins[i].Exploitation,
			bulletins[j].Score, bulletins[j].Exploitation) {
			return true
		}
		if worseFinding(bulletins[j].Score, bulletins[j].Exploitation,
			bulletins[i].Score, bulletins[i].Exploitation) {
			return false
		}
		return bulletins[i].Name < bulletins[j].Name
	})

	return model.HostResult{
		Host:              b.host,
		Score:             b.maxScore,
		CumulativeFix:     strings.Join(b.fixes, "; "),
		Packages:          packages,
		Bulletins:         bulletins,
		Exploitation:      b.worst,
		ActivelyExploited: active,
	}
}

// transformLinux converts a v4/audit/linux response into a HostResult.
func transformLinux(h model.Host, res *gv.PackageAuditResult) model.HostResult {
	b := newBuilder(h)
	if res == nil {
		return b.result()
	}
	for i := range res.Issues {
		issue := &res.Issues[i]
		fix := fixCommand(h.OSName, issue.Package)
		// Indexed rather than ranged: an advisory is a heavy struct and
		// CVEMetrics takes it by pointer.
		for j := range issue.ApplicableAdvisories {
			adv := &issue.ApplicableAdvisories[j]
			metrics, err := adv.CVEMetrics()
			if err != nil {
				metrics = nil
			}
			b.add(issue.Package, adv.ID, fix, linuxScore(adv, metrics),
				worstExploitation(metrics))
		}
	}
	return b.result()
}

// linuxScore reads the rollup the server maintains, falling back to the maximum
// across the per-CVE entries. Both answer the same question; the server-side one
// is the same number every endpoint reports for that advisory.
func linuxScore(adv *gv.AuditApplicableAdvisory, metrics []gv.CVEListMetric) float64 {
	if adv.Metrics != nil && adv.Metrics.CVSS != nil {
		return adv.Metrics.CVSS.Score
	}
	score, _ := gv.MaxCVSS(metrics)
	return score
}

// transformWindows merges the smart (registry software) and KB audit responses
// into a single HostResult.
func transformWindows(h model.Host, software []gv.SmartAuditItem, kb *gv.KBAuditV4Result) model.HostResult {
	b := newBuilder(h)

	for i := range software {
		item := &software[i]
		// The endpoint derives the upgrade target from the match evidence, so a
		// Windows application finding finally carries an answer to "install what".
		fix := ""
		if item.FixedVersion != "" {
			fix = fmt.Sprintf("upgrade %s to %s", item.Input, item.FixedVersion)
		}
		for j := range item.Vulnerabilities {
			v := &item.Vulnerabilities[j]
			b.add(item.Input, v.ID, fix, advisoryScore(v), worstExploitation(v.CVEListMetrics))
		}
	}

	if kb != nil {
		for i := range kb.Items {
			item := &kb.Items[i]
			// One advisory per missing update, each naming the KB to install -
			// where the v3 endpoint gave a flat CVE list with no remediation.
			fix := ""
			if item.FixedPackage != "" {
				fix = "install " + item.FixedPackage
			}
			for j := range item.Advisories {
				adv := &item.Advisories[j]
				b.add(kbPackageName(item, adv), adv.ID, fix,
					kbScore(adv), worstExploitation(adv.CVEListMetrics))
			}
		}
	}

	return b.result()
}

// kbPackageName names the finding after the product, falling back through the
// advisory title: affectedProducts is a display label and is empty on updates
// that fix nothing.
func kbPackageName(item *gv.KBAuditIssue, adv *gv.KBAuditAdvisory) string {
	if item.Package != "" {
		return item.Package
	}
	if len(adv.AffectedProducts) > 0 {
		return adv.AffectedProducts[0]
	}
	if adv.Title != "" {
		return adv.Title
	}
	return adv.ID
}

// advisoryScore prefers the rollup the server maintains over anything recomputed
// here. ai_score is the last resort: it tops out below the high band and cannot
// express KEV, so a host scored from it reports no critical findings at all.
func advisoryScore(v *gv.SmartAuditVulnerability) float64 {
	if v.Metrics != nil && v.Metrics.CVSS != nil {
		return v.Metrics.CVSS.Score
	}
	if score, ok := gv.MaxCVSS(v.CVEListMetrics); ok {
		return score
	}
	if v.AIScore != nil {
		return v.AIScore.Value
	}
	return 0
}

func kbScore(adv *gv.KBAuditAdvisory) float64 {
	if adv.Metrics != nil && adv.Metrics.CVSS != nil {
		return adv.Metrics.CVSS.Score
	}
	score, _ := gv.MaxCVSS(adv.CVEListMetrics)
	return score
}

// worstExploitation reduces an advisory's per-CVE entries to the most serious
// SSVC decision among them. An advisory is as exploited as its worst CVE.
func worstExploitation(metrics []gv.CVEListMetric) model.Exploitation {
	worst := model.ExploitationUnknown
	for i := range metrics {
		worst = worst.Worse(model.Exploitation(metrics[i].SSVC.Exploitation()))
	}
	return worst
}
