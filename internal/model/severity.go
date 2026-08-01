package model

// SeverityBand maps a CVSS score range to a Zabbix trigger priority. Shared by
// aggregate (which stamps each finding's band label into an LLD macro) and
// provision (which turns the bands into LLD override rules that set the
// discovered trigger's severity). Keeping one source of truth means the label a
// finding carries always matches the override that colours it.
type SeverityBand struct {
	Label    string
	Priority int     // Zabbix trigger priority (0=not classified … 5=disaster)
	Lo, Hi   float64 // score range [Lo, Hi); Hi==0 means no upper bound
}

// SeverityBands cover the whole score range with no gaps or overlaps, so every
// finding maps to exactly one band.
var SeverityBands = []SeverityBand{
	{"Disaster", 5, 9, 0},
	{"High", 4, 7, 9},
	{"Average", 3, 4, 7},
	{"Warning", 2, 0, 4},
}

// SeverityFor returns the band a CVSS score falls into.
func SeverityFor(score float64) SeverityBand {
	for _, b := range SeverityBands {
		if score >= b.Lo && (b.Hi == 0 || score < b.Hi) {
			return b
		}
	}
	return SeverityBands[len(SeverityBands)-1] // Warning fallback (score < 0)
}
