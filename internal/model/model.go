// Package model contains the source-neutral domain types shared across the
// scanner. Linux, Windows software (smart) and Windows KB audit responses are
// all reduced to these types before aggregation and pushing to Zabbix.
package model

// Platform identifies how a host must be audited.
type Platform string

const (
	// PlatformLinux hosts are audited via vulners v4/audit/linux.
	PlatformLinux Platform = "linux"
	// PlatformWindows hosts are audited via v4/audit/smart (registry software)
	// and v3/audit/winaudit (installed KBs).
	PlatformWindows Platform = "windows"
)

// Host is a monitored host pulled from Zabbix together with the raw inventory
// data collected by the zabbix-agent2 UserParameter items.
type Host struct {
	HostID    string
	Host      string // technical host name
	Name      string // visible name
	Platform  Platform
	OSName    string
	OSVersion string
	OSArch    string

	// Linux inventory: native package listing (one "name version" per line).
	Packages []string

	// Windows inventory.
	Software []string // raw software strings from the registry (Uninstall keys)
	KBList   []string // installed KB identifiers, e.g. "KB5031354"
}

// Bulletin is a security bulletin/advisory affecting a host.
type Bulletin struct {
	Name  string
	Score float64
}

// Package is a vulnerable package with the highest-scoring bulletin and the
// remediation command for it.
type Package struct {
	Name       string
	Score      float64
	BulletinID string
	Fix        string
}

// HostResult is the audit outcome for a single host.
type HostResult struct {
	Host          Host
	Score         float64
	CumulativeFix string
	Packages      []Package
	Bulletins     []Bulletin
}
