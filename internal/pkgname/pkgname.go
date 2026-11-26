// Package pkgname reduces a raw package listing line, as the agent reports it
// and as the audit echoes it back, to the bare name a package manager accepts.
package pkgname

import (
	"regexp"
	"strings"
)

var (
	// apkNVR matches the trailing "-<version>-r<release>" of an Alpine apk
	// listing (e.g. "busybox-1.37.0-r31").
	apkNVR = regexp.MustCompile(`-[^-\s]+-r[0-9]+$`)

	// rpmEVRA matches the trailing "-[epoch:]<version>-<release>.<arch>" of an
	// rpm listing ("sudo-1.9.15p1-2.red80.x86_64", "openssl-1:3.5.7-1.red80.x86_64").
	// The arch must be a known one so a bare name with dots is never cut. This
	// is a deliberate trade-off: a line with an arch missing from the list is
	// returned whole (as before pkgname existed), never cut in the wrong place.
	rpmEVRA = regexp.MustCompile(`-(?:[0-9]+:)?[^-\s:]+-[^-\s]+\.(?:` +
		`x86_64|noarch|i[3-6]86|aarch64|ppc64le|ppc64p7|ppc64|ppc|s390x|s390|` +
		`armv7hl|armv7l|armv6hl|armv5tel|armhfp|riscv64|loongarch64|` +
		`mips64el|mipsel|sparc64|sparcv9|ia64|alpha|e2k|e2kv[0-9]+)$`)
)

// Name returns the package name from a raw listing line:
//   - deb, space-separated:  "openssl 3.0.2-0ubuntu1 amd64" -> "openssl"
//   - apk, hyphen-joined:    "busybox-1.37.0-r31"           -> "busybox"
//   - rpm NEVRA:             "openssl-1:3.5.7-1.red80.x86_64" -> "openssl"
//
// Passing a full rpm NEVRA to `dnf/yum upgrade` means "upgrade to this very
// version", which is a no-op for the installed one - hence the name only.
func Name(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	name := fields[0]
	if len(fields) > 1 {
		return name
	}
	if loc := rpmEVRA.FindStringIndex(name); loc != nil {
		return name[:loc[0]]
	}
	if loc := apkNVR.FindStringIndex(name); loc != nil {
		return name[:loc[0]]
	}
	return name
}
