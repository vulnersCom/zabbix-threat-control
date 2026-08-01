package audit

import (
	"fmt"
	"strings"
)

// packageManager returns the shell command that upgrades a single package on
// the given OS. It is a port of scan.py:_get_fix_command.
func fixCommand(osName, packageName string) string {
	pkg := firstField(packageName)
	switch strings.ToLower(osName) {
	case "debian", "ubuntu", "astra", "astralinuxce", "astralinuxse":
		return fmt.Sprintf("sudo apt-get --assume-yes install --only-upgrade %s", pkg)
	case "rhel", "centos", "oraclelinux", "fedora", "rocky", "almalinux", "amzn":
		return fmt.Sprintf("sudo yum -y update %s", pkg)
	case "alpine":
		return fmt.Sprintf("sudo apk upgrade %s", pkg)
	case "suse", "opensuse", "sles", "opensuse-leap":
		return fmt.Sprintf("sudo zypper update -y %s", pkg)
	default:
		return fmt.Sprintf("sudo yum -y update %s", pkg)
	}
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
