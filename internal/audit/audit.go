// Package audit orchestrates the Vulners audit for a host and transforms the
// SDK responses into the source-neutral model. It routes Linux hosts to
// v4/audit/linux and Windows hosts to v4/audit/smart + v4/audit/kb.
package audit

import (
	"context"
	"fmt"

	gv "github.com/kidoz/go-vulners"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/vulners"
)

// Audit runs the appropriate audit(s) for a host and returns its HostResult.
func Audit(ctx context.Context, a vulners.Auditor, h model.Host) (model.HostResult, error) {
	switch h.Platform {
	case model.PlatformLinux:
		res, err := a.LinuxAudit(ctx, h.OSName, h.OSVersion, h.OSArch, h.Packages)
		if err != nil {
			return model.HostResult{}, fmt.Errorf("linux audit %q: %w", h.Name, err)
		}
		return transformLinux(h, res), nil

	case model.PlatformWindows:
		var software []gv.SmartAuditItem
		var kb *gv.KBAuditV4Result
		if len(h.Software) > 0 {
			items, err := a.WindowsSoftwareAudit(ctx, h.Software)
			if err != nil {
				return model.HostResult{}, fmt.Errorf("windows software audit %q: %w", h.Name, err)
			}
			software = items
		}
		if len(h.KBList) > 0 {
			// osName labels the finding; what the host is missing is decided by the
			// installed-KB set alone. The agent reports Win32_OperatingSystem.Caption,
			// so that is what the finding gets named after.
			res, err := a.WindowsKBAudit(ctx, h.OSName, h.OSVersion, h.KBList)
			if err != nil {
				return model.HostResult{}, fmt.Errorf("windows kb audit %q: %w", h.Name, err)
			}
			kb = res
		}
		return transformWindows(h, software, kb), nil

	default:
		return model.HostResult{}, fmt.Errorf("host %q: unknown platform %q", h.Name, h.Platform)
	}
}
