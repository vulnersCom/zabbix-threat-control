// Package audit orchestrates the Vulners audit for a host and transforms the
// SDK responses into the source-neutral model. It routes Linux hosts to
// v4/audit/linux and Windows hosts to v4/audit/smart + v3/audit/winaudit.
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
		var kb *gv.AuditResult
		if len(h.Software) > 0 {
			items, err := a.WindowsSoftwareAudit(ctx, h.Software)
			if err != nil {
				return model.HostResult{}, fmt.Errorf("windows software audit %q: %w", h.Name, err)
			}
			software = items
		}
		if len(h.KBList) > 0 {
			// The KB endpoint matches os against bulletin affectedProducts; the raw
			// Caption (e.g. "Microsoft Windows 11 Pro") matches nothing (errorCode
			// 110). Send the OS family and let the installed-KB set scope the audit,
			// as the vulners-agent reference does (os=os_data["osType"]).
			res, err := a.WindowsKBAudit(ctx, "Windows", h.KBList)
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
