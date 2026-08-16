package vulners

import (
	"context"

	gv "github.com/kidoz/go-vulners"
)

// Mock is a test double for Auditor. Set the func fields to control behaviour.
type Mock struct {
	LinuxFunc    func(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error)
	SoftwareFunc func(ctx context.Context, software []string) ([]gv.SmartAuditItem, error)
	KBFunc       func(ctx context.Context, osName, osVersion string, kbList []string) (*gv.KBAuditV4Result, error)
}

var _ Auditor = (*Mock)(nil)

func (m *Mock) LinuxAudit(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error) {
	if m.LinuxFunc != nil {
		return m.LinuxFunc(ctx, osName, osVersion, osArch, packages)
	}
	return &gv.PackageAuditResult{}, nil
}

func (m *Mock) WindowsSoftwareAudit(ctx context.Context, software []string) ([]gv.SmartAuditItem, error) {
	if m.SoftwareFunc != nil {
		return m.SoftwareFunc(ctx, software)
	}
	return nil, nil
}

func (m *Mock) WindowsKBAudit(
	ctx context.Context,
	osName, osVersion string,
	kbList []string,
) (*gv.KBAuditV4Result, error) {
	if m.KBFunc != nil {
		return m.KBFunc(ctx, osName, osVersion, kbList)
	}
	return &gv.KBAuditV4Result{}, nil
}
