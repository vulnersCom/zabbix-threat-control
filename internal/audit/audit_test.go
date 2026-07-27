package audit

import (
	"context"
	"testing"

	gv "github.com/kidoz/go-vulners"

	"github.com/vulnersCom/zabbix-threat-control/internal/model"
	"github.com/vulnersCom/zabbix-threat-control/internal/vulners"
)

func strp(s string) *string { return &s }

func metrics(score float64) []map[string]interface{} {
	return []map[string]interface{}{
		{"cve": "CVE-2021-1", "cvss": map[string]interface{}{"score": score}},
	}
}

func TestFixCommand(t *testing.T) {
	cases := map[string]string{
		"ubuntu":      "sudo apt-get --assume-yes install --only-upgrade bash",
		"debian":      "sudo apt-get --assume-yes install --only-upgrade bash",
		"centos":      "sudo yum -y update bash",
		"oraclelinux": "sudo yum -y update bash",
		"alpine":      "sudo apk upgrade bash",
		"sles":        "sudo zypper update -y bash",
		"weirdos":     "sudo yum -y update bash", // default branch
	}
	for os, want := range cases {
		if got := fixCommand(os, "bash 4.4-1 amd64"); got != want {
			t.Errorf("fixCommand(%q) = %q, want %q", os, got, want)
		}
	}
}

func TestTransformLinux(t *testing.T) {
	res := &gv.PackageAuditResult{
		Issues: []gv.PackageAuditIssue{
			{
				Package: "bash",
				Version: strp("4.4-1"),
				ApplicableAdvisories: []gv.AuditApplicableAdvisory{
					{ID: "USN-1", Operator: "lt", Version: "4.4-2", CVEListMetrics: metrics(7.5)},
					{ID: "USN-2", Operator: "lt", Version: "4.4-3", CVEListMetrics: metrics(9.8)},
				},
			},
			{
				Package:              "openssl",
				ApplicableAdvisories: []gv.AuditApplicableAdvisory{{ID: "USN-3", CVEListMetrics: metrics(5.0)}},
			},
		},
	}
	h := model.Host{Name: "h1", OSName: "ubuntu", OSVersion: "22.04", Platform: model.PlatformLinux}
	got := transformLinux(h, res)

	if got.Score != 9.8 {
		t.Errorf("host score = %v, want 9.8", got.Score)
	}
	if len(got.Bulletins) != 3 {
		t.Errorf("bulletins = %d, want 3", len(got.Bulletins))
	}
	if len(got.Packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(got.Packages))
	}
	// bash keeps the highest advisory score
	var bash model.Package
	for _, p := range got.Packages {
		if p.Name == "bash" {
			bash = p
		}
	}
	if bash.Score != 9.8 {
		t.Errorf("bash score = %v, want 9.8", bash.Score)
	}
	if bash.Fix != "sudo apt-get --assume-yes install --only-upgrade bash" {
		t.Errorf("bash fix = %q", bash.Fix)
	}
	if got.CumulativeFix == "" {
		t.Error("cumulative fix should not be empty")
	}
}

func TestTransformWindows(t *testing.T) {
	software := []gv.SmartAuditItem{
		{
			Input: "Google Chrome 100.0",
			Vulnerabilities: []gv.SmartAuditVulnerability{
				{ID: "CVE-2022-1", AIScore: &gv.AIScore{Value: 8.1}},
			},
		},
		{Input: "Unknown blob", Vulnerabilities: nil},
	}
	kb := &gv.AuditResult{
		Vulnerabilities: []gv.Vulnerability{
			{BulletinID: "KB5031", Package: "Windows 10", CVSS: &gv.CVSS{Score: 6.5}, Fix: "Install KB5031"},
		},
	}
	h := model.Host{Name: "win1", OSName: "Windows 10", Platform: model.PlatformWindows}
	got := transformWindows(h, software, kb)

	if got.Score != 8.1 {
		t.Errorf("score = %v, want 8.1", got.Score)
	}
	if len(got.Bulletins) != 2 {
		t.Errorf("bulletins = %d, want 2 (CVE + KB)", len(got.Bulletins))
	}
	if len(got.Packages) != 2 {
		t.Errorf("packages = %d, want 2", len(got.Packages))
	}
}

func TestAuditWindowsKBUsesFamilyOSName(t *testing.T) {
	var gotOS string
	mock := &vulners.Mock{
		KBFunc: func(ctx context.Context, os string, kbList []string) (*gv.AuditResult, error) {
			gotOS = os
			return &gv.AuditResult{}, nil
		},
	}
	// OSName is the raw Win32_OperatingSystem.Caption the agent reports.
	h := model.Host{
		Platform: model.PlatformWindows,
		OSName:   "Microsoft Windows 11 Pro",
		KBList:   []string{"KB5066131"},
	}
	if _, err := Audit(context.Background(), mock, h); err != nil {
		t.Fatalf("audit: %v", err)
	}
	// The KB endpoint matches os against bulletin affectedProducts and rejects the
	// raw Caption (errorCode 110); the OS family "Windows" must be sent instead.
	if gotOS != "Windows" {
		t.Errorf("KB audit os = %q, want %q", gotOS, "Windows")
	}
}

func TestAuditRoutesByPlatform(t *testing.T) {
	linuxCalled, kbCalled, smartCalled := false, false, false
	mock := &vulners.Mock{
		LinuxFunc: func(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error) {
			linuxCalled = true
			return &gv.PackageAuditResult{}, nil
		},
		SoftwareFunc: func(ctx context.Context, software []string) ([]gv.SmartAuditItem, error) {
			smartCalled = true
			return nil, nil
		},
		KBFunc: func(ctx context.Context, os string, kbList []string) (*gv.AuditResult, error) {
			kbCalled = true
			return &gv.AuditResult{}, nil
		},
	}

	_, err := Audit(context.Background(), mock, model.Host{Platform: model.PlatformLinux, Packages: []string{"a"}})
	if err != nil || !linuxCalled {
		t.Fatalf("linux route: err=%v called=%v", err, linuxCalled)
	}

	_, err = Audit(context.Background(), mock, model.Host{
		Platform: model.PlatformWindows,
		Software: []string{"Chrome"},
		KBList:   []string{"KB1"},
	})
	if err != nil || !smartCalled || !kbCalled {
		t.Fatalf("windows route: err=%v smart=%v kb=%v", err, smartCalled, kbCalled)
	}

	_, err = Audit(context.Background(), mock, model.Host{Platform: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown platform")
	}
}
