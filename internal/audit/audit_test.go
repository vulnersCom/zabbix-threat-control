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
			Input:        "Google Chrome 100.0",
			FixedVersion: "101.0.4951.41",
			Vulnerabilities: []gv.SmartAuditVulnerability{{
				ID:      "GCSA-1",
				AIScore: &gv.AIScore{Value: 6.9},
				// The rollup is what the finding is scored from; ai_score would
				// have capped this below the high band.
				Metrics: &gv.AdvisoryMetrics{CVSS: &gv.CVSS{Score: 9.6}},
			}},
		},
		{Input: "Unknown blob", Vulnerabilities: nil},
	}
	kb := &gv.KBAuditV4Result{Items: []gv.KBAuditIssue{{
		Package:      "Windows Server 2022",
		FixedPackage: "KB5120242",
		Advisories: []gv.KBAuditAdvisory{{
			ID:      "KB5120242",
			Metrics: &gv.AdvisoryMetrics{CVSS: &gv.CVSS{Score: 6.5}},
		}},
	}}}
	h := model.Host{Name: "win1", OSName: "Windows Server 2022", Platform: model.PlatformWindows}
	got := transformWindows(h, software, kb)

	if got.Score != 9.6 {
		t.Errorf("score = %v, want 9.6 (rollup, not ai_score)", got.Score)
	}
	if len(got.Bulletins) != 2 {
		t.Errorf("bulletins = %d, want 2 (advisory + KB)", len(got.Bulletins))
	}
	if len(got.Packages) != 2 {
		t.Errorf("packages = %d, want 2", len(got.Packages))
	}
	// Windows findings used to carry no remediation at all.
	var chrome, windows model.Package
	for _, p := range got.Packages {
		switch p.Name {
		case "Google Chrome 100.0":
			chrome = p
		case "Windows Server 2022":
			windows = p
		}
	}
	if chrome.Fix != "upgrade Google Chrome 100.0 to 101.0.4951.41" {
		t.Errorf("software fix = %q", chrome.Fix)
	}
	if windows.Fix != "install KB5120242" {
		t.Errorf("kb fix = %q", windows.Fix)
	}
}

func TestAuditWindowsKBSendsTheHostOSName(t *testing.T) {
	var gotOS, gotVersion string
	mock := &vulners.Mock{
		KBFunc: func(_ context.Context, osName, osVersion string, _ []string) (*gv.KBAuditV4Result, error) {
			gotOS, gotVersion = osName, osVersion
			return &gv.KBAuditV4Result{}, nil
		},
	}
	// OSName is the raw Win32_OperatingSystem.Caption the agent reports. The v4
	// endpoint labels the finding with it rather than matching on it, so the
	// Caption goes through as-is instead of being flattened to a family name.
	h := model.Host{
		Platform:  model.PlatformWindows,
		OSName:    "Microsoft Windows 11 Pro",
		OSVersion: "10.0.22631",
		KBList:    []string{"KB5066131"},
	}
	if _, err := Audit(context.Background(), mock, h); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if gotOS != "Microsoft Windows 11 Pro" || gotVersion != "10.0.22631" {
		t.Errorf("KB audit os = %q / %q", gotOS, gotVersion)
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
		KBFunc: func(_ context.Context, _, _ string, _ []string) (*gv.KBAuditV4Result, error) {
			kbCalled = true
			return &gv.KBAuditV4Result{}, nil
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
