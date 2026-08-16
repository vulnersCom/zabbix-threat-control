// Package vulners wraps github.com/kidoz/go-vulners behind the Auditor
// interface so the scanner can be tested without network access.
package vulners

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	gv "github.com/kidoz/go-vulners"

	"github.com/vulnersCom/zabbix-threat-control/internal/config"
)

// Auditor is the subset of the Vulners audit API used by the scanner. Results
// are returned as SDK-native structs; the audit package transforms them into
// the source-neutral model.
type Auditor interface {
	// LinuxAudit audits a Linux host via v4/audit/linux.
	LinuxAudit(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error)
	// WindowsSoftwareAudit resolves raw registry software strings to
	// vulnerabilities via v4/audit/smart.
	WindowsSoftwareAudit(ctx context.Context, software []string) ([]gv.SmartAuditItem, error)
	// WindowsKBAudit audits installed KBs via v4/audit/kb. osName must match a
	// KB bulletin's affectedProducts value, e.g. "Windows Server 2022".
	WindowsKBAudit(ctx context.Context, osName, osVersion string, kbList []string) (*gv.KBAuditV4Result, error)
}

// smartAuditFields is the enrichment Smart Audit must be asked for. `metrics`
// carries the advisory rollup used for scoring, `exploitation` the KEV flag and
// `cvelistMetrics` the per-CVE entries that carry SSVC.
var smartAuditFields = []string{"title", "metrics", "exploitation", "cvelist", "cvelistMetrics"}

// Client is the production Auditor backed by go-vulners.
type Client struct {
	svc *gv.AuditService
}

// New builds a Client from configuration.
func New(cfg config.Vulners) (*Client, error) {
	opts := []gv.Option{
		gv.WithTimeout(cfg.Timeout.D()),
		gv.WithRetries(cfg.Retries),
		gv.WithUserAgent("vulners-zabbix-agent"),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, gv.WithBaseURL(cfg.BaseURL))
	}
	// The SDK refuses a plain-HTTP base URL unless explicitly allowed. Enable it
	// automatically for http:// endpoints (local/proxy) or when configured.
	if cfg.Insecure || strings.HasPrefix(cfg.BaseURL, "http://") {
		opts = append(opts, gv.WithAllowInsecure())
	}
	// Mutual-TLS: present a client certificate for endpoints that require it
	// (e.g. beta). WithHTTPClient bypasses WithTimeout, so set it on the client.
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("vulners client cert: %w", err)
		}
		opts = append(opts, gv.WithHTTPClient(&http.Client{
			Timeout: cfg.Timeout.D(),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{cert},
					InsecureSkipVerify: cfg.Insecure,
				},
			},
		}))
	}
	c, err := gv.NewClient(cfg.APIKey, opts...)
	if err != nil {
		return nil, fmt.Errorf("vulners client: %w", err)
	}
	return &Client{svc: c.Audit()}, nil
}

// LinuxAudit implements Auditor. CVE-list metrics are requested so advisories
// carry a CVSS score for aggregation.
func (c *Client) LinuxAudit(ctx context.Context, osName, osVersion, osArch string, packages []string) (*gv.PackageAuditResult, error) {
	opts := []gv.AuditOption{gv.WithCVEListMetrics(true)}
	if osArch != "" {
		opts = append(opts, gv.WithOSArch(osArch))
	}
	return c.svc.LinuxAuditV4(ctx, osName, osVersion, packages, opts...)
}

// WindowsSoftwareAudit implements Auditor. The enrichment is requested
// explicitly: without it the endpoint answers with ai_score alone, which tops
// out below the high band and cannot express KEV, so every Windows application
// finding would look mild.
func (c *Client) WindowsSoftwareAudit(ctx context.Context, software []string) ([]gv.SmartAuditItem, error) {
	res, err := c.svc.SmartAudit(ctx, software, gv.WithAuditFields(smartAuditFields...))
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Items, nil
}

// WindowsKBAudit implements Auditor via v4/audit/kb.
//
// The v3 endpoint returned every missing CVE in one flat list with nothing
// tying them to the update that fixes them, which turned a stale host into
// thousands of findings with no remediation. v4 groups them under the updates
// to install, so the same host yields one finding that names the KB.
func (c *Client) WindowsKBAudit(
	ctx context.Context,
	osName, osVersion string,
	kbList []string,
) (*gv.KBAuditV4Result, error) {
	opts := []gv.AuditOption{gv.WithAuditFields("metrics", "cvelistMetrics")}
	if osVersion != "" {
		opts = append(opts, gv.WithOSVersion(osVersion))
	}
	return c.svc.KBAuditV4(ctx, osName, kbList, opts...)
}
