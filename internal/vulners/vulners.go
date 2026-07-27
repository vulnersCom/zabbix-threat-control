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
	// WindowsKBAudit audits installed KBs via v3/audit/kb. os is the family
	// ("Windows"); the installed KB set scopes the result.
	WindowsKBAudit(ctx context.Context, os string, kbList []string) (*gv.AuditResult, error)
}

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

// WindowsSoftwareAudit implements Auditor.
func (c *Client) WindowsSoftwareAudit(ctx context.Context, software []string) ([]gv.SmartAuditItem, error) {
	res, err := c.svc.SmartAudit(ctx, software)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Items, nil
}

// WindowsKBAudit implements Auditor via v3/audit/kb. The endpoint matches os
// against bulletin affectedProducts (the OS family "Windows" matches loosely)
// and returns the CVEs implied by the missing KBs relative to the installed set.
func (c *Client) WindowsKBAudit(ctx context.Context, os string, kbList []string) (*gv.AuditResult, error) {
	return c.svc.KBAudit(ctx, os, kbList)
}
