// Package zabbix provides a version-agnostic Zabbix API client. The Client
// interface is the seam that lets us add implementations for older Zabbix
// versions later; today only the 7.x implementation exists.
package zabbix

import (
	"context"
	"encoding/json"
)

// HostBrief is the minimal host record read during collection.
type HostBrief struct {
	HostID string
	Host   string
	Name   string
}

// ItemBrief is the minimal item record read during collection.
type ItemBrief struct {
	Name      string
	Key       string
	LastValue string
}

// Client abstracts the Zabbix JSON-RPC API. The read methods are strongly typed
// (used by collection); the write path uses the generic Call so provisioning
// can send version-shaped payloads without bloating the interface.
type Client interface {
	// Version returns the Zabbix API version (e.g. "7.0.4").
	Version(ctx context.Context) (string, error)

	// TemplateID resolves a template's technical name to its id ("" if absent).
	TemplateID(ctx context.Context, technicalName string) (string, error)

	// HostsByTemplate returns monitored hosts linked to the given template.
	HostsByTemplate(ctx context.Context, templateID string, limit int) ([]HostBrief, error)

	// ItemsByKeySearch returns items on a host whose key matches keySearch.
	ItemsByKeySearch(ctx context.Context, hostID, keySearch string) ([]ItemBrief, error)

	// Call performs a raw JSON-RPC call (write path / provisioning).
	Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error)
}
