package zabbix

import (
	"context"
	"encoding/json"
)

// Mock is a test double for Client. It records Call invocations and lets tests
// stub each method.
type Mock struct {
	VersionFunc    func(ctx context.Context) (string, error)
	TemplateIDFunc func(ctx context.Context, name string) (string, error)
	HostsFunc      func(ctx context.Context, templateID string, limit int) ([]HostBrief, error)
	ItemsFunc      func(ctx context.Context, hostID, keySearch string) ([]ItemBrief, error)
	CallFunc       func(ctx context.Context, method string, params interface{}) (json.RawMessage, error)

	Calls []MockCall
}

// MockCall records a single Call invocation.
type MockCall struct {
	Method string
	Params interface{}
}

var _ Client = (*Mock)(nil)

func (m *Mock) Version(ctx context.Context) (string, error) {
	if m.VersionFunc != nil {
		return m.VersionFunc(ctx)
	}
	return "7.0.0", nil
}

func (m *Mock) TemplateID(ctx context.Context, name string) (string, error) {
	if m.TemplateIDFunc != nil {
		return m.TemplateIDFunc(ctx, name)
	}
	return "", nil
}

func (m *Mock) HostsByTemplate(ctx context.Context, templateID string, limit int) ([]HostBrief, error) {
	if m.HostsFunc != nil {
		return m.HostsFunc(ctx, templateID, limit)
	}
	return nil, nil
}

func (m *Mock) ItemsByKeySearch(ctx context.Context, hostID, keySearch string) ([]ItemBrief, error) {
	if m.ItemsFunc != nil {
		return m.ItemsFunc(ctx, hostID, keySearch)
	}
	return nil, nil
}

func (m *Mock) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	m.Calls = append(m.Calls, MockCall{Method: method, Params: params})
	if m.CallFunc != nil {
		return m.CallFunc(ctx, method, params)
	}
	return json.RawMessage(`{}`), nil
}
