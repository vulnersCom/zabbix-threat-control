package zabbix

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Options configures a client.
type Options struct {
	URL       string
	User      string
	Password  string
	Token     string
	VerifySSL bool
	Timeout   time.Duration
}

// rpcClient is the shared Zabbix JSON-RPC client. Versions differ only in how
// the session/token is presented: 6.4+ through 8.x use the Authorization: Bearer
// header; 6.0/5.x pass it in the request "auth" field. authInBody selects that.
type rpcClient struct {
	endpoint   string
	http       *http.Client
	auth       string // bearer token / session id (or api token)
	nextID     int
	authInBody bool
}

func newRPCClient(opts Options, authInBody bool) *rpcClient {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	transport := &http.Transport{}
	if !opts.VerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in
	}
	return &rpcClient{
		endpoint:   strings.TrimRight(opts.URL, "/") + "/api_jsonrpc.php",
		http:       &http.Client{Timeout: timeout, Transport: transport},
		authInBody: authInBody,
	}
}

// login authenticates via user.login and stores the session token. userField is
// "username" on 6.4+/7.x and "user" on 6.0/5.x.
func (c *rpcClient) login(ctx context.Context, userField, user, password string) error {
	res, err := c.Call(ctx, "user.login", map[string]interface{}{
		userField:  user,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("zabbix login: %w", err)
	}
	var token string
	if err := json.Unmarshal(res, &token); err != nil {
		return fmt.Errorf("zabbix login token: %w", err)
	}
	c.auth = token
	return nil
}

type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	Auth    string      `json:"auth,omitempty"` // 6.0/5.x carry the token here
	ID      int         `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("zabbix api error %d: %s (%s)", e.Code, e.Message, e.Data)
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// Call performs a JSON-RPC request. Methods that must run unauthenticated
// (apiinfo.version, user.login) are sent without the token in either transport.
func (c *rpcClient) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	c.nextID++
	if params == nil {
		params = map[string]interface{}{}
	}
	authed := c.auth != "" && !isAnonymousMethod(method)

	reqObj := rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: c.nextID}
	if authed && c.authInBody {
		reqObj.Auth = c.auth
	}
	body, err := json.Marshal(reqObj)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	if authed && !c.authInBody {
		req.Header.Set("Authorization", "Bearer "+c.auth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zabbix call %s: %w", method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("zabbix call %s: reading response from %s: %w", method, c.endpoint, err)
	}
	// The JSON-RPC endpoint answers 200 with JSON even for API errors; anything
	// else (or a non-JSON 200 — a login page, reverse-proxy 404, WAF block) means
	// ZABBIX_URL is not pointing at api_jsonrpc.php. Say so instead of surfacing a
	// bare "invalid character '<'".
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zabbix call %s: %s returned HTTP %d — is ZABBIX_URL the JSON-RPC API? %s",
			method, c.endpoint, resp.StatusCode, bodySnippet(respBody))
	}
	var out rpcResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("zabbix call %s: %s did not return JSON — is ZABBIX_URL the JSON-RPC API? %s",
			method, c.endpoint, bodySnippet(respBody))
	}
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func isAnonymousMethod(method string) bool {
	return method == "apiinfo.version" || method == "user.login"
}

// bodySnippet returns a short single-line excerpt of a response body for error
// messages (e.g. the first line of an HTML error page).
func bodySnippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(empty response body)"
	}
	return "body: " + s
}

func (c *rpcClient) Version(ctx context.Context) (string, error) {
	res, err := c.Call(ctx, "apiinfo.version", []interface{}{})
	if err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(res, &v); err != nil {
		return "", err
	}
	return v, nil
}

func (c *rpcClient) TemplateID(ctx context.Context, technicalName string) (string, error) {
	res, err := c.Call(ctx, "template.get", map[string]interface{}{
		"filter": map[string]interface{}{"host": technicalName},
		"output": []string{"templateid"},
	})
	if err != nil {
		return "", err
	}
	var rows []struct {
		TemplateID string `json:"templateid"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].TemplateID, nil
}

func (c *rpcClient) HostsByTemplate(ctx context.Context, templateID string, limit int) ([]HostBrief, error) {
	params := map[string]interface{}{
		"templated_hosts": false,
		"templateids":     templateID,
		"monitored_hosts": true,
		"output":          []string{"hostid", "host", "name"},
	}
	if limit > 0 {
		params["limit"] = limit
	}
	res, err := c.Call(ctx, "host.get", params)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		HostID string `json:"hostid"`
		Host   string `json:"host"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return nil, err
	}
	hosts := make([]HostBrief, len(rows))
	for i, r := range rows {
		hosts[i] = HostBrief{HostID: r.HostID, Host: r.Host, Name: r.Name}
	}
	return hosts, nil
}

func (c *rpcClient) ItemsByKeySearch(ctx context.Context, hostID, keySearch string) ([]ItemBrief, error) {
	res, err := c.Call(ctx, "item.get", map[string]interface{}{
		"hostids": hostID,
		"search":  map[string]interface{}{"key_": keySearch},
		"output":  []string{"name", "key_", "lastvalue"},
	})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name      string `json:"name"`
		Key       string `json:"key_"`
		LastValue string `json:"lastvalue"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return nil, err
	}
	items := make([]ItemBrief, len(rows))
	for i, r := range rows {
		items[i] = ItemBrief{Name: r.Name, Key: r.Key, LastValue: r.LastValue}
	}
	return items, nil
}
