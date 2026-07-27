package zabbix

import "context"

// NewV6 constructs and authenticates a Zabbix 6.0 (also 5.x) client. Unlike 7.x,
// the session/API token is passed in the request "auth" field and user.login
// uses the "user" parameter (renamed to "username" in 6.4).
func NewV6(ctx context.Context, opts Options) (Client, error) {
	c := newRPCClient(opts, true)
	if opts.Token != "" {
		c.auth = opts.Token
		return c, nil
	}
	if err := c.login(ctx, "user", opts.User, opts.Password); err != nil {
		return nil, err
	}
	return c, nil
}
