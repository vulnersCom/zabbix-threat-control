package zabbix

import "context"

// NewV7 constructs and authenticates a Zabbix 6.4+ / 7.x / 8.x client. The
// session/API token is presented via the Authorization: Bearer header and
// user.login uses the "username" parameter. 8.0's API is compatible with 7.x
// for the methods ztc uses, so it shares this client (see factory.go).
func NewV7(ctx context.Context, opts Options) (Client, error) {
	c := newRPCClient(opts, false)
	if opts.Token != "" {
		c.auth = opts.Token
		return c, nil
	}
	if err := c.login(ctx, "username", opts.User, opts.Password); err != nil {
		return nil, err
	}
	return c, nil
}
