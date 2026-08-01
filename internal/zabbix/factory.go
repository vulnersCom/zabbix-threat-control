package zabbix

import (
	"context"
	"strconv"
	"strings"
)

// New builds a Client for the detected/requested Zabbix version. 6.4+ through
// 8.x authenticate with the Authorization: Bearer header (NewV7); 6.0/6.2 and
// 5.x pass the token in the request "auth" field (NewV6). When version is empty
// it is autodetected via apiinfo.version (which needs no authentication).
//
// Zabbix 8.0 reuses the NewV7 client on purpose: for the API methods ztc calls
// (host/item/trigger/template/graph/dashboard.*, LLD create, problem.get, …) 8.0
// is compatible with 7.x and keeps Bearer auth — the removed 8.0 methods are all
// *.massupdate / replacehostinterfaces, none of which ztc uses. A dedicated v8
// client would only duplicate v7.
func New(ctx context.Context, opts Options, version string) (Client, error) {
	if version == "" {
		// apiinfo.version is unauthenticated and identically shaped on all
		// versions, so a bare probe client can read it before we commit.
		probe := newRPCClient(opts, false)
		if v, err := probe.Version(ctx); err == nil {
			version = v
		}
	}
	if useBodyAuth(version) {
		return NewV6(ctx, opts)
	}
	return NewV7(ctx, opts)
}

// useBodyAuth reports whether the version predates Bearer-header auth and the
// "username" login parameter (5.x, 6.0, 6.2). 6.4+ through 8.x and an unknown
// version default to the header-based 7.x client.
func useBodyAuth(version string) bool {
	major, minor := parseVersion(version)
	switch {
	case major == 0:
		return false // unknown -> default to 7.x client
	case major < 6:
		return true // 5.x
	case major == 6 && minor < 4:
		return true // 6.0, 6.2
	default:
		return false // 6.4+, 7.x, 8.x
	}
}

func parseVersion(v string) (major, minor int) {
	if v == "" {
		return 0, 0
	}
	parts := strings.SplitN(v, ".", 3)
	major, _ = strconv.Atoi(parts[0])
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}
