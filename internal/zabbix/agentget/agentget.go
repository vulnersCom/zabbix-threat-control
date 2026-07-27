// Package agentget implements the Zabbix passive-agent protocol (the client side
// of zabbix_get): it connects to a zabbix-agent2 on port 10050 and requests an
// item key, returning the agent's response. It is used to invoke the whitelisted
// vulners.fix[<pkg>] key on a target host during remediation.
package agentget

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	header       = "ZBXD\x01"
	notSupported = "ZBX_NOTSUPPORTED"
)

// Client performs passive-agent requests.
type Client struct {
	Timeout time.Duration
}

// New builds a Client with the given per-request timeout.
func New(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{Timeout: timeout}
}

// Get sends the item key to the agent at addr ("host:port") and returns its
// textual response. A ZBX_NOTSUPPORTED reply becomes an error.
func (c *Client) Get(ctx context.Context, addr, key string) (string, error) {
	dialer := net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial agent %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	if err := writeFrame(conn, []byte(key)); err != nil {
		return "", err
	}

	data, err := readResponse(conn)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(data, notSupported) {
		reason := strings.TrimPrefix(data, notSupported)
		reason = strings.TrimLeft(reason, "\x00")
		return "", fmt.Errorf("agent %s: key %q not supported: %s", addr, key, strings.TrimSpace(reason))
	}
	return strings.TrimRight(data, "\n"), nil
}

func writeFrame(w io.Writer, payload []byte) error {
	buf := make([]byte, 0, len(header)+8+len(payload))
	buf = append(buf, header...)
	length := make([]byte, 8)
	binary.LittleEndian.PutUint64(length, uint64(len(payload)))
	buf = append(buf, length...)
	buf = append(buf, payload...)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write agent request: %w", err)
	}
	return nil
}

// readResponse reads either a ZBXD-framed reply or a bare (legacy) reply.
func readResponse(r io.Reader) (string, error) {
	head := make([]byte, 5) // "ZBXD" + flags
	n, err := io.ReadFull(r, head)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// Bare reply shorter than a header: return what we have.
		rest, _ := io.ReadAll(io.MultiReader(bytes.NewReader(head[:n]), r))
		return string(rest), nil
	}
	if err != nil {
		return "", fmt.Errorf("read agent header: %w", err)
	}
	if string(head[:4]) != "ZBXD" {
		// Legacy unframed response: head + remainder is the payload.
		rest, _ := io.ReadAll(r)
		return string(head[:n]) + string(rest), nil
	}
	lenBuf := make([]byte, 8)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", fmt.Errorf("read agent length: %w", err)
	}
	size := binary.LittleEndian.Uint64(lenBuf)
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", fmt.Errorf("read agent body: %w", err)
	}
	return string(body), nil
}
