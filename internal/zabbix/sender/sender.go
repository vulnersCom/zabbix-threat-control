// Package sender implements the zabbix-sender wire protocol so the scanner can
// push trapper values without shelling out to the zabbix_sender binary.
package sender

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Metric is a single value to push to a trapper item.
type Metric struct {
	Host  string `json:"host"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Response is the parsed server acknowledgement.
type Response struct {
	Response string `json:"response"`
	Info     string `json:"info"`
}

const header = "ZBXD\x01"

// Sender pushes metrics to a Zabbix server/proxy trapper port.
type Sender struct {
	Addr    string // host:port
	Timeout time.Duration
}

// New builds a Sender for the given server and port.
func New(server string, port int, timeout time.Duration) *Sender {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Sender{Addr: fmt.Sprintf("%s:%d", server, port), Timeout: timeout}
}

// Send delivers a batch of metrics and returns the server response.
func (s *Sender) Send(ctx context.Context, metrics []Metric) (*Response, error) {
	payload, err := json.Marshal(struct {
		Request string   `json:"request"`
		Data    []Metric `json:"data"`
	}{Request: "sender data", Data: metrics})
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial zabbix %s: %w", s.Addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.Timeout))

	if err := writeFrame(conn, payload); err != nil {
		return nil, err
	}
	return readResponse(conn)
}

func writeFrame(w io.Writer, payload []byte) error {
	buf := make([]byte, 0, len(header)+8+len(payload))
	buf = append(buf, header...)
	length := make([]byte, 8)
	binary.LittleEndian.PutUint64(length, uint64(len(payload)))
	buf = append(buf, length...)
	buf = append(buf, payload...)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write sender frame: %w", err)
	}
	return nil
}

func readResponse(r io.Reader) (*Response, error) {
	head := make([]byte, 13) // "ZBXD"+flags(1)+len(8)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("read sender header: %w", err)
	}
	if string(head[:4]) != "ZBXD" {
		return nil, fmt.Errorf("bad sender response header %q", head[:4])
	}
	n := binary.LittleEndian.Uint64(head[5:13])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read sender body: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse sender response: %w", err)
	}
	return &resp, nil
}
