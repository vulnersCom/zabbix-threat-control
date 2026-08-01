package sender

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// fakeServer accepts one connection, decodes the sender frame and replies with
// a success response, returning the decoded metrics via a channel.
func fakeServer(t *testing.T) (addr string, got chan []Metric) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan []Metric, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		head := make([]byte, 13)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		n := binary.LittleEndian.Uint64(head[5:13])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req struct {
			Data []Metric `json:"data"`
		}
		_ = json.Unmarshal(body, &req)
		got <- req.Data

		resp, _ := json.Marshal(Response{Response: "success", Info: "processed: 1; failed: 0"})
		frame := append([]byte(header), make([]byte, 8)...)
		binary.LittleEndian.PutUint64(frame[5:13], uint64(len(resp)))
		frame = append(frame, resp...)
		_, _ = conn.Write(frame)
	}()
	return ln.Addr().String(), got
}

func TestSenderRoundTrip(t *testing.T) {
	addr, got := fakeServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	if _, err := fmtSscan(portStr, &port); err != nil {
		t.Fatal(err)
	}

	s := New(host, port, 3*time.Second)
	resp, err := s.Send(context.Background(), []Metric{{Host: "h", Key: "k", Value: "1"}})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.Response != "success" {
		t.Errorf("response = %q", resp.Response)
	}

	select {
	case metrics := <-got:
		if len(metrics) != 1 || metrics[0].Key != "k" {
			t.Errorf("server got %+v", metrics)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive metrics")
	}
}

// fmtSscan avoids importing fmt just for one Sscan in the test file body.
func fmtSscan(s string, p *int) (int, error) {
	var n int
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	*p = n
	return 1, nil
}
