package agentget

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeAgent accepts one connection, reads the framed key request and replies
// with reply (ZBXD-framed). The received key is sent back on the channel.
func fakeAgent(t *testing.T, reply string) (addr string, gotKey chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gotKey = make(chan string, 1)
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
		key := make([]byte, n)
		if _, err := io.ReadFull(conn, key); err != nil {
			return
		}
		gotKey <- string(key)

		frame := append([]byte(header), make([]byte, 8)...)
		binary.LittleEndian.PutUint64(frame[5:13], uint64(len(reply)))
		frame = append(frame, reply...)
		_, _ = conn.Write(frame)
	}()
	return ln.Addr().String(), gotKey
}

func TestGetSuccess(t *testing.T) {
	addr, gotKey := fakeAgent(t, "1")
	val, err := New(2*time.Second).Get(context.Background(), addr, "vulners.fix[openssl]")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "1" {
		t.Errorf("value = %q, want 1", val)
	}
	select {
	case k := <-gotKey:
		if k != "vulners.fix[openssl]" {
			t.Errorf("agent got key %q", k)
		}
	case <-time.After(time.Second):
		t.Fatal("agent did not receive key")
	}
}

func TestGetNotSupported(t *testing.T) {
	addr, _ := fakeAgent(t, notSupported+"\x00Unknown metric")
	_, err := New(2*time.Second).Get(context.Background(), addr, "bogus")
	if err == nil {
		t.Fatal("expected error for ZBX_NOTSUPPORTED")
	}
}
