package agentget

import (
	"bytes"
	"compress/zlib"
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

// readFrom feeds readResponse a raw agent reply.
func readFrom(t *testing.T, raw []byte) string {
	t.Helper()
	got, err := readResponse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	return got
}

// zabbix-agent2 6.x puts the uncompressed size into the reserved field even for
// an uncompressed reply: "ZBXD\x01" <len=6> <reserved=6> "queued".
func TestReadResponseReservedFilled(t *testing.T) {
	raw := []byte("ZBXD\x01\x06\x00\x00\x00\x06\x00\x00\x00queued")
	if got := readFrom(t, raw); got != "queued" {
		t.Errorf("got %q, want queued", got)
	}
}

func TestReadResponseCompressed(t *testing.T) {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write([]byte("queued"))
	_ = w.Close()
	raw := []byte("ZBXD\x03")
	raw = binary.LittleEndian.AppendUint32(raw, uint32(z.Len()))
	raw = binary.LittleEndian.AppendUint32(raw, 6)
	raw = append(raw, z.Bytes()...)
	if got := readFrom(t, raw); got != "queued" {
		t.Errorf("got %q, want queued", got)
	}
}

func TestReadResponseCompressedTooLarge(t *testing.T) {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write(make([]byte, maxResponse+1)) // zeros compress to a few KB
	_ = w.Close()
	raw := []byte("ZBXD\x03")
	raw = binary.LittleEndian.AppendUint32(raw, uint32(z.Len()))
	raw = binary.LittleEndian.AppendUint32(raw, maxResponse+1)
	raw = append(raw, z.Bytes()...)
	if _, err := readResponse(bytes.NewReader(raw)); err == nil {
		t.Error("expected an error for an over-limit uncompressed reply, got none")
	}
}
