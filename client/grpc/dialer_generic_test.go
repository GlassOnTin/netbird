//go:build !js

package grpc

import (
	"context"
	"net"
	"testing"
	"time"
)

// startEcho listens on IPv4 loopback only and echoes one payload back. Returns
// the listener address (host:port) and a cleanup func.
func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()
	return l.Addr().String(), func() { _ = l.Close() }
}

// dialPreferIPv4 must resolve a hostname to its A record and dial IPv4 even when
// the host also has an AAAA record (localhost has ::1 too). The listener is
// IPv4-only, so a successful echo proves the IPv4 path was used (#662: Android
// netd can return AAAA-only, leaving the dual-stack dial no IPv4 fallback).
func TestDialPreferIPv4ResolvesAndDialsIPv4(t *testing.T) {
	addr, cleanup := startEcho(t)
	defer cleanup()
	_, port, _ := net.SplitHostPort(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialPreferIPv4(ctx, net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("dialPreferIPv4 localhost: %v", err)
	}
	defer conn.Close()

	// The peer must be the IPv4 loopback, not ::1.
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		t.Fatalf("dialed peer %s is not IPv4", host)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}

// An IP literal must dial directly without resolution.
func TestDialPreferIPv4Literal(t *testing.T) {
	addr, cleanup := startEcho(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialPreferIPv4(ctx, addr)
	if err != nil {
		t.Fatalf("dialPreferIPv4 literal %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("echo = %q, want ok", buf)
	}
}