package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

// Keep tunnels live while opening additional ones. Reading an echo exercises
// both relay directions; a local CONNECT 200 alone does not establish delivery.
func TestConcurrentTunnels(t *testing.T) { exerciseTunnels(t, false) }
func TestLaneBlackhole(t *testing.T)     { exerciseTunnels(t, true) }

func exerciseTunnels(t *testing.T, fault bool) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", origin.Addr().String())
	}
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	leaf := fixture.Certificate()
	fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept(context.Background())
			if e != nil {
				return
			}
			go func() {
				for {
					s, e := c.AcceptStream(c.Context())
					if e != nil {
						return
					}
					go acceptStream(s, dial)
				}
			}()
		}
	}()
	p := &client{}
	var dropped atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 2; i++ {
		addr := listener.Addr().String()
		if fault && i == 1 {
			addr = udpFaultLink(t, addr, &dropped)
		}
		p.lanes = append(p.lanes, &client{address: addr, tls: &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}})
	}
	proxy := httptest.NewServer(p)
	defer proxy.Close()
	defer func() {
		for _, l := range p.lanes {
			if c := l.currentSession(); c != nil {
				c.CloseWithError(0, "done")
			}
		}
	}()
	open := func(i int) net.Conn {
		t.Helper()
		c, e := net.DialTimeout("tcp", proxy.Listener.Addr().String(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		marker := fmt.Sprintf("echo-%d", i)
		_, e = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n%s", marker)
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		r := bufio.NewReader(c)
		resp, e := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
		if e != nil {
			c.Close()
			t.Fatalf("tunnel %d: %v", i, e)
		}
		if resp.StatusCode != 200 {
			c.Close()
			t.Fatalf("tunnel %d: %s", i, resp.Status)
		}
		buf := make([]byte, len(marker))
		_, e = io.ReadFull(r, buf)
		if e != nil || string(buf) != marker {
			c.Close()
			t.Fatalf("echo %d: %v", i, e)
		}
		c.SetDeadline(time.Time{})
		return c
	}
	if fault {
		for _, lane := range p.lanes {
			warm, stop := context.WithTimeout(ctx, 3*time.Second)
			_, err := lane.connect(warm)
			stop()
			if err != nil {
				t.Fatal(err)
			}
			go lane.watchPath(ctx)
		}
		active := open(1)
		dropped.Store(true)
		active.SetDeadline(time.Now().Add(time.Second))
		payload := make([]byte, 192*1024)
		if _, e := active.Write(payload); e != nil {
			t.Fatal(e)
		}
		_, readErr := io.ReadFull(active, payload)
		active.Close()
		if readErr == nil {
			t.Fatal("striped transfer unexpectedly completed with a blackholed lane")
		}
		t.Log("existing striped echo interrupted by injected packet loss")
		start := time.Now()
		for !p.lanes[1].unavailable.Load() && time.Since(start) < 15*time.Second {
			time.Sleep(50 * time.Millisecond)
		}
		if !p.lanes[1].unavailable.Load() || p.lanes[0].unavailable.Load() {
			t.Fatal("failed to isolate stalled lane")
		}
		open(2).Close()
		t.Logf("new tunnel returned echo on surviving lane after %s", time.Since(start))
		dropped.Store(false)
		start = time.Now()
		for p.lanes[1].unavailable.Load() && time.Since(start) < 10*time.Second {
			time.Sleep(50 * time.Millisecond)
		}
		if p.lanes[1].unavailable.Load() {
			t.Fatal("restored path did not rejoin")
		}
		open(3).Close()
		t.Logf("two-lane echo after path restoration in %s", time.Since(start))
		cancel()
		return
	}
	var live []net.Conn
	defer func() {
		for _, c := range live {
			c.Close()
		}
	}()
	for i := 1; i <= 201; i++ {
		live = append(live, open(i))
	}
	for _, c := range live {
		c.Close()
	}
	live = nil
	for i := 1; i <= 500; i++ {
		open(i).Close()
	}
}

// Drop packets in both directions for one lane, including reconnection
// attempts, without affecting the second lane or the host routing table.
func udpFaultLink(t *testing.T, endpoint string, drop *atomic.Bool) string {
	remote, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	go func() {
		buf := make([]byte, 65535)
		var peer *net.UDPAddr
		for {
			n, from, e := socket.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if drop.Load() {
				continue
			}
			if from.Port == remote.Port && from.IP.Equal(remote.IP) {
				if peer != nil {
					socket.WriteToUDP(buf[:n], peer)
				}
			} else {
				peer = from
				socket.WriteToUDP(buf[:n], remote)
			}
		}
	}()
	return socket.LocalAddr().String()
}
