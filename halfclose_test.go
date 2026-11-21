package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

// Set TWINSAIL_LONG_TESTS=1 to exercise the production 60-second half-close
// timer over real TCP and QUIC. Both transfers run concurrently on loopback.
func TestLongLivedHalfClose(t *testing.T) {
	if os.Getenv("TWINSAIL_LONG_TESTS") != "1" {
		t.Skip("set TWINSAIL_LONG_TESTS=1 for the 64-second half-close transfer")
	}
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}
	clientTLS := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var accepted, expected atomic.Int32
	t.Cleanup(func() {
		if n, want := accepted.Load(), expected.Load(); n != want {
			t.Errorf("server accepted %d tunnel streams, expected %d for the selected lane counts", n, want)
		}
	})

	dial := func(ctx context.Context, target string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(target)
		if err != nil || host != "127.0.0.1" {
			return nil, errors.New("test origin must be IPv4 loopback")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", target)
	}
	go func() {
		for {
			conn, err := listener.Accept(t.Context())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(conn.Context())
					if err != nil {
						return
					}
					accepted.Add(1)
					go acceptStream(s, dial)
				}
			}()
		}
	}()

	for _, tc := range []struct {
		name  string
		lanes int
	}{
		{"single_lane_download_after_client_FIN", 1},
		{"two_lane_upload_after_origin_FIN", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expected.Add(int32(tc.lanes))
			origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()

			endpoint := listener.Addr().String()
			p := &client{address: endpoint, tls: clientTLS}
			if tc.lanes == 2 {
				for range tc.lanes {
					p.lanes = append(p.lanes, &client{address: endpoint, tls: clientTLS})
				}
			}
			warm := p.lanes
			if len(warm) == 0 {
				warm = []*client{p}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			for _, lane := range warm {
				session, err := lane.connect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { session.CloseWithError(0, "test complete") })
			}
			proxy := httptest.NewServer(p)
			defer proxy.Close()
			deadline := time.Now().Add(85 * time.Second)
			// Each chunk has a distinct byte value so loss, duplication or
			// reordering across the former timeout boundary is observable.
			var payload []byte
			for i := 1; i <= 9; i++ {
				payload = append(payload, bytes.Repeat([]byte{byte(i)}, 1024)...)
			}
			writeOverMinute := func(c *net.TCPConn) error {
				tick := time.NewTicker(8 * time.Second)
				defer tick.Stop()
				for pos := 0; pos < len(payload); pos += 1024 {
					if pos > 0 {
						<-tick.C
					}
					if _, err := c.Write(payload[pos : pos+1024]); err != nil {
						return err
					}
				}
				return c.CloseWrite()
			}
			const short = "request or early response"
			writeShortThenFIN := func(c *net.TCPConn) error {
				if _, err := io.WriteString(c, short); err != nil {
					return err
				}
				return c.CloseWrite()
			}
			expectThroughFIN := func(r io.Reader, want []byte) error {
				got, err := io.ReadAll(r)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, want) {
					return fmt.Errorf("got %d bytes through FIN, expected %d with identical content", len(got), len(want))
				}
				return nil
			}
			originDone := make(chan error, 1)
			go func() {
				c, err := origin.AcceptTCP()
				if err != nil {
					originDone <- err
					return
				}
				defer c.Close()
				c.SetDeadline(deadline)
				if tc.lanes == 1 {
					if err = expectThroughFIN(c, []byte(short)); err == nil {
						err = writeOverMinute(c)
					}
				} else if err = writeShortThenFIN(c); err == nil {
					err = expectThroughFIN(c, payload)
				}
				originDone <- err
			}()

			c, err := net.DialTCP("tcp4", nil, proxy.Listener.Addr().(*net.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(deadline)
			target := origin.Addr().String()
			if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(c)
			resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatal(resp.Status)
			}
			if tc.lanes == 1 {
				if err = writeShortThenFIN(c); err == nil {
					err = expectThroughFIN(reader, payload)
				}
			} else if err = expectThroughFIN(reader, []byte(short)); err == nil {
				err = writeOverMinute(c)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := <-originDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
