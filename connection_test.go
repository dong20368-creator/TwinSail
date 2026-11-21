package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

func TestColdStartUsesFirstConnectedLane(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}
	var handshakes atomic.Int32
	serverTLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return nil, nil
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	healthy := &client{address: listener.Addr().String(), tls: &tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13}}
	defer func() {
		if c := healthy.currentSession(); c != nil {
			c.CloseWithError(0, "test complete")
		}
	}()
	// Leave one handshake pending. Neither a burst of cold requests nor a
	// subsequent warm request may wait for it.
	stalled := &client{dialing: &sessionDial{done: make(chan struct{})}}
	p := &client{lanes: []*client{stalled, healthy}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const callers = 16
	start := make(chan struct{})
	selected := make(chan []*client, callers)
	for range callers {
		go func() {
			<-start
			selected <- p.readyLanes(ctx)
		}()
	}
	close(start)
	for i := 0; i < callers; i++ {
		lanes := <-selected
		if len(lanes) != 1 || lanes[0] != healthy {
			t.Fatalf("request %d selected %d lanes, want only the connected lane", i+1, len(lanes))
		}
	}
	if lanes := p.readyLanes(ctx); len(lanes) != 1 || lanes[0] != healthy {
		t.Fatal("warm request failed to reuse the connected lane")
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("%d TLS handshakes for %d callers, want one", got, callers)
	}
}

func TestCanceledWaiterLeavesSharedHandshake(t *testing.T) {
	d := &sessionDial{done: make(chan struct{})}
	lane := &client{dialing: d}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := lane.connect(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v", err)
	}
	if _, shared := lane.startConnect(); shared != d {
		t.Fatal("waiter's deadline replaced the in-flight handshake")
	}
	d.err = errors.New("handshake completed with an error")
	close(d.done)
	if _, err := lane.connect(context.Background()); err != d.err {
		t.Fatalf("other waiter missed the shared result: %v", err)
	}
}
