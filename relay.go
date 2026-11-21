package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	bbr "github.com/sagernet/sing-quic/congestion_meta2"
	paced "github.com/sagernet/sing-quic/hysteria/congestion"
)

// One mutually authenticated QUIC connection multiplexes TCP tunnels.
// Stream request: uint16 big-endian length, then host:port. Reply: 0=ready, 1=failed.
// After success each direction carries bytes; FIN half-closes that direction.
const alpn = "r76-relay/1"
const maxTarget = 260

var transport = &quic.Config{KeepAlivePeriod: 15 * time.Second, MaxIdleTimeout: 90 * time.Second, MaxIncomingStreams: 256, MaxIncomingUniStreams: -1, InitialStreamReceiveWindow: 4 << 20, MaxStreamReceiveWindow: 16 << 20, InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 32 << 20}

func credentials(dir, role string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, role+".crt"), filepath.Join(dir, role+".key"))
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("bad CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, ServerName: "relay.internal", MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}, nil
}

func publicDial(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("bad port")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	var dial net.Dialer
	return dialPublicIPs(ctx, ips, port, dial.DialContext)
}

var sharedIPv4 = netip.MustParsePrefix("100.64.0.0/10")

func dialPublicIPs(ctx context.Context, ips []netip.Addr, port string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	// Compact the lookup result in place, keeping only validated numeric addresses.
	public := ips[:0]
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.As4()[0] == 0 || sharedIPv4.Contains(ip) {
			continue
		}
		public = append(public, ip)
	}
	for i, ip := range public {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt := ctx
		cancel := func() {}
		if remaining := len(public) - i; remaining > 1 {
			// Bound a stalled connect and reserve time for the other addresses.
			timeout := 2 * time.Second
			if deadline, ok := ctx.Deadline(); ok {
				timeout = min(timeout, time.Until(deadline)/time.Duration(remaining))
			}
			attempt, cancel = context.WithTimeout(ctx, timeout)
		}
		c, err := dial(attempt, "tcp4", net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return c, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("destination unavailable")
}

func bridge(s *quic.Stream, c net.Conn, fromTCP io.Reader, awaitReply bool) {
	defer c.Close()
	done := make(chan struct{})
	writer := newDrainingWriter(s)
	go func() {
		e := copyRelayPayload(writer, fromTCP)
		if e != nil {
			s.CancelWrite(1)
		} else {
			_ = s.Close()
		}
		close(done)
	}()
	if awaitReply {
		s.SetReadDeadline(time.Now().Add(12 * time.Second))
		var reply [1]byte
		if _, e := io.ReadFull(s, reply[:]); e != nil || reply[0] != 0 {
			s.CancelWrite(1)
			c.Close()
			<-done
			return
		}
		s.SetReadDeadline(time.Time{})
	}
	err := copyRelayPayload(c, s)
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
	if err != nil {
		_ = c.Close()
	}
	writer.wait(done, halfCloseIdle, func() {
		s.CancelWrite(1)
		c.Close()
	})
}

type targetDialer func(context.Context, string) (net.Conn, error)

func acceptStream(s *quic.Stream, dial targetDialer) {
	defer s.CancelRead(0)
	s.SetDeadline(time.Now().Add(12 * time.Second))
	var n uint16
	if binary.Read(s, binary.BigEndian, &n) != nil {
		s.CancelWrite(1)
		return
	}
	if n == stripedMarker || n == interactiveMarker {
		acceptLane(s, n == interactiveMarker, dial)
		return
	}
	if n == 0 || n > maxTarget {
		s.CancelWrite(1)
		return
	}
	dest := make([]byte, n)
	if _, err := io.ReadFull(s, dest); err != nil {
		s.CancelWrite(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	c, err := dial(ctx, string(dest))
	cancel()
	if err != nil {
		s.Write([]byte{1})
		s.Close()
		return
	}
	if _, err = s.Write([]byte{0}); err != nil {
		c.Close()
		return
	}
	s.SetDeadline(time.Time{})
	bridge(s, c, c, false)
}

type client struct {
	unavailable atomic.Bool
	suspect     atomic.Bool
	uploadMbps  int
	lanes       []*client
	mu          sync.Mutex
	session     *quic.Conn
	dialing     *sessionDial
	address     string
	tls         *tls.Config
}

type sessionDial struct {
	done chan struct{}
	conn *quic.Conn
	err  error
}

func (p *client) currentSession() *quic.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != nil && p.session.Context().Err() == nil {
		return p.session
	}
	return nil
}

// A warm-up belongs to the lane, so canceling one CONNECT cannot abort
// the shared handshake for other callers. The handshake has its own bound.
func (p *client) startConnect() (*quic.Conn, *sessionDial) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != nil && p.session.Context().Err() == nil {
		return p.session, nil
	}
	if p.dialing != nil {
		return nil, p.dialing
	}
	d := &sessionDial{done: make(chan struct{})}
	p.dialing = d
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg := transport.Clone()
		cfg.KeepAlivePeriod = clientKeepalive
		c, err := quic.DialAddr(ctx, p.address, p.tls, cfg)
		if err == nil {
			if p.uploadMbps > 0 {
				c.SetCongestionControl(paced.NewBrutalSender(uint64(p.uploadMbps)*125000, c.InitialPacketSize(), false, nil))
			} else {
				c.SetCongestionControl(bbr.NewBbrSenderWithProfile(c.InitialPacketSize(), bbr.ProfileStandard))
			}
		}
		p.mu.Lock()
		p.session = c
		p.dialing = nil
		d.conn, d.err = c, err
		close(d.done)
		p.mu.Unlock()
	}()
	return nil, d
}

func (p *client) connect(ctx context.Context) (*quic.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, d := p.startConnect()
	if c != nil {
		return c, nil
	}
	select {
	case <-d.done:
		return d.conn, d.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Select all established lanes immediately. If every lane is cold, race
// only the handshakes; the destination and application bytes are sent once.
func (p *client) readyLanes(ctx context.Context) []*client {
	var ready []*client
	var fallback *client
	type warmingLane struct {
		lane *client
		dial *sessionDial
	}
	var warming []warmingLane
	for _, lane := range p.lanes {
		if lane.unavailable.Load() {
			continue
		}
		if c, d := lane.startConnect(); c != nil {
			if lane.suspect.Load() {
				if fallback == nil {
					fallback = lane
				}
				continue
			}
			ready = append(ready, lane)
		} else {
			warming = append(warming, warmingLane{lane, d})
		}
	}
	if len(ready) > 0 {
		return ready
	}
	if fallback != nil {
		return []*client{fallback}
	}
	if len(warming) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan *client, len(warming))
	for _, w := range warming {
		go func() {
			select {
			case <-w.dial.done:
				if w.dial.err != nil {
					result <- nil
				} else {
					result <- w.lane
				}
			case <-ctx.Done():
			}
		}()
	}
	for range warming {
		select {
		case lane := <-result:
			if lane != nil {
				return []*client{lane}
			}
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}
func (p *client) stream(ctx context.Context) (*quic.Stream, error) {
	c, e := p.connect(ctx)
	if e != nil {
		return nil, e
	}
	return c.OpenStreamSync(ctx)
}
func (p *client) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || len(r.Host) > maxTarget {
		http.Error(w, "CONNECT required", 405)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if len(p.lanes) > 1 {
		live := p.readyLanes(ctx)
		switch len(live) {
		case 0:
			http.Error(w, "relay unavailable", 502)
			return
		case 1:
			p = live[0]
		default:
			p.serveStriped(ctx, w, r, live)
			return
		}
	}
	s, err := p.stream(ctx)
	if err != nil {
		http.Error(w, "relay unavailable", 502)
		return
	}
	defer s.CancelRead(0)
	s.SetDeadline(time.Now().Add(12 * time.Second))
	frame := make([]byte, 2+len(r.Host))
	binary.BigEndian.PutUint16(frame, uint16(len(r.Host)))
	copy(frame[2:], r.Host)
	if _, err = s.Write(frame); err != nil {
		s.CancelWrite(1)
		http.Error(w, "destination unavailable", 502)
		return
	}
	c, b, err := w.(http.Hijacker).Hijack()
	if err != nil {
		s.CancelWrite(1)
		return
	}
	if _, err = b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
		err = b.Flush()
	}
	if err != nil {
		c.Close()
		s.CancelWrite(1)
		return
	}
	s.SetDeadline(time.Time{})
	bridge(s, c, b.Reader, true)
}

func main() {
	role := flag.String("role", "client", "server or client")
	addr := flag.String("endpoint", "", "QUIC server host:port")
	local := flag.String("listen", "127.0.0.1:19683", "loopback CONNECT listener")
	dir := flag.String("keys", ".", "certificate directory")
	rate := flag.Int("send-mbps", 0, "server target in decimal Mbps; zero uses adaptive BBR")
	lanes := flag.Int("lanes", 2, "number of independent downstream QUIC connections (1 to 4)")
	upload := flag.Int("upload-mbps", 0, "client upload pacing target in Mbps; zero uses adaptive BBR")
	flag.Parse()
	if *upload < 0 || *upload > 1000 {
		log.Fatal("invalid upload-mbps")
	}
	if *lanes < 1 || *lanes > 4 {
		log.Fatal("invalid lane count")
	}
	if *rate < 0 || *rate > 1000 {
		log.Fatal("invalid send-mbps")
	}
	if *role != "server" && *role != "client" {
		log.Fatal("invalid role")
	}
	cfg, err := credentials(*dir, *role)
	if err != nil {
		log.Fatal(err)
	}
	if *role == "client" {
		h, _, e := net.SplitHostPort(*local)
		if e != nil || !net.ParseIP(h).IsLoopback() {
			log.Fatal("local listener requires loopback")
		}
		p := &client{address: *addr, tls: cfg, uploadMbps: *upload}
		for i := 0; i < *lanes; i++ {
			p.lanes = append(p.lanes, &client{address: *addr, tls: cfg, uploadMbps: *upload})
		}
		warm := p.lanes
		if len(warm) == 1 {
			warm = []*client{p}
		}
		for _, lane := range warm {
			go lane.watchPath(context.Background())
		}
		srv := &http.Server{Addr: *local, Handler: p, ReadHeaderTimeout: 8 * time.Second, MaxHeaderBytes: 8192}
		log.Fatal(srv.ListenAndServe())
	}
	l, err := listenRelay(*addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("relay ready")
	for {
		c, e := l.Accept(context.Background())
		if e != nil {
			log.Fatal(e)
		}
		if *rate == 0 {
			c.SetCongestionControl(bbr.NewBbrSenderWithProfile(c.InitialPacketSize(), bbr.ProfileStandard))
		} else {
			c.SetCongestionControl(paced.NewBrutalSender(uint64(*rate)*125000, c.InitialPacketSize(), false, nil))
		}
		go func() {
			for {
				s, e := c.AcceptStream(c.Context())
				if e != nil {
					return
				}
				go acceptStream(s, publicDial)
			}
		}()
	}
}

// When systemd owns the UDP socket it can set its buffers before passing
// it to the unprivileged service. A manually launched server binds normally.
func listenRelay(addr string, cfg *tls.Config) (*quic.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") == "" {
		return quic.ListenAddr(addr, cfg, transport)
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("expected one UDP socket from systemd")
	}
	f := os.NewFile(3, "relay-udp")
	if f == nil {
		return nil, errors.New("missing socket from systemd")
	}
	defer f.Close()
	pc, e := net.FilePacketConn(f)
	if e != nil {
		return nil, e
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("inherited socket is not UDP")
	}
	listener, e := quic.Listen(udp, cfg, transport)
	if e != nil {
		udp.Close()
	}
	return listener, e
}

const clientKeepalive = 3 * time.Second

// An idle quic-go connection schedules a PING after at least 1.5 PTO.
// Allow time for a response and a retry before steering new tunnels away.
// Both endpoints use the library's default maximum ACK delay (25ms plus
// 1ms timer granularity). No extra probe traffic is required.
func pathTimeouts(stats quic.ConnectionStats) (response, avoid, retire time.Duration) {
	pto := stats.SmoothedRTT + max(4*stats.MeanDeviation, time.Millisecond) + 26*time.Millisecond
	response = max(2*time.Second, 2*pto)
	avoid = max(clientKeepalive, 3*pto/2) + response
	retire = max(10*time.Second, avoid+response)
	return
}

func (p *client) watchPath(ctx context.Context) {
	var previous *quic.Conn
	var received, sentAtProgress uint64
	var lastProgress, firstSend time.Time
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := p.connect(attempt)
		cancel()
		now := time.Now()
		if err != nil {
			p.unavailable.Store(true)
		} else {
			stats := c.ConnectionStats()
			if previous != c || stats.PacketsReceived != received {
				previous, received, lastProgress = c, stats.PacketsReceived, now
				sentAtProgress = stats.PacketsSent
				firstSend = time.Time{}
				p.suspect.Store(false)
				p.unavailable.Store(false)
			} else if stats.PacketsSent != sentAtProgress {
				if firstSend.IsZero() {
					firstSend = now
				}
				response, avoid, retire := pathTimeouts(stats)
				silence := now.Sub(lastProgress)
				if silence >= avoid && now.Sub(firstSend) >= response {
					p.suspect.Store(true)
					if silence >= retire {
						p.unavailable.Store(true)
						_ = c.CloseWithError(0, "path unresponsive")
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
