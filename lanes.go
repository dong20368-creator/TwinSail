package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	quic "github.com/sagernet/quic-go"
)

// After the marker, each lane sends the same random 128-bit tunnel ID,
// lane count and index. Lane zero adds the length-prefixed TCP destination
// and carries uploads. Interactive streams send the first 32 KiB on the
// primary lane, then distribute the remaining length-prefixed blocks in round-robin
// order; a zero length in the next lane signals a clean downstream EOF.
const stripedMarker = 0xffff
const interactiveMarker = 0xfffe
const maxBlock = 64 * 1024

// Reuse frame storage across tunnels. A server frame includes its four-byte header.
var frameBuffers = sync.Pool{New: func() any { return new([maxBlock]byte) }}

const smallBlock = 4096

var smallFrames = sync.Pool{New: func() any { return new([smallBlock]byte) }}

type laneGroup struct {
	streams     []*quic.Stream
	interactive bool
	ready       chan struct{}
	complete    bool
}

var pending = struct {
	sync.Mutex
	groups map[[16]byte]*laneGroup
}{groups: make(map[[16]byte]*laneGroup)}

func reset(s *quic.Stream) { s.CancelRead(1); s.CancelWrite(1) }
func acceptLane(s *quic.Stream, interactive bool, dial targetDialer) {
	var hdr [18]byte
	if _, e := io.ReadFull(s, hdr[:]); e != nil {
		reset(s)
		return
	}
	var id [16]byte
	copy(id[:], hdr[:16])
	count, index := int(hdr[16]), int(hdr[17])
	if count < 2 || count > 4 || index >= count {
		reset(s)
		return
	}
	var target string
	if index == 0 {
		var l uint16
		if binary.Read(s, binary.BigEndian, &l) != nil || l == 0 || l > maxTarget {
			reset(s)
			return
		}
		data := make([]byte, l)
		if _, e := io.ReadFull(s, data); e != nil {
			reset(s)
			return
		}
		target = string(data)
	}
	pending.Lock()
	g := pending.groups[id]
	if g == nil {
		if len(pending.groups) >= 128 {
			pending.Unlock()
			reset(s)
			return
		}
		g = &laneGroup{interactive: interactive, streams: make([]*quic.Stream, count), ready: make(chan struct{})}
		pending.groups[id] = g
	}
	if g.interactive != interactive || len(g.streams) != count || g.streams[index] != nil {
		pending.Unlock()
		reset(s)
		return
	}
	g.streams[index] = s

	full := true
	for _, lane := range g.streams {
		if lane == nil {
			full = false
			break
		}
	}
	if full {
		g.complete = true
		delete(pending.groups, id)
		close(g.ready)
	}
	pending.Unlock()
	var origin net.Conn
	var dialErr error
	if index == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		origin, dialErr = dial(ctx, target)
		cancel()
		if origin != nil {
			defer origin.Close()
		}
	}
	select {
	case <-g.ready:
	case <-time.After(10 * time.Second):
		pending.Lock()
		if pending.groups[id] == g {
			delete(pending.groups, id)
			close(g.ready)
		}
		pending.Unlock()
		<-g.ready
	}
	if !g.complete {
		reset(s)
		return
	}
	// Only the primary handler owns the joined streams. Other handlers must
	// not cancel their receive halves while the primary is forwarding.
	if index != 0 {
		return
	}
	serveGroup(g, origin, dialErr)
}

func serveGroup(g *laneGroup, c net.Conn, err error) {
	for _, s := range g.streams {
		s.SetDeadline(time.Time{})
		defer s.CancelRead(0)
	}

	if err != nil {
		for _, s := range g.streams {
			reset(s)
		}
		return
	}
	defer c.Close()
	uploadDone := make(chan struct{})
	writer := newDrainingWriter(c)
	go func() {
		e := copyRelayPayload(writer, g.streams[0])
		if t, ok := c.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		if e != nil {
			c.Close()
		}
		close(uploadDone)
	}()
	small := smallFrames.Get().(*[smallBlock]byte)
	defer smallFrames.Put(small)
	buf := small[:]
	next := 0
	var delivered uint64
	for {
		n, e := c.Read(buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf[:4], uint32(n))
			_, err = g.streams[next].Write(buf[:4+n])
			if err != nil {
				break
			}
			delivered += uint64(n)
			if len(buf) == smallBlock && n == smallBlock-4 {
				large := frameBuffers.Get().(*[maxBlock]byte)
				defer frameBuffers.Put(large)
				buf = large[:]
			}
			if !g.interactive || delivered >= 32768 {
				next = (next + 1) % len(g.streams)
			}
		}
		if e != nil {
			err = e
			if e == io.EOF {
				_, err = g.streams[next].Write([]byte{0, 0, 0, 0})
			}
			break
		}
	}
	for _, s := range g.streams {
		if err == nil {
			s.Close()
		} else {
			reset(s)
		}
	}
	if err != nil {
		c.Close()
	}
	writer.wait(uploadDone, halfCloseIdle, func() {
		g.streams[0].CancelRead(1)
		c.Close()
	})
}

func (p *client) serveStriped(ctx context.Context, w http.ResponseWriter, r *http.Request, lanes []*client) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		http.Error(w, "random source unavailable", 503)
		return
	}

	best := time.Duration(1<<63 - 1)
	primary := 0
	for i, l := range lanes {
		if c := l.currentSession(); c != nil {
			stats := c.ConnectionStats()
			score := stats.SmoothedRTT + stats.MeanDeviation
			if score > 0 && score < best {
				best = score
				primary = i
			}
		}
	}
	lanes[0], lanes[primary] = lanes[primary], lanes[0]
	streams := make([]*quic.Stream, len(lanes))
	var wg sync.WaitGroup
	for i, lane := range lanes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := lane.stream(ctx)
			if e != nil {
				return
			}
			h := make([]byte, 20, 22+len(r.Host))
			binary.BigEndian.PutUint16(h, interactiveMarker)
			copy(h[2:], id[:])
			h[18] = byte(len(streams))
			h[19] = byte(i)
			if i == 0 {
				h = binary.BigEndian.AppendUint16(h, uint16(len(r.Host)))
				h = append(h, r.Host...)
			}
			s.SetWriteDeadline(time.Now().Add(12 * time.Second))
			if _, e = s.Write(h); e != nil {
				reset(s)
				return
			}
			s.SetWriteDeadline(time.Time{})
			if i != 0 {
				s.Close()
			}
			streams[i] = s
		}()
	}
	wg.Wait()
	for _, s := range streams {
		if s == nil {
			for _, v := range streams {
				if v != nil {
					reset(v)
				}
			}
			http.Error(w, "relay unavailable", 502)
			return
		}
	}
	defer func() {
		for _, s := range streams {
			s.CancelRead(0)
		}
	}()
	c, b, e := w.(http.Hijacker).Hijack()
	if e != nil {
		for _, s := range streams {
			reset(s)
		}
		return
	}
	defer c.Close()
	if _, e = b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e == nil {
		e = b.Flush()
	}
	if e != nil {
		for _, s := range streams {
			reset(s)
		}
		return
	}
	done := make(chan struct{})
	writer := newDrainingWriter(streams[0])
	go func() {
		_, e := io.Copy(writer, b.Reader)
		if e == nil {
			streams[0].Close()
		} else {
			streams[0].CancelWrite(1)
		}
		close(done)
	}()
	small := smallFrames.Get().(*[smallBlock]byte)
	defer smallFrames.Put(small)
	buf := small[:]
	var header [4]byte
	var delivered uint64
	for i := 0; ; {
		if _, e = io.ReadFull(streams[i], header[:]); e != nil {
			break
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 {
			break
		}
		if n > maxBlock {
			e = io.ErrUnexpectedEOF
			break
		}
		if int(n) > len(buf) {
			large := frameBuffers.Get().(*[maxBlock]byte)
			defer frameBuffers.Put(large)
			buf = large[:]
		}
		if e = forwardFrame(c, streams[i], buf[:n]); e != nil {
			break
		}
		delivered += uint64(n)
		if delivered >= 32768 {
			i = (i + 1) % len(streams)
		}
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	if e != nil {
		c.Close()
		for _, s := range streams {
			reset(s)
		}
	}
	writer.wait(done, halfCloseIdle, func() {
		c.Close()
		streams[0].CancelWrite(1)
	})
}

// Forward the first available bytes immediately. On fragmented bulk frames,
// batch subsequent reads so each QUIC packet doesn't need a separate TCP write.
func forwardFrame(dst io.Writer, src io.Reader, frame []byte) error {
	minRead := 1
	for len(frame) > 0 {
		n, err := io.ReadAtLeast(src, frame, min(minRead, len(frame)))
		if n > 0 {
			written, writeErr := dst.Write(frame[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			frame = frame[n:]
		}
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		minRead = 16 * 1024
	}
	return nil
}
