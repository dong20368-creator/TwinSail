package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestForwardFrameDeliversBeforeTail(t *testing.T) {
	src, feed := net.Pipe()
	dst, observed := net.Pipe()
	for _, c := range []net.Conn{src, feed, dst, observed} {
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	done := make(chan error, 1)
	go func() { done <- forwardFrame(dst, src, make([]byte, len(payload))) }()

	// Release one fragment at a time. Its last byte must reach the application
	// before the relay can read anything from the next fragment.
	received := make([]byte, len(payload))
	start := 0
	for _, end := range []int{375, 375 + 16384, len(payload)} {
		if _, err := feed.Write(payload[start:end]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(observed, received[start:end]); err != nil {
			t.Fatalf("frame bytes [%d,%d) were withheld: %v", start, end, err)
		}
		start = end
	}
	if err := <-done; err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("frame delivery mismatch: %v", err)
	}
}

type frameRecorder struct {
	bytes.Buffer
	writes int
}

func (w *frameRecorder) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func TestForwardFrameBufferedAndBounded(t *testing.T) {
	frame := bytes.Repeat([]byte("abc"), 20000)
	src := bytes.NewReader(append(frame, 1, 2, 3))
	var dst frameRecorder
	if err := forwardFrame(&dst, src, make([]byte, len(frame))); err != nil {
		t.Fatal(err)
	}
	if dst.writes != 1 || src.Len() != 3 || !bytes.Equal(dst.Bytes(), frame) {
		t.Fatalf("buffered delivery: %d writes, %d bytes left", dst.writes, src.Len())
	}
	if err := forwardFrame(io.Discard, src, make([]byte, 4)); err != io.ErrUnexpectedEOF {
		t.Fatalf("short frame returned %v", err)
	}
}
