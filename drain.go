package main

import (
	"io"
	"sync/atomic"
	"time"
)

const halfCloseIdle = 60 * time.Second

// One side can still send after the other side has sent FIN.
type drainingWriter struct {
	dst       io.Writer
	started   time.Time
	lastWrite atomic.Int64
}

func newDrainingWriter(dst io.Writer) *drainingWriter {
	return &drainingWriter{dst: dst, started: time.Now()}
}

func (w *drainingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.lastWrite.Store(int64(time.Since(w.started)))
	}
	return n, err
}

// Wait for the copying goroutine, allowing a full idle interval after FIN
// or its most recent successful write, whichever happened later.
func (w *drainingWriter) wait(done <-chan struct{}, idle time.Duration, abort func()) {
	select {
	case <-done:
		return
	default:
	}
	start := time.Since(w.started)
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-timer.C:
			last := max(start, time.Duration(w.lastWrite.Load()))
			remaining := idle - (time.Since(w.started) - last)
			if remaining <= 0 {
				abort()
				<-done
				return
			}
			timer.Reset(remaining)
		}
	}
}
