package main

import (
	"io"
	"testing"
	"testing/synctest"
	"time"
)

func TestHalfCloseIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newDrainingWriter(io.Discard)
		done := make(chan struct{})
		stopped := make(chan struct{})
		go w.wait(done, halfCloseIdle, func() { close(stopped); close(done) })
		synctest.Wait()
		for i := 0; i < 4; i++ {
			time.Sleep(halfCloseIdle * 3 / 4)
			synctest.Wait()
			select {
			case <-stopped:
				t.Fatal("active half-closed transfer was stopped")
			default:
			}
			w.Write([]byte("still sending"))
		}
		time.Sleep(halfCloseIdle - time.Second)
		synctest.Wait()
		select {
		case <-stopped:
			t.Fatal("did not grant a full interval after the last write")
		default:
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-stopped:
		default:
			t.Fatal("idle half-closed transfer was not stopped")
		}
	})
}
