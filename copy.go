package main

import (
	"bufio"
	"io"
	"sync"
)

const bulkCopySize = 32 * 1024

var bulkCopies = sync.Pool{New: func() any { return new([bulkCopySize]byte) }}

// These copies have a QUIC stream on one side, so TCP splice and sendfile
// cannot apply. A hijacked HTTP reader already owns a buffer and can drain it.
func copyRelayPayload(dst io.Writer, src io.Reader) error {
	if buffered, ok := src.(*bufio.Reader); ok {
		_, err := buffered.WriteTo(dst)
		return err
	}
	small := smallFrames.Get().(*[smallBlock]byte)
	buf := small[:]
	var bulk *[bulkCopySize]byte
	defer func() {
		if bulk != nil {
			bulkCopies.Put(bulk)
		} else {
			smallFrames.Put(small)
		}
	}()
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, err := dst.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
		if n == smallBlock && bulk == nil {
			bulk = bulkCopies.Get().(*[bulkCopySize]byte)
			buf = bulk[:]
			smallFrames.Put(small)
		}
	}
}
