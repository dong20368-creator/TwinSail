package main

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"testing/iotest"
)

func TestRelayCopy(t *testing.T) {
	for _, size := range []int{0, 25, smallBlock, bulkCopySize * 3} {
		payload := bytes.Repeat([]byte("a"), size)
		var dst bytes.Buffer
		src := iotest.DataErrReader(bytes.NewReader(payload))
		if err := copyRelayPayload(&dst, src); err != nil || !bytes.Equal(dst.Bytes(), payload) {
			t.Fatalf("copy %d bytes: wrote %d, err %v", size, dst.Len(), err)
		}
	}
	var dst bytes.Buffer
	src := iotest.DataErrReader(io.MultiReader(bytes.NewBufferString("last bytes"), iotest.ErrReader(io.ErrUnexpectedEOF)))
	if err := copyRelayPayload(&dst, src); err != io.ErrUnexpectedEOF || dst.String() != "last bytes" {
		t.Fatalf("copied %q, err %v", dst.String(), err)
	}
}

func BenchmarkRelayCopy(b *testing.B) {
	oldCopy := func(dst io.Writer, src io.Reader) error {
		_, err := io.Copy(dst, src)
		return err
	}
	for _, method := range []struct {
		name string
		copy func(io.Writer, io.Reader) error
	}{{"io.Copy", oldCopy}, {"pooled", copyRelayPayload}} {
		for _, input := range []struct {
			name     string
			size     int
			buffered bool
		}{{"stream1KiB", 1024, false}, {"stream1MiB", 1 << 20, false}, {"httpReader1KiB", 1024, true}} {
			b.Run(method.name+"/"+input.name, func(b *testing.B) {
				data := make([]byte, input.size)
				var raw bytes.Reader
				// QUIC streams and the underlying net/http connReader implement
				// Read without bytes.Reader's extra WriteTo optimization.
				var src io.Reader = struct{ io.Reader }{&raw}
				if input.buffered {
					src = bufio.NewReader(src)
				}
				dst := newDrainingWriter(io.Discard)
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					raw.Reset(data)
					if err := method.copy(dst, src); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
