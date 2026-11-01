//go:build !windows

package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestPartialWriteTimeoutRecovers(t *testing.T) {
	client, server := streamPair(t)
	data := randomPayload(t, stalledWriteSize)
	n := stallWrite(t, client, data)

	received := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		got := make([]byte, len(data))
		if _, err := io.ReadFull(server, got); err != nil {
			readErr <- err
			return
		}
		received <- got
	}()
	if m, err := client.Write(data[n:]); err != nil || m != len(data)-n {
		t.Fatalf("resumed Write: %d, %v", m, err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, data) {
			t.Fatal("peer received different bytes after the recovered timeout")
		}
	case err := <-readErr:
		t.Fatalf("peer read failed after the recovered timeout: %v", err)
	}
}

func TestCloseAfterRecoveredWriteTimeout(t *testing.T) {
	client, server := streamPair(t)
	data := randomPayload(t, stalledWriteSize)
	n := stallWrite(t, client, data)

	result := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(server)
		if err == nil && !bytes.Equal(got, data[:n]) {
			err = errors.New("peer bytes differ from the accepted prefix")
		}
		result <- err
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func stallWrite(t *testing.T, client *Conn, data []byte) int {
	t.Helper()
	if err := client.SetWriteDeadline(time.Now().Add(streamTestTimeout)); err != nil {
		t.Fatal(err)
	}
	n, err := client.Write(data)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled Write returned n=%d err=%v, want a timeout", n, err)
	}
	if n >= len(data) {
		t.Fatalf("stalled Write reported all %d bytes; the socket never filled", n)
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return n
}
