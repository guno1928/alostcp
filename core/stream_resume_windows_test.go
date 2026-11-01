package core

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestMidWriteTimeoutPoisonsOnWindows(t *testing.T) {
	client, _ := streamPair(t)
	data := randomPayload(t, stalledWriteSize)
	if err := client.SetWriteDeadline(time.Now().Add(streamTestTimeout)); err != nil {
		t.Fatal(err)
	}
	var err error
	for range 64 {
		if _, err = client.Write(data); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrConnBroken) {
		t.Fatalf("mid-write timeout on Windows returned %v, want ErrConnBroken", err)
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("poisoned write timeout %T does not report Timeout()", err)
	}
	if _, err := client.Write([]byte("x")); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("Write after poisoning returned %v", err)
	}
}
