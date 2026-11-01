package core

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

const hardeningTestTimeout = 150 * time.Millisecond

func dialRaw(t *testing.T, ln *Listener) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func handshakeAsync(ln *Listener) chan error {
	result := make(chan error, 1)
	go func() {
		raw, err := ln.AcceptRaw()
		if err != nil {
			result <- err
			return
		}
		_, err = ln.Handshake(raw)
		result <- err
	}()
	return result
}

func TestListenHostBindsLoopbackOnly(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() {
		t.Fatalf("expected loopback bind, got %v", ip)
	}
}

func TestHandshakeTimesOutIdleClient(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetHandshakeTimeout(hardeningTestTimeout)
	result := handshakeAsync(ln)
	dialRaw(t, ln)

	select {
	case err := <-result:
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("expected idle handshake to fail with ErrHandshake, got %v", err)
		}
	case <-time.After(20 * hardeningTestTimeout):
		t.Fatal("handshake with an idle client never timed out")
	}
}

func TestHandshakeRejectsBadHello(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := handshakeAsync(ln)
	conn := dialRaw(t, ln)

	hello := make([]byte, clientHelloSize)
	putHelloPrefix(hello, MaxMessageSize)
	hello[len(protocolMagic)] = protocolVersion + 1
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("expected bad hello to fail with ErrHandshake, got %v", err)
		}
	case <-time.After(20 * hardeningTestTimeout):
		t.Fatal("bad hello was not rejected promptly")
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * hardeningTestTimeout)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("server answered a bad hello: n=%d err=%v", n, err)
	}
}

func TestAcceptRawThenHandshakeServesClient(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := make(chan *Conn, 1)
	go func() {
		raw, err := ln.AcceptRaw()
		if err != nil {
			server <- nil
			return
		}
		c, err := ln.Handshake(raw)
		if err != nil {
			server <- nil
			return
		}
		server <- c
	}()

	client, err := ConnectTimeout("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "pw", 20*hardeningTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s := <-server
	if s == nil {
		t.Fatal("server handshake failed")
	}
	defer s.Close()
	if err := client.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Recv()
	if err != nil || !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("round trip failed: %q %v", got, err)
	}
}

func TestAcceptNotBlockedByIdleClients(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	for range 4 {
		dialRaw(t, ln)
	}

	client, err := ConnectTimeout("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "pw", 4*hardeningTestTimeout)
	if err != nil {
		t.Fatalf("legitimate client starved by idle sockets: %v", err)
	}
	defer client.Close()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("Accept failed")
		}
		c.Close()
	case <-time.After(4 * hardeningTestTimeout):
		t.Fatal("Accept did not return the legitimate client")
	}
}

func TestAcceptSkipsFailedHandshakes(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
		accepted <- err
	}()

	garbage := dialRaw(t, ln)
	if _, err := garbage.Write(bytes.Repeat([]byte{0xAB}, clientHelloSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := Connect("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "wrong"); !errors.Is(err, ErrHandshake) {
		t.Fatalf("wrong-password client: expected ErrHandshake, got %v", err)
	}
	client, err := ConnectTimeout("127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "pw", 4*hardeningTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("Accept surfaced a failed client handshake: %v", err)
	}
}

func TestListenerCloseUnblocksAcceptAndAbortsHandshakes(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	acceptErr := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		acceptErr <- err
	}()
	idle := dialRaw(t, ln)
	waitFor(t, func() bool {
		ln.mu.Lock()
		defer ln.mu.Unlock()
		return len(ln.pending) == 1
	})

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acceptErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed from Accept after Close, got %v", err)
		}
	case <-time.After(4 * hardeningTestTimeout):
		t.Fatal("Accept did not return after Close")
	}
	if err := idle.SetReadDeadline(time.Now().Add(4 * hardeningTestTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := idle.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("in-flight handshake connection was not closed by Listener.Close: %v", err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed from Accept on a closed listener, got %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * hardeningTestTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
