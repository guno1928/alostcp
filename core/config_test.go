package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

const configTestTimeout = 2 * time.Second

func newConfigPair(t *testing.T, serverCfg, clientCfg *Config) (client, server *Conn) {
	t.Helper()
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan *Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), configTestTimeout)
	defer cancel()
	client, err = DialConfig(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, testPassword, clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(configTestTimeout):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"zero", Config{}, true},
		{"read buffer too small", Config{ReadBufferSize: 1000}, false},
		{"read buffer too large", Config{ReadBufferSize: maxBufferSize + 1}, false},
		{"read buffer negative", Config{ReadBufferSize: -1}, false},
		{"read buffer min", Config{ReadBufferSize: minBufferSize}, true},
		{"write buffer too small", Config{WriteBufferSize: minBufferSize - 1}, false},
		{"write buffer max", Config{WriteBufferSize: maxBufferSize}, true},
		{"message limit too small", Config{MaxMessageSize: 512}, false},
		{"message limit too large", Config{MaxMessageSize: MaxMessageSize + 1}, false},
		{"message limit min", Config{MaxMessageSize: minMessageLimit}, true},
		{"pending too large", Config{MaxPendingHandshakes: 70000}, false},
		{"pending negative", Config{MaxPendingHandshakes: -5}, false},
		{"pending one", Config{MaxPendingHandshakes: 1}, true},
		{"handshake timeout negative", Config{HandshakeTimeout: -1}, false},
		{"keepalive negative idle", Config{KeepAlive: &net.KeepAliveConfig{Enable: true, Idle: -1}}, false},
		{"keepalive negative count", Config{KeepAlive: &net.KeepAliveConfig{Enable: true, Count: -1}}, false},
		{"keepalive disabled", Config{KeepAlive: &net.KeepAliveConfig{}}, true},
	}
	for _, tc := range cases {
		_, _, err := tc.cfg.normalize()
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", tc.name, err)
		}
	}

	if _, err := ListenConfig("127.0.0.1", 0, testPassword, &Config{ReadBufferSize: 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ListenConfig accepted an invalid config: %v", err)
	}
	if _, err := DialConfig(context.Background(), "127.0.0.1", 1, testPassword, &Config{WriteBufferSize: 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("DialConfig accepted an invalid config: %v", err)
	}
}

func TestConfigZeroValueMatchesDefaults(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		conn, listen, err := cfg.normalize()
		if err != nil {
			t.Fatal(err)
		}
		if conn.readBufferSize != connBufferSize || conn.writeBufferSize != connBufferSize || conn.recvLimit != MaxMessageSize || conn.keepAlive != nil {
			t.Fatalf("conn defaults changed: %+v", conn)
		}
		if listen.handshakeTimeout != defaultHandshakeTimeout || listen.maxPending != defaultMaxPendingHandshakes || listen.acceptFilter != nil {
			t.Fatalf("listener defaults changed: %+v", listen)
		}
	}
}

func TestConfigIsCopiedAtCall(t *testing.T) {
	ka := &net.KeepAliveConfig{Enable: true, Idle: time.Minute}
	cfg := &Config{KeepAlive: ka}
	conn, _, err := cfg.normalize()
	if err != nil {
		t.Fatal(err)
	}
	ka.Idle = -1
	if conn.keepAlive.Idle != time.Minute {
		t.Fatal("normalized settings alias the caller's KeepAliveConfig")
	}
}

func TestAcceptFilterRejectsBeforeHandshake(t *testing.T) {
	var calls atomic.Int32
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, &Config{
		AcceptFilter: func(remote net.Addr) bool {
			if _, ok := remote.(*net.TCPAddr); !ok {
				t.Errorf("filter got %T, want *net.TCPAddr", remote)
			}
			calls.Add(1)
			return false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptDone := make(chan error, 1)
	if err := ln.SetDeadline(time.Now().Add(450 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := ln.Accept()
		acceptDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := DialConfig(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, testPassword, nil); err == nil {
		t.Fatal("client completed a handshake the filter rejected")
	}
	if err := <-acceptDone; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept returned %v, want a deadline error", err)
	}
	if calls.Load() < 1 {
		t.Fatal("AcceptFilter was never called")
	}
}

func TestAcceptFilterAllowsAccepted(t *testing.T) {
	var calls atomic.Int32
	client, server := newConfigPair(t, &Config{AcceptFilter: func(net.Addr) bool {
		calls.Add(1)
		return true
	}}, nil)
	if err := client.SendString("through the filter"); err != nil {
		t.Fatal(err)
	}
	if got, err := server.RecvString(); err != nil || got != "through the filter" {
		t.Fatalf("got %q, %v", got, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("filter called %d times, want 1", calls.Load())
	}
}

func TestMaxPendingHandshakesConfig(t *testing.T) {
	const idleTimeout = 450 * time.Millisecond
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, &Config{MaxPendingHandshakes: 1, HandshakeTimeout: idleTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	idle := dialRaw(t, ln)
	defer idle.Close()
	waitFor(t, func() bool {
		ln.mu.Lock()
		defer ln.mu.Unlock()
		return len(ln.pending) == 1
	})

	dialed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), configTestTimeout)
		defer cancel()
		c, err := DialConfig(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, testPassword, nil)
		if err == nil {
			c.Close()
		}
		dialed <- err
	}()

	select {
	case err := <-dialed:
		t.Fatalf("client finished while the only handshake slot was held: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := <-dialed; err != nil {
		t.Fatalf("client failed after the idle handshake timed out: %v", err)
	}
	if err := idle.SetReadDeadline(time.Now().Add(configTestTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle socket was not closed by the handshake timeout")
	}
}

func TestKeepAliveConfigApplied(t *testing.T) {
	for _, ka := range []*net.KeepAliveConfig{
		{Enable: true, Idle: 150 * time.Millisecond, Interval: 150 * time.Millisecond, Count: 3},
		{Enable: false},
	} {
		cfg := &Config{KeepAlive: ka}
		client, server := newConfigPair(t, cfg, cfg)
		if err := client.SendString("ping"); err != nil {
			t.Fatal(err)
		}
		if got, err := server.RecvString(); err != nil || got != "ping" {
			t.Fatalf("keepalive %+v: got %q, %v", *ka, got, err)
		}
	}
}

func TestLocalMaxMessageSizeEnforced(t *testing.T) {
	const limit = 64 << 10
	client, server := newConfigPair(t, &Config{MaxMessageSize: limit}, &Config{MaxMessageSize: limit})

	if err := client.Send(make([]byte, limit+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Send over the limit returned %v", err)
	}
	if err := client.SendBuffered(make([]byte, limit+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("SendBuffered over the limit returned %v", err)
	}
	if err := client.Send(make([]byte, limit)); err != nil {
		t.Fatalf("Send at the limit failed: %v", err)
	}
	if msg, err := server.Recv(); err != nil || len(msg) != limit {
		t.Fatalf("Recv at the limit: %d bytes, %v", len(msg), err)
	}

	if _, err := client.tcp.Write(sealRawFrame(client, make([]byte, limit+1), 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Recv(); !errors.Is(err, ErrConnBroken) || !errors.Is(err, errInvalidFrame) {
		t.Fatalf("receiver accepted a frame over its limit: %v", err)
	}
}

func TestCustomBufferSizesRoundTrip(t *testing.T) {
	const messages = 1000
	cfg := &Config{ReadBufferSize: minBufferSize, WriteBufferSize: minBufferSize}
	client, server := newConfigPair(t, cfg, cfg)

	sent := make([][]byte, messages)
	for i := range sent {
		n, err := rand.Int(rand.Reader, big.NewInt(70<<10))
		if err != nil {
			t.Fatal(err)
		}
		sent[i] = make([]byte, 1+int(n.Int64()))
		rand.Read(sent[i])
	}
	sendErr := make(chan error, 1)
	go func() {
		for _, msg := range sent {
			if err := client.SendBuffered(msg); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- client.Flush()
	}()
	for i, want := range sent {
		got, err := server.Recv()
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d corrupted (%d bytes)", i, len(want))
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatal(err)
	}
	client.Close()
	if _, err := server.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after close: %v", err)
	}
}
