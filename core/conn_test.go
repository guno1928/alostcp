package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestConnRoundTrip(t *testing.T) {
	client, server := newConnPair(t)

	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 64, 256, 1024, 4096, 16384, 65536, 1 << 20}
	for _, sz := range sizes {
		msg := make([]byte, sz)
		rand.Read(msg)

		if err := client.Send(msg); err != nil {
			t.Fatalf("size %d: send: %v", sz, err)
		}
		got, err := server.Recv()
		if err != nil {
			t.Fatalf("size %d: recv: %v", sz, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: payload mismatch", sz)
		}
	}
}

func TestConnRoundTripBothDirections(t *testing.T) {
	client, server := newConnPair(t)

	for i := 0; i < 100; i++ {
		msg := make([]byte, 1+i*37)
		rand.Read(msg)
		if err := client.Send(msg); err != nil {
			t.Fatal(err)
		}
		got, err := server.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("iter %d client->server mismatch", i)
		}

		reply := make([]byte, 1+i*53)
		rand.Read(reply)
		if err := server.Send(reply); err != nil {
			t.Fatal(err)
		}
		got, err = client.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, reply) {
			t.Fatalf("iter %d server->client mismatch", i)
		}
	}
}

func TestConnRecvInto(t *testing.T) {
	client, server := newConnPair(t)
	buf := make([]byte, 1<<20)
	for _, sz := range []int{0, 1, 32, 1000, 65536} {
		msg := make([]byte, sz)
		rand.Read(msg)
		if err := client.Send(msg); err != nil {
			t.Fatal(err)
		}
		n, err := server.RecvInto(buf)
		if err != nil {
			t.Fatalf("size %d: %v", sz, err)
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Fatalf("size %d: RecvInto mismatch", sz)
		}
	}
}

func TestConnWrongPassword(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	listener := &Listener{ln: ln, password: "correct-password"}

	errCh := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		errCh <- err
	}()

	addr := ln.Addr().(*net.TCPAddr)
	_, err = Connect("127.0.0.1", addr.Port, "wrong-password")
	if err == nil {
		t.Fatal("expected client handshake to fail with wrong password")
	}
	if serr := <-errCh; serr == nil {
		t.Fatal("expected server handshake to reject wrong password")
	}
}

func TestConnTamperRejected(t *testing.T) {
	client, server := newConnPair(t)

	msg := make([]byte, 500)
	rand.Read(msg)

	cipherLen := len(msg) + tagSize
	frame := make([]byte, 4+cipherLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))
	client.cipher.seal(frame[4:], msg, frame[0:4])
	frame[4+200] ^= 0x80

	if _, err := client.tcp.Write(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Recv(); err == nil {
		t.Fatal("server accepted a tampered frame")
	}
}

func TestConnTamperedLengthRejected(t *testing.T) {
	client, server := newConnPair(t)

	msg := make([]byte, 300)
	rand.Read(msg)

	cipherLen := len(msg) + tagSize
	frame := make([]byte, 4+cipherLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))
	client.cipher.seal(frame[4:], msg, frame[0:4])
	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen+0))
	frame[2] ^= 0x01

	if _, err := client.tcp.Write(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Recv(); err == nil {
		t.Fatal("server accepted a frame with tampered length AD")
	}
}

func TestConnConcurrentSenders(t *testing.T) {
	client, server := newConnPair(t)

	const senders = 8
	const perSender = 200
	total := senders * perSender

	want := make(map[string]int)
	var mu sync.Mutex

	var wg sync.WaitGroup
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				msg := make([]byte, 16+((s*7+i)%200))
				rand.Read(msg)
				mu.Lock()
				want[string(msg)]++
				mu.Unlock()
				if err := client.Send(msg); err != nil {
					t.Errorf("send: %v", err)
					return
				}
			}
		}(s)
	}

	got := make(map[string]int)
	recvErr := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			b, err := server.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			got[string(b)]++
		}
		recvErr <- nil
	}()

	wg.Wait()
	if err := <-recvErr; err != nil {
		t.Fatalf("recv: %v", err)
	}

	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if got[k] != want[k] {
			t.Fatalf("message multiset mismatch: got %d want %d for a payload", got[k], want[k])
		}
	}
}

func stallingListener(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			_ = conn
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestConnectTimeoutDuringHandshake(t *testing.T) {
	ln := stallingListener(t)
	port := ln.Addr().(*net.TCPAddr).Port

	start := time.Now()
	_, err := ConnectTimeout("127.0.0.1", port, "pw", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error during handshake")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took too long: %v", elapsed)
	}
}

func TestConnectContextCanceled(t *testing.T) {
	ln := stallingListener(t)
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := ConnectContext(ctx, "127.0.0.1", port, "pw"); err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestReadDeadlinePoisonsConn(t *testing.T) {
	client, _ := newConnPair(t)

	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Recv(); err == nil {
		t.Fatal("expected deadline error on Recv")
	}

	if _, err := client.Recv(); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("expected ErrConnBroken after timeout, got %v", err)
	}
	if err := client.Send([]byte("x")); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("expected ErrConnBroken on Send after timeout, got %v", err)
	}
}

func TestListenerDeadline(t *testing.T) {
	ln, err := Listen(0, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if err := ln.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected Accept to time out")
	}
}

func TestConnectTimeoutSucceeds(t *testing.T) {
	ln, err := Listen(0, "good-pw")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	srvDone := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		close(srvDone)
	}()

	client, err := ConnectTimeout("127.0.0.1", port, "good-pw", 5*time.Second)
	if err != nil {
		t.Fatalf("ConnectTimeout failed: %v", err)
	}
	client.Close()
	<-srvDone
}

func TestAEADNonceDesyncFails(t *testing.T) {
	iv := make([]byte, 16)
	rand.Read(iv)

	a := newConnCipher("pw", iv, iv)
	msg := []byte("hello world 1234")
	ad := []byte{0, 0, 0, byte(len(msg) + tagSize)}

	dst := make([]byte, len(msg)+tagSize)
	a.seal(dst, msg, ad)

	b := newConnCipher("pw", iv, iv)
	incrementNonce(b.recvNonce)

	if _, err := b.open(make([]byte, 0, len(msg)), dst, ad); err == nil {
		t.Fatal("open succeeded with desynced nonce")
	}
}
