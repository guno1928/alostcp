package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

const securityTestTimeout = 150 * time.Millisecond

type handshakeResult struct {
	keys sessionKeys
	err  error
}

func runAsync(fn func() (sessionKeys, error)) chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		keys, err := fn()
		ch <- handshakeResult{keys, err}
	}()
	return ch
}

func mustPasswordKey(t *testing.T, password string) *passwordKey {
	t.Helper()
	key, err := derivePasswordKey(password)
	if err != nil {
		t.Fatal(err)
	}
	return &key
}

func pipeWithDeadline(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(20 * securityTestTimeout)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func writeAll(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
}

func guessedClientHello(t *testing.T, recvLimit int) []byte {
	t.Helper()
	wrongKey := mustPasswordKey(t, "an attacker's guess")
	hello := make([]byte, clientHelloSize)
	putHelloPrefix(hello, recvLimit)
	rand.Read(hello[clientSIDOffset:clientPointOffset])
	_, point, err := newEphemeral(wrongKey, hello[clientSIDOffset:clientPointOffset])
	if err != nil {
		t.Fatal(err)
	}
	copy(hello[clientPointOffset:], point)
	return hello
}

func recordServerFlight(t *testing.T, pwKey *passwordKey) (serverHello, serverFinished []byte) {
	t.Helper()
	clientEnd, mitmClient := pipeWithDeadline(t)
	serverEnd, mitmServer := pipeWithDeadline(t)
	client := runAsync(func() (sessionKeys, error) { return clientHandshake(clientEnd, pwKey, MaxMessageSize) })
	server := runAsync(func() (sessionKeys, error) { return serverHandshake(serverEnd, pwKey, MaxMessageSize) })

	writeAll(t, mitmServer, readN(t, mitmClient, clientHelloSize))
	serverHello = readN(t, mitmServer, serverHelloSize)
	writeAll(t, mitmClient, serverHello)
	writeAll(t, mitmServer, readN(t, mitmClient, finishedSize))
	serverFinished = readN(t, mitmServer, finishedSize)
	writeAll(t, mitmClient, serverFinished)

	if r := <-client; r.err != nil {
		t.Fatalf("recorded client handshake failed: %v", r.err)
	}
	if r := <-server; r.err != nil {
		t.Fatalf("recorded server handshake failed: %v", r.err)
	}
	return serverHello, serverFinished
}

func TestClientRejectsReplayedServerHandshake(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	serverHello, serverFinished := recordServerFlight(t, pwKey)

	victim, attacker := pipeWithDeadline(t)
	result := runAsync(func() (sessionKeys, error) { return clientHandshake(victim, pwKey, MaxMessageSize) })
	readN(t, attacker, clientHelloSize)
	writeAll(t, attacker, serverHello)
	readN(t, attacker, finishedSize)
	writeAll(t, attacker, serverFinished)

	if r := <-result; !errors.Is(r.err, ErrHandshake) {
		t.Fatalf("client accepted a replayed server handshake: %v", r.err)
	}
}

func TestRelayedServerFlightCompletesOnlyOneClient(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	aliceEnd, mitmAlice := pipeWithDeadline(t)
	bobEnd, mitmBob := pipeWithDeadline(t)
	serverEnd, mitmServer := pipeWithDeadline(t)
	alice := runAsync(func() (sessionKeys, error) { return clientHandshake(aliceEnd, pwKey, MaxMessageSize) })
	bob := runAsync(func() (sessionKeys, error) { return clientHandshake(bobEnd, pwKey, MaxMessageSize) })
	server := runAsync(func() (sessionKeys, error) { return serverHandshake(serverEnd, pwKey, MaxMessageSize) })

	aliceHello := readN(t, mitmAlice, clientHelloSize)
	readN(t, mitmBob, clientHelloSize)
	writeAll(t, mitmServer, aliceHello)
	serverHello := readN(t, mitmServer, serverHelloSize)
	writeAll(t, mitmAlice, serverHello)
	writeAll(t, mitmBob, serverHello)
	aliceFinished := readN(t, mitmAlice, finishedSize)
	readN(t, mitmBob, finishedSize)
	writeAll(t, mitmServer, aliceFinished)
	serverFinished := readN(t, mitmServer, finishedSize)
	writeAll(t, mitmAlice, serverFinished)
	writeAll(t, mitmBob, serverFinished)

	a, b, s := <-alice, <-bob, <-server
	if a.err != nil || s.err != nil {
		t.Fatalf("relayed genuine session failed: alice=%v server=%v", a.err, s.err)
	}
	if a.keys.send != s.keys.recv || a.keys.recv != s.keys.send {
		t.Fatal("alice and server derived different session keys")
	}
	if !errors.Is(b.err, ErrHandshake) {
		t.Fatalf("a second client was cloned into alice's session: %v", b.err)
	}
}

func TestClientRejectsReflectedHandshake(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	victim, attacker := pipeWithDeadline(t)
	result := runAsync(func() (sessionKeys, error) { return clientHandshake(victim, pwKey, MaxMessageSize) })

	hello := readN(t, attacker, clientHelloSize)
	writeAll(t, attacker, append(hello[:helloPrefixSize:helloPrefixSize], hello[clientPointOffset:]...))
	writeAll(t, attacker, readN(t, attacker, finishedSize))

	if r := <-result; !errors.Is(r.err, ErrHandshake) {
		t.Fatalf("client accepted its own reflected handshake: %v", r.err)
	}
}

func TestServerGivesAnonymousClientNoPasswordProof(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := raw.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_, err = serverHandshake(conn, pwKey, MaxMessageSize)
		result <- err
	}()

	attacker, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	attacker.SetDeadline(time.Now().Add(20 * securityTestTimeout))
	writeAll(t, attacker, guessedClientHello(t, MaxMessageSize))
	readN(t, attacker, serverHelloSize)
	guess := make([]byte, finishedSize)
	rand.Read(guess)
	writeAll(t, attacker, guess)

	if err := <-result; !errors.Is(err, errBadFinished) {
		t.Fatalf("server did not reject a guessed password proof: %v", err)
	}
	if n, _ := attacker.Read(make([]byte, finishedSize)); n != 0 {
		t.Fatalf("server sent %d bytes to a client that failed the password proof", n)
	}
}

func TestSessionsUseFreshKeys(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	seen := make(map[[sessionKeySize]byte]bool)
	for range 3 {
		clientEnd, serverEnd := pipeWithDeadline(t)
		client := runAsync(func() (sessionKeys, error) { return clientHandshake(clientEnd, pwKey, MaxMessageSize) })
		server := runAsync(func() (sessionKeys, error) { return serverHandshake(serverEnd, pwKey, MaxMessageSize) })
		c, s := <-client, <-server
		if c.err != nil || s.err != nil {
			t.Fatalf("handshake failed: %v %v", c.err, s.err)
		}
		if c.keys.send == c.keys.recv {
			t.Fatal("both directions share one key")
		}
		for _, k := range [][sessionKeySize]byte{c.keys.send, c.keys.recv} {
			if seen[k] {
				t.Fatal("a session key repeated across sessions")
			}
			seen[k] = true
		}
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := Listen(0, ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Listen accepted an empty password: %v", err)
	}
	if _, err := ConnectTimeout("127.0.0.1", 1, "", securityTestTimeout); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Connect accepted an empty password: %v", err)
	}
}

func TestPasswordKeyCacheIsBounded(t *testing.T) {
	passwordKeyCache.Lock()
	saved := passwordKeyCache.keys
	passwordKeyCache.keys = make(map[passwordFingerprint]passwordKey)
	for i := range maxCachedPasswordKeys {
		passwordKeyCache.keys[passwordFingerprint{byte(i), 1}] = passwordKey{}
	}
	passwordKeyCache.Unlock()
	defer func() {
		passwordKeyCache.Lock()
		passwordKeyCache.keys = saved
		passwordKeyCache.Unlock()
	}()

	if _, err := derivePasswordKey("one more password"); err != nil {
		t.Fatal(err)
	}
	passwordKeyCache.Lock()
	size := len(passwordKeyCache.keys)
	passwordKeyCache.Unlock()
	if size > maxCachedPasswordKeys {
		t.Fatalf("password key cache grew to %d entries", size)
	}
}

func TestConnectContextCancelDuringHandshake(t *testing.T) {
	ln := stallingListener(t)
	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(securityTestTimeout, cancel)

	start := time.Now()
	_, err := ConnectContext(ctx, "127.0.0.1", port, testPassword)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("expected a canceled handshake error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*securityTestTimeout {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestConnectIPv6Literal(t *testing.T) {
	ln, err := ListenHost("::1", 0, testPassword)
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := ConnectTimeout("::1", ln.Addr().(*net.TCPAddr).Port, testPassword, 10*securityTestTimeout)
	if err != nil {
		t.Fatalf("dialing an IPv6 literal failed: %v", err)
	}
	c.Close()
}

func TestRecvIntoClearsBufferOnTamper(t *testing.T) {
	client, server := newConnPair(t)
	msg := []byte("transfer=0000100;transfer=0000100;")
	frame := sealRawFrame(client, msg, 0)
	frame[frameHeaderSize+9] ^= 0x07
	writeAll(t, client.tcp, frame)

	buf := make([]byte, 64)
	if _, err := server.RecvInto(buf); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("expected ErrConnBroken, got %v", err)
	}
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("unverified plaintext left in caller buffer: %q", buf)
	}
}

func TestRecvIntoShortBufferKeepsConn(t *testing.T) {
	client, server := newConnPair(t)
	msg := bytes.Repeat([]byte("z"), 100)
	if err := client.Send(msg); err != nil {
		t.Fatal(err)
	}
	n, err := server.RecvInto(make([]byte, 10))
	if !errors.Is(err, io.ErrShortBuffer) || n != len(msg) {
		t.Fatalf("expected io.ErrShortBuffer with size %d, got n=%d err=%v", len(msg), n, err)
	}
	buf := make([]byte, n)
	if got, err := server.RecvInto(buf); err != nil || !bytes.Equal(buf[:got], msg) {
		t.Fatalf("message lost after short buffer: %v", err)
	}
}

func TestRecvTimeoutMidFrameKeepsConn(t *testing.T) {
	client, server := newConnPair(t)
	msg := bytes.Repeat([]byte("m"), 1000)
	frame := sealRawFrame(client, msg, 0)
	writeAll(t, client.tcp, frame[:500])

	server.SetReadDeadline(time.Now().Add(securityTestTimeout))
	if _, err := server.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a timeout, got %v", err)
	}
	server.SetReadDeadline(time.Time{})
	writeAll(t, client.tcp, frame[500:])
	got, err := server.Recv()
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("frame lost after a mid-frame timeout: %v", err)
	}
}

func TestRecvDoesNotPreallocateFromUnauthenticatedLength(t *testing.T) {
	client, server := newConnPair(t)
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], maxCiphertextSize)
	writeAll(t, client.tcp, header[:])
	writeAll(t, client.tcp, make([]byte, 100))

	server.SetReadDeadline(time.Now().Add(securityTestTimeout))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := server.Recv()
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("expected Recv to fail on a stalled oversized frame")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4*largeFrameReadChunk {
		t.Fatalf("a 4-byte header caused %d bytes of allocation", grew)
	}
}

func TestSendRejectsOversizeMessage(t *testing.T) {
	client, server := newConnPair(t)
	if err := client.Send(make([]byte, MaxMessageSize+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
	if err := client.SendBuffered(make([]byte, MaxMessageSize+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge from SendBuffered, got %v", err)
	}
	if err := client.Send([]byte("ok")); err != nil {
		t.Fatalf("connection unusable after a rejected send: %v", err)
	}
	if got, err := server.Recv(); err != nil || string(got) != "ok" {
		t.Fatalf("recv after rejected send: %q %v", got, err)
	}
}

func TestLargeMessagesRoundTrip(t *testing.T) {
	client, server := newConnPair(t)
	for _, size := range []int{connBufferSize - frameHeaderSize - tagSize, connBufferSize, 3 * connBufferSize} {
		msg := make([]byte, size)
		rand.Read(msg)
		errCh := make(chan error, 1)
		go func() { errCh <- client.Send(msg) }()
		got, err := server.Recv()
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("size %d: Recv failed: %v", size, err)
		}
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		go func() { errCh <- client.Send(msg) }()
		buf := make([]byte, size)
		n, err := server.RecvInto(buf)
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("size %d: RecvInto failed: %v", size, err)
		}
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCloseFlushesBufferedAndPeerSeesEOF(t *testing.T) {
	client, server := newConnPair(t)
	for _, m := range []string{"one", "two", "three"} {
		if err := client.SendBuffered([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two", "three"} {
		got, err := server.RecvString()
		if err != nil || got != want {
			t.Fatalf("buffered message lost on Close: got %q err %v", got, err)
		}
	}
	if _, err := server.Recv(); err != io.EOF {
		t.Fatalf("expected io.EOF after close notification, got %v", err)
	}
	if _, err := server.Recv(); err != io.EOF {
		t.Fatalf("expected io.EOF to repeat, got %v", err)
	}
}

func TestPeerTruncationDetected(t *testing.T) {
	client, server := newConnPair(t)
	if err := client.Send([]byte("last")); err != nil {
		t.Fatal(err)
	}
	client.tcp.Close()
	if got, err := server.Recv(); err != nil || string(got) != "last" {
		t.Fatalf("recv: %q %v", got, err)
	}
	_, err := server.Recv()
	if !errors.Is(err, ErrConnBroken) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation without close notification was not detected: %v", err)
	}
}

func TestCloseWhileRecvBlocked(t *testing.T) {
	client, _ := newConnPair(t)
	errCh := make(chan error, 1)
	go func() {
		_, err := client.Recv()
		errCh <- err
	}()
	waitFor(t, func() bool {
		if client.rmu.TryLock() {
			client.rmu.Unlock()
			return false
		}
		return true
	})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrConnClosed) {
		t.Fatalf("blocked Recv: expected ErrConnClosed, got %v", err)
	}
	if _, err := client.Recv(); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Recv after Close: expected ErrConnClosed, got %v", err)
	}
	if err := client.Send([]byte("x")); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Send after Close: expected ErrConnClosed, got %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close returned %v", err)
	}
}

func TestPoisonErrorsWrapErrConnBroken(t *testing.T) {
	client, server := newConnPair(t)
	frame := sealRawFrame(client, []byte("payload"), 0)
	frame[len(frame)-1] ^= 1
	writeAll(t, client.tcp, frame)

	if _, err := server.Recv(); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("first failure does not wrap ErrConnBroken: %v", err)
	}
	if _, err := server.Recv(); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("later Recv: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close after poisoning returned %v", err)
	}
}

func TestConnectContextCancelDuringPasswordStretch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	fresh := make([]byte, 16)
	rand.Read(fresh)
	_, err := ConnectContext(ctx, "127.0.0.1", 1, string(fresh)+"x")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("password stretching ignored the context: %v", err)
	}
}

func TestAcceptDeadlineWakesEveryWaiter(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := ln.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	const waiters = 3
	errs := make(chan error, waiters)
	for range waiters {
		go func() {
			_, err := ln.Accept()
			errs <- err
		}()
	}
	time.Sleep(securityTestTimeout)
	if err := ln.SetDeadline(time.Now().Add(securityTestTimeout)); err != nil {
		t.Fatal(err)
	}
	for range waiters {
		select {
		case err := <-errs:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("expected a deadline error, got %v", err)
			}
		case <-time.After(10 * securityTestTimeout):
			t.Fatal("SetDeadline did not wake every blocked Accept")
		}
	}
}

func TestAcceptAfterCloseReportsClosedEvenWithPastDeadline(t *testing.T) {
	ln, err := ListenHost("127.0.0.1", 0, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a deadline error before Close, got %v", err)
	}
	ln.Close()
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

func sealWithAD(c *Conn, msg, ad []byte) []byte {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame := make([]byte, frameHeaderSize+len(msg)+tagSize)
	binary.BigEndian.PutUint32(frame, frameHeader(len(msg), 0))
	c.sealer.seal(frame[frameHeaderSize:], msg, ad)
	return frame
}

func TestFrameHeaderIsBoundAsAD(t *testing.T) {
	for _, size := range []int{100, 2 * connBufferSize} {
		client, server := newConnPair(t)
		frame := sealWithAD(client, make([]byte, size), nil)
		go client.tcp.Write(frame)
		if _, err := server.Recv(); !errors.Is(err, ErrConnBroken) {
			t.Fatalf("size %d: frame sealed without its header was accepted: %v", size, err)
		}
	}
}

func TestFullSizeSmallMessageSurvivesTimeout(t *testing.T) {
	client, server := newConnPair(t)
	msg := make([]byte, connBufferSize)
	rand.Read(msg)
	frame := sealRawFrame(client, msg, 0)
	writeAll(t, client.tcp, frame[:len(frame)/2])

	server.SetReadDeadline(time.Now().Add(securityTestTimeout))
	if _, err := server.Recv(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a timeout, got %v", err)
	}
	server.SetReadDeadline(time.Time{})
	go client.tcp.Write(frame[len(frame)/2:])
	got, err := server.Recv()
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("a %d-byte message did not survive a mid-frame timeout: %v", len(msg), err)
	}
}
