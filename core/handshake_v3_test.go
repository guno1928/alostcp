package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const v3TestTimeout = 150 * time.Millisecond

func rejectsWithoutReply(t *testing.T, ln *Listener, result chan error, conn net.Conn) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, ErrHandshake) {
			t.Fatalf("server handshake returned %v, want ErrHandshake", err)
		}
	case <-time.After(20 * v3TestTimeout):
		t.Fatal("server did not reject the hello")
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * v3TestTimeout)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("server replied to a rejected hello: n=%d err=%v", n, err)
	}
}

func newV3TestListener(t *testing.T) *Listener {
	t.Helper()
	ln, err := ListenHost("127.0.0.1", 0, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	ln.SetHandshakeTimeout(4 * v3TestTimeout)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestV2ClientHelloRejected(t *testing.T) {
	v2Hello := append([]byte(protocolMagic), 2)
	v2Hello = append(v2Hello, bytes.Repeat([]byte{9}, 32)...)
	padded := make([]byte, clientHelloSize)
	copy(padded, v2Hello)

	for name, hello := range map[string][]byte{"v2 length": v2Hello, "v2 padded": padded} {
		ln := newV3TestListener(t)
		result := handshakeAsync(ln)
		conn := dialRaw(t, ln)
		writeAll(t, conn, hello)
		t.Run(name, func(t *testing.T) { rejectsWithoutReply(t, ln, result, conn) })
	}
}

func TestServerRejectsInvalidClientPoints(t *testing.T) {
	for name, point := range map[string][]byte{
		"identity":      make([]byte, cpacePointSize),
		"non-canonical": mustHex(t, cpaceDraft21Vectors["invalidY1"]),
	} {
		ln := newV3TestListener(t)
		result := handshakeAsync(ln)
		conn := dialRaw(t, ln)
		hello := guessedClientHello(t, MaxMessageSize)
		copy(hello[clientPointOffset:], point)
		writeAll(t, conn, hello)
		t.Run(name, func(t *testing.T) { rejectsWithoutReply(t, ln, result, conn) })
	}
}

func TestServerRejectsOutOfRangeLimits(t *testing.T) {
	for _, limit := range []uint32{0, minMessageLimit - 1, MaxMessageSize + 1, 0xFFFFFFFF} {
		ln := newV3TestListener(t)
		result := handshakeAsync(ln)
		conn := dialRaw(t, ln)
		hello := guessedClientHello(t, MaxMessageSize)
		binary.BigEndian.PutUint32(hello[len(protocolMagic)+1:helloPrefixSize], limit)
		writeAll(t, conn, hello)
		rejectsWithoutReply(t, ln, result, conn)
	}
}

func TestClientRejectsBadServerHellos(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	validServerHello := func() []byte {
		hello := make([]byte, serverHelloSize)
		putHelloPrefix(hello, MaxMessageSize)
		_, point, err := newEphemeral(pwKey, make([]byte, cpaceSIDSize))
		if err != nil {
			t.Fatal(err)
		}
		copy(hello[serverPointOffset:], point)
		return hello
	}
	cases := map[string]func([]byte){
		"limit zero":    func(h []byte) { binary.BigEndian.PutUint32(h[len(protocolMagic)+1:helloPrefixSize], 0) },
		"limit huge":    func(h []byte) { binary.BigEndian.PutUint32(h[len(protocolMagic)+1:helloPrefixSize], MaxMessageSize+1) },
		"version 2":     func(h []byte) { h[len(protocolMagic)] = 2 },
		"bad magic":     func(h []byte) { h[0] = 'X' },
		"identity":      func(h []byte) { clear(h[serverPointOffset:]) },
		"non-canonical": func(h []byte) { copy(h[serverPointOffset:], mustHex(t, cpaceDraft21Vectors["invalidY1"])) },
	}
	for name, mutate := range cases {
		victim, attacker := pipeWithDeadline(t)
		result := runAsync(func() (sessionKeys, error) { return clientHandshake(victim, pwKey, MaxMessageSize) })
		readN(t, attacker, clientHelloSize)
		hello := validServerHello()
		mutate(hello)
		writeAll(t, attacker, hello)
		if r := <-result; !errors.Is(r.err, errBadHello) {
			t.Fatalf("%s: client returned %v, want errBadHello", name, r.err)
		}
	}
}

type tamperingRelay struct {
	direction int
	offset    int
}

func relayStream(dst io.WriteCloser, src io.Reader, flipOffset int) {
	defer dst.Close()
	buf := make([]byte, 1)
	for pos := 0; ; pos++ {
		if _, err := io.ReadFull(src, buf); err != nil {
			return
		}
		if pos == flipOffset {
			buf[0] ^= 0x10
		}
		if _, err := dst.Write(buf); err != nil {
			return
		}
	}
}

func TestTamperedHandshakeFieldsFailBothSides(t *testing.T) {
	const (
		clientToServer = iota
		serverToClient
	)
	limitOffset := len(protocolMagic) + 1 + recvLimitFieldSize - 1
	cases := map[string]tamperingRelay{
		"client recvLimit": {clientToServer, limitOffset},
		"client sid":       {clientToServer, clientSIDOffset + 3},
		"client point":     {clientToServer, clientPointOffset + 5},
		"server recvLimit": {serverToClient, limitOffset},
		"server point":     {serverToClient, serverPointOffset + 5},
		"client finished":  {clientToServer, clientHelloSize + 7},
	}
	pwKey := mustPasswordKey(t, testPassword)
	for name, tc := range cases {
		clientEnd, relayClient := pipeWithDeadline(t)
		serverEnd, relayServer := pipeWithDeadline(t)
		upFlip, downFlip := -1, -1
		if tc.direction == clientToServer {
			upFlip = tc.offset
		} else {
			downFlip = tc.offset
		}
		go relayStream(relayServer, relayClient, upFlip)
		go relayStream(relayClient, relayServer, downFlip)

		client := runAsync(func() (sessionKeys, error) {
			keys, err := clientHandshake(clientEnd, pwKey, MaxMessageSize)
			clientEnd.Close()
			return keys, err
		})
		server := runAsync(func() (sessionKeys, error) {
			keys, err := serverHandshake(serverEnd, pwKey, MaxMessageSize)
			serverEnd.Close()
			return keys, err
		})
		c, s := <-client, <-server
		if !errors.Is(c.err, ErrHandshake) || !errors.Is(s.err, ErrHandshake) {
			t.Fatalf("%s: tampering went unnoticed: client=%v server=%v", name, c.err, s.err)
		}
	}
}

func TestReplayedClientHelloGetsFreshServerHello(t *testing.T) {
	pwKey := mustPasswordKey(t, testPassword)
	clientHello := guessedClientHello(t, MaxMessageSize)
	var serverHellos [][]byte
	for range 2 {
		serverEnd, attacker := pipeWithDeadline(t)
		result := runAsync(func() (sessionKeys, error) { return serverHandshake(serverEnd, pwKey, MaxMessageSize) })
		writeAll(t, attacker, clientHello)
		serverHellos = append(serverHellos, readN(t, attacker, serverHelloSize))
		attacker.Close()
		<-result
	}
	if bytes.Equal(serverHellos[0], serverHellos[1]) {
		t.Fatal("server reused its ephemeral key for a replayed client hello")
	}
}

func TestNegotiatedMessageLimit(t *testing.T) {
	const serverLimit = 64 << 10
	client, server := newConfigPair(t, &Config{MaxMessageSize: serverLimit}, nil)

	if err := client.Send(make([]byte, serverLimit+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("client sent past the server's advertised limit: %v", err)
	}
	if err := client.Send(make([]byte, serverLimit)); err != nil {
		t.Fatal(err)
	}
	if msg, err := server.Recv(); err != nil || len(msg) != serverLimit {
		t.Fatalf("server Recv: %d bytes, %v", len(msg), err)
	}
	if err := server.Send(make([]byte, serverLimit+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("server sent past its own limit: %v", err)
	}
	if err := server.Send(make([]byte, serverLimit)); err != nil {
		t.Fatal(err)
	}
	if msg, err := client.Recv(); err != nil || len(msg) != serverLimit {
		t.Fatalf("client Recv: %d bytes, %v", len(msg), err)
	}
}

func TestDialConfigAdvertisesLocalLimit(t *testing.T) {
	const clientLimit = 2 << 10
	client, server := newConfigPair(t, nil, &Config{MaxMessageSize: clientLimit})
	if err := server.Send(make([]byte, clientLimit+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("server ignored the client's advertised limit: %v", err)
	}
	if err := server.Send(make([]byte, clientLimit)); err != nil {
		t.Fatal(err)
	}
	if msg, err := client.Recv(); err != nil || len(msg) != clientLimit {
		t.Fatalf("client Recv: %d bytes, %v", len(msg), err)
	}
}
