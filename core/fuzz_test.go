package core

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

var fuzzFrameKey = [sessionKeySize]byte{0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

var fuzzSocket = struct {
	once sync.Once
	conn *net.TCPConn
	err  error
}{}

func sharedFuzzSocket(t testing.TB) *net.TCPConn {
	fuzzSocket.once.Do(func() {
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			fuzzSocket.err = err
			return
		}
		defer ln.Close()
		accepted := make(chan *net.TCPConn, 1)
		go func() {
			c, _ := ln.AcceptTCP()
			accepted <- c
		}()
		fuzzSocket.conn, fuzzSocket.err = net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
		<-accepted
	})
	if fuzzSocket.err != nil {
		t.Fatal(fuzzSocket.err)
	}
	return fuzzSocket.conn
}

func newFuzzReadConn(t testing.TB, stream []byte) *Conn {
	settings := defaultConnSettings()
	settings.readBufferSize = minBufferSize
	settings.writeBufferSize = minBufferSize
	keys := sessionKeys{send: fuzzFrameKey, recv: fuzzFrameKey, peerRecvLimit: MaxMessageSize}
	c := newConn(sharedFuzzSocket(t), &keys, &settings)
	c.br = bufio.NewReaderSize(bytes.NewReader(stream), settings.readBufferSize+frameOverhead)
	return c
}

func sealFuzzFrames(messages [][]byte, closeNotify bool) []byte {
	key := fuzzFrameKey
	s := sealer{engine: newAEGISEngine(&key)}
	var stream []byte
	appendFrame := func(msg []byte, flags uint32) {
		frame := make([]byte, frameHeaderSize+len(msg)+tagSize)
		binary.BigEndian.PutUint32(frame[:frameHeaderSize], frameHeader(len(msg), flags))
		s.seal(frame[frameHeaderSize:], msg, frame[:frameHeaderSize])
		stream = append(stream, frame...)
	}
	for _, msg := range messages {
		appendFrame(msg, 0)
	}
	if closeNotify {
		appendFrame(nil, closeNotifyFlag)
	}
	return stream
}

const (
	fuzzModeRecv = iota
	fuzzModeRecvIntoSmall
	fuzzModeRecvIntoLarge
	fuzzModeRead
	fuzzModeCount
)

const (
	fuzzPoison          = 0xAA
	fuzzMaxReadsPerCase = 64
)

func fillPoison(b []byte) {
	for i := range b {
		b[i] = fuzzPoison
	}
}

func onlyZeroOrPoison(b []byte) bool {
	for _, c := range b {
		if c != 0 && c != fuzzPoison {
			return false
		}
	}
	return true
}

func FuzzRecvFrames(f *testing.F) {
	small := bytes.Repeat([]byte{'A'}, 100)
	f.Add(sealFuzzFrames(nil, false), byte(fuzzModeRecv))
	f.Add(sealFuzzFrames([][]byte{{}, {'A'}, small}, true), byte(fuzzModeRecv))
	f.Add(sealFuzzFrames([][]byte{small, bytes.Repeat([]byte{'B'}, 4096)}, true), byte(fuzzModeRecvIntoSmall))
	f.Add(sealFuzzFrames([][]byte{bytes.Repeat([]byte{'C'}, 4096)}, true), byte(fuzzModeRecvIntoLarge))
	f.Add(sealFuzzFrames([][]byte{bytes.Repeat([]byte{'D'}, minBufferSize+1024)}, true), byte(fuzzModeRecv))
	f.Add([]byte{0, 0}, byte(fuzzModeRecv))
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}, byte(fuzzModeRecv))
	f.Add(append([]byte{0x80, 0, 0, 0x20}, make([]byte, 32)...), byte(fuzzModeRecv))
	f.Add(sealFuzzFrames([][]byte{{}, small, bytes.Repeat([]byte{'E'}, 5000)}, true), byte(fuzzModeRead))
	f.Add(sealFuzzFrames([][]byte{bytes.Repeat([]byte{'F'}, minBufferSize+1024)}, true), byte(fuzzModeRead))

	f.Fuzz(func(t *testing.T, stream []byte, mode byte) {
		c := newFuzzReadConn(t, stream)
		buf := make([]byte, 0)
		switch mode % fuzzModeCount {
		case fuzzModeRecvIntoSmall:
			buf = make([]byte, 64)
		case fuzzModeRecvIntoLarge:
			buf = make([]byte, 2*minBufferSize)
		case fuzzModeRead:
			buf = make([]byte, 1000)
		}
		fillPoison(buf)
		for range fuzzMaxReadsPerCase {
			var (
				msg []byte
				n   int
				err error
			)
			switch mode % fuzzModeCount {
			case fuzzModeRecv:
				msg, err = c.Recv()
				n = len(msg)
			case fuzzModeRead:
				n, err = c.Read(buf)
				if n > len(buf) || err != nil && n != 0 {
					t.Fatalf("Read returned n=%d err=%v for a %d-byte buffer", n, err, len(buf))
				}
			default:
				n, err = c.RecvInto(buf)
				if err == nil {
					msg = buf[:n]
				}
			}
			if errors.Is(err, io.ErrShortBuffer) {
				if n <= len(buf) || n > MaxMessageSize {
					t.Fatalf("short buffer reported %d bytes for a %d-byte buffer", n, len(buf))
				}
				return
			}
			if n > len(stream) {
				t.Fatalf("returned %d bytes from a %d-byte stream", n, len(stream))
			}
			if err == nil {
				fillPoison(buf[:min(n, len(buf))])
				continue
			}
			if msg != nil && mode%fuzzModeCount == fuzzModeRecv {
				t.Fatalf("Recv returned data with error %v", err)
			}
			if mode%fuzzModeCount != fuzzModeRecv && errors.Is(err, errAuthFailed) && !onlyZeroOrPoison(buf) {
				t.Fatalf("unverified plaintext left in buffer after %v", err)
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrConnBroken) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
	})
}

type fuzzReadWriter struct {
	r *bytes.Reader
}

func (rw fuzzReadWriter) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw fuzzReadWriter) Write(p []byte) (int, error) { return len(p), nil }

func fuzzPasswordKey(t testing.TB) *passwordKey {
	key, err := derivePasswordKey(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return &key
}

func fuzzHello(f *testing.F, size, pointOffset int) []byte {
	pwKey := fuzzPasswordKey(f)
	hello := make([]byte, size)
	putHelloPrefix(hello, MaxMessageSize)
	_, point, err := newEphemeral(pwKey, hello[clientSIDOffset:clientPointOffset])
	if err != nil {
		f.Fatal(err)
	}
	copy(hello[pointOffset:], point)
	return hello
}

func FuzzServerHandshake(f *testing.F) {
	hello := fuzzHello(f, clientHelloSize, clientPointOffset)
	f.Add(hello)
	f.Add(append(hello[:len(hello):len(hello)], make([]byte, finishedSize)...))
	f.Add(make([]byte, clientHelloSize))
	f.Add([]byte("ALTC"))
	f.Fuzz(func(t *testing.T, clientBytes []byte) {
		pwKey := fuzzPasswordKey(t)
		if _, err := serverHandshake(fuzzReadWriter{bytes.NewReader(clientBytes)}, pwKey, MaxMessageSize); err == nil {
			t.Fatal("server handshake succeeded on fuzzed client bytes")
		}
	})
}

func FuzzClientHandshake(f *testing.F) {
	hello := fuzzHello(f, serverHelloSize, serverPointOffset)
	f.Add(hello)
	f.Add(append(hello[:len(hello):len(hello)], make([]byte, finishedSize)...))
	f.Add(make([]byte, serverHelloSize))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, serverBytes []byte) {
		pwKey := fuzzPasswordKey(t)
		if _, err := clientHandshake(fuzzReadWriter{bytes.NewReader(serverBytes)}, pwKey, MaxMessageSize); err == nil {
			t.Fatal("client handshake succeeded on fuzzed server bytes")
		}
	})
}

func FuzzEnginesDifferential(f *testing.F) {
	f.Add(make([]byte, sessionKeySize), make([]byte, nonceSize), []byte{}, []byte{}, uint32(0))
	f.Add(bytes.Repeat([]byte{1}, sessionKeySize), bytes.Repeat([]byte{2}, nonceSize), []byte("ad"), bytes.Repeat([]byte("m"), 100), uint32(7))
	f.Add(bytes.Repeat([]byte{3}, sessionKeySize), bytes.Repeat([]byte{4}, nonceSize), make([]byte, 65), make([]byte, 4097), uint32(1<<20))
	f.Fuzz(func(t *testing.T, keyBytes, nonceBytes, ad, msg []byte, flip uint32) {
		var key [sessionKeySize]byte
		var nonce [nonceSize]byte
		copy(key[:], keyBytes)
		copy(nonce[:], nonceBytes)
		native := newAEGISEngine(&key)
		lib := newLibAEGISEngine(&key)

		fromNative := make([]byte, len(msg)+tagSize)
		fromLib := make([]byte, len(msg)+tagSize)
		native.seal(&nonce, fromNative, msg, ad)
		lib.seal(&nonce, fromLib, msg, ad)
		if !bytes.Equal(fromNative, fromLib) {
			t.Fatal("native and library seal disagree")
		}

		opened := make([]byte, len(msg))
		if !native.open(&nonce, opened, fromLib[:len(msg)], fromLib[len(msg):], ad) || !bytes.Equal(opened, msg) {
			t.Fatal("native open failed on library ciphertext")
		}
		if !lib.open(&nonce, opened, fromNative[:len(msg)], fromNative[len(msg):], ad) || !bytes.Equal(opened, msg) {
			t.Fatal("library open failed on native ciphertext")
		}

		tampered := append([]byte(nil), fromNative...)
		bit := int(flip % uint32(8*len(tampered)))
		tampered[bit/8] ^= 1 << (bit % 8)
		for name, engine := range map[string]vectorEngine{"native": &native, "lib": &lib} {
			out := bytes.Repeat([]byte{fuzzPoison}, len(msg))
			if engine.open(&nonce, out, tampered[:len(msg)], tampered[len(msg):], ad) {
				t.Fatalf("%s accepted a ciphertext with bit %d flipped", name, bit)
			}
			if !bytes.Equal(out, make([]byte, len(msg))) {
				t.Fatalf("%s left unverified plaintext after tamper", name)
			}
		}
	})
}
