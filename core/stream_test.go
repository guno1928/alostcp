package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

const (
	streamTestTimeout  = 150 * time.Millisecond
	stalledWriteSize   = 32 << 20
	streamCopySize     = 8 << 20
	streamTestDeadline = 20 * streamTestTimeout
)

func makeStreamPipe() (c1, c2 net.Conn, stop func(), err error) {
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, nil)
	if err != nil {
		return nil, nil, nil, err
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), streamTestDeadline)
	defer cancel()
	client, err := DialConfig(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, testPassword, nil)
	if err != nil {
		ln.Close()
		return nil, nil, nil, err
	}
	select {
	case server := <-accepted:
		stop = func() {
			client.Close()
			server.Close()
			ln.Close()
		}
		return client, server, stop, nil
	case err := <-acceptErr:
		client.Close()
		ln.Close()
		return nil, nil, nil, err
	}
}

func streamPair(t *testing.T) (client, server *Conn) {
	t.Helper()
	c1, c2, stop, err := makeStreamPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return c1.(*Conn), c2.(*Conn)
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

const nettestChildEnv = "ALOSTCP_NETTEST_CHILD"

func TestNetConnConformance(t *testing.T) {
	if resumableWriteTimeouts || os.Getenv(nettestChildEnv) == "1" {
		nettest.TestConn(t, makeStreamPipe)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestNetConnConformance$", "-test.skip", "^TestNetConnConformance/(FutureTimeout|ConcurrentMethods)$", "-test.v")
	cmd.Env = append(os.Environ(), nettestChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	passed := strings.Count(string(out), "--- PASS: TestNetConnConformance/")
	if err != nil || passed != 9 {
		t.Fatalf("nettest without FutureTimeout and ConcurrentMethods: %d/9 subtests passed, err=%v\n%s", passed, err, out)
	}
}

func TestConcurrentStreamMethods(t *testing.T) {
	client, server := streamPair(t)
	go io.Copy(io.Discard, server)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { client.Read(make([]byte, 1024)) })
		wg.Go(func() { client.Write(make([]byte, 1024)) })
		wg.Go(func() { client.SetDeadline(time.Now().Add(10 * time.Millisecond)) })
		wg.Go(func() { client.SetReadDeadline(time.Unix(1, 0)) })
		wg.Go(func() { client.SetWriteDeadline(time.Unix(1, 0)) })
		wg.Go(func() { client.LocalAddr() })
		wg.Go(func() { client.RemoteAddr() })
		wg.Go(func() { client.Send([]byte("m")) })
	}
	wg.Wait()
}

func TestStreamIOCopy(t *testing.T) {
	client, server := streamPair(t)
	data := randomPayload(t, streamCopySize)
	sent := make(chan error, 1)
	go func() {
		_, err := io.Copy(client, bytes.NewReader(data))
		if err == nil {
			err = client.Close()
		}
		sent <- err
	}()
	h := sha256.New()
	n, err := io.Copy(h, server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if n != streamCopySize || !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatalf("copied %d bytes with a different digest", n)
	}
}

func TestStreamHTTPRoundTrip(t *testing.T) {
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "hello")
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: streamTestDeadline}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln.NetListener()) }()

	transport := &http.Transport{DialContext: DialContextFunc(testPassword, nil)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: streamTestDeadline}
	base := "http://" + ln.Addr().String()

	resp, err := client.Get(base + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("GET /hello: %d %q %v", resp.StatusCode, body, err)
	}

	payload := randomPayload(t, 1<<20)
	resp, err = client.Post(base+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("POST /echo returned %d bytes, %v", len(body), err)
	}

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve returned %v", err)
	}
}

func TestStreamReadWithSmallBuffer(t *testing.T) {
	client, server := streamPair(t)
	msg := randomPayload(t, 10<<10)
	if err := client.Send(msg); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 1000)
	for len(got) < len(msg) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if want := min(len(buf), len(msg)-len(got)); n != want {
			t.Fatalf("Read returned %d, want %d", n, want)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("stream bytes differ from the sent message")
	}
}

func TestRecvAfterPartialRead(t *testing.T) {
	client, server := streamPair(t)
	first, second := randomPayload(t, 10<<10), randomPayload(t, 300)
	if err := client.Send(first); err != nil {
		t.Fatal(err)
	}
	if err := client.Send(second); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 1<<10)
	if n, err := server.Read(head); err != nil || n != len(head) {
		t.Fatalf("Read: %d, %v", n, err)
	}
	small := make([]byte, 16)
	if n, err := server.RecvInto(small); !errors.Is(err, io.ErrShortBuffer) || n != len(first)-len(head) {
		t.Fatalf("RecvInto with a small buffer: %d, %v", n, err)
	}
	rest, err := server.Recv()
	if err != nil || !bytes.Equal(rest, first[len(head):]) {
		t.Fatalf("Recv did not return the unread remainder: %d bytes, %v", len(rest), err)
	}
	if got, err := server.Recv(); err != nil || !bytes.Equal(got, second) {
		t.Fatalf("next message: %d bytes, %v", len(got), err)
	}
}

func TestStreamSkipsEmptyMessages(t *testing.T) {
	client, server := streamPair(t)
	for _, msg := range [][]byte{{}, {}, []byte("x")} {
		if err := client.Send(msg); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 4)
	if n, err := server.Read(buf); n != 1 || err != nil || buf[0] != 'x' {
		t.Fatalf("Read: %d %q %v", n, buf[:n], err)
	}
}

func TestWritePastDeadlineIsRecoverable(t *testing.T) {
	client, server := streamPair(t)
	if err := client.SetWriteDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	n, err := client.Write(make([]byte, 4096))
	var netErr net.Error
	if n != 0 || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Write with a past deadline: n=%d err=%v", n, err)
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	msg := randomPayload(t, 4096)
	if n, err := client.Write(msg); n != len(msg) || err != nil {
		t.Fatalf("Write after clearing the deadline: %d, %v", n, err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("peer read %v / equal=%v", err, bytes.Equal(got, msg))
	}
}

func TestSendWriteTimeoutStillPoisons(t *testing.T) {
	client, _ := streamPair(t)
	if err := client.SetWriteDeadline(time.Now().Add(streamTestTimeout)); err != nil {
		t.Fatal(err)
	}
	var err error
	chunk := make([]byte, 1<<20)
	for range stalledWriteSize >> 18 {
		if err = client.Send(chunk); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrConnBroken) {
		t.Fatalf("Send timeout returned %v, want ErrConnBroken", err)
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("Send timeout error %T does not report Timeout()", err)
	}
	if _, err := client.Write([]byte("x")); !errors.Is(err, ErrConnBroken) {
		t.Fatalf("Write on a poisoned conn returned %v", err)
	}
}

func TestStreamEOFAndClosed(t *testing.T) {
	client, server := streamPair(t)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after peer Close: %v", err)
	}
	if _, err := client.Read(make([]byte, 8)); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Read after local Close: %v", err)
	}
	if _, err := client.Write([]byte("x")); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Write after local Close: %v", err)
	}
}

func TestStreamRespectsNegotiatedLimit(t *testing.T) {
	const serverLimit = 2 << 10
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, &Config{MaxMessageSize: serverLimit})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), streamTestDeadline)
	defer cancel()
	client, err := DialConfig(ctx, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, testPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	data := randomPayload(t, 100<<10)
	go client.Write(data)
	got := make([]byte, len(data))
	if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream over a 2 KiB peer limit: %v", err)
	}
}

func TestDialContextFuncRejectsBadAddresses(t *testing.T) {
	dial := DialContextFunc(testPassword, nil)
	ctx := context.Background()
	var unknown net.UnknownNetworkError
	if _, err := dial(ctx, "udp", "127.0.0.1:1"); !errors.As(err, &unknown) {
		t.Fatalf("udp: %v", err)
	}
	for _, addr := range []string{"nohost", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:http"} {
		if _, err := dial(ctx, "tcp", addr); err == nil {
			t.Fatalf("%q was accepted", addr)
		}
	}
}

func TestNetListenerAccept(t *testing.T) {
	ln, err := ListenConfig("127.0.0.1", 0, testPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	nl := ln.NetListener()
	if nl.Addr().String() != ln.Addr().String() {
		t.Fatal("NetListener reports a different address")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), streamTestDeadline)
		defer cancel()
		if c, err := DialContextFunc(testPassword, nil)(ctx, "tcp", nl.Addr().String()); err == nil {
			c.Write([]byte("hi"))
			c.Close()
		}
	}()
	c, err := nl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("read %q, %v", buf, err)
	}
	c.Close()
	if err := nl.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := nl.Accept(); c != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v, %v", c, err)
	}
}
