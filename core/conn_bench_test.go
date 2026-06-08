package core

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
)

func newConnPair(tb testing.TB) (client, server *Conn) {
	tb.Helper()
	const password = "benchmark-password"

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	listener := &Listener{ln: ln, password: password}

	var wg sync.WaitGroup
	wg.Add(1)
	var srvErr error
	go func() {
		defer wg.Done()
		server, srvErr = listener.Accept()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	client, err = Connect("127.0.0.1", addr.Port, password)
	if err != nil {
		tb.Fatal(err)
	}
	wg.Wait()
	if srvErr != nil {
		tb.Fatal(srvErr)
	}

	tb.Cleanup(func() {
		client.Close()
		server.Close()
		listener.Close()
	})
	return client, server
}

func BenchmarkTCPRoundTrip(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			client, server := newConnPair(b)
			msg := make([]byte, size)
			rand.Read(msg)

			done := make(chan error, 1)
			go func() {
				buf := make([]byte, size)
				for i := 0; i < b.N; i++ {
					n, err := server.RecvInto(buf)
					if err != nil {
						done <- err
						return
					}
					if err := server.Send(buf[:n]); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()

			recv := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := client.Send(msg); err != nil {
					b.Fatal(err)
				}
				if _, err := client.RecvInto(recv); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
		})
	}
}

func BenchmarkTCPStream(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			client, server := newConnPair(b)
			msg := make([]byte, size)
			rand.Read(msg)

			done := make(chan error, 1)
			go func() {
				buf := make([]byte, size)
				for i := 0; i < b.N; i++ {
					if _, err := server.RecvInto(buf); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := client.SendBuffered(msg); err != nil {
					b.Fatal(err)
				}
			}
			if err := client.Flush(); err != nil {
				b.Fatal(err)
			}
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
		})
	}
}
