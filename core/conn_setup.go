package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"
)

// Connect dials an encrypted TCP connection. It blocks until the TCP
// connection and password handshake complete.
func Connect(ip string, port int, password string) (*Conn, error) {
	return ConnectContext(context.Background(), ip, port, password)
}

// ConnectTimeout dials an encrypted TCP connection, bounding the combined TCP
// connect and handshake by timeout.
func ConnectTimeout(ip string, port int, password string, timeout time.Duration) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return ConnectContext(ctx, ip, port, password)
}

// ConnectContext dials an encrypted TCP connection. The context bounds both the
// TCP connect and the password handshake; if it has a deadline, that deadline
// is applied to the handshake I/O and cleared once the handshake succeeds.
func ConnectContext(ctx context.Context, ip string, port int, password string) (*Conn, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := nc.(*net.TCPConn)
	applySocketOpts(conn)

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	otp, err := clientHandshake(conn, password)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})

	ivA, ivB := deriveIVs(password, otp)
	c := &Conn{tcp: conn, cipher: newConnCipher(password, ivB[:], ivA[:])}
	c.br = bufio.NewReaderSize(conn, 256*1024)
	c.bw = bufio.NewWriterSize(conn, 256*1024)
	return c, nil
}

// Listener accepts encrypted TCP connections.
type Listener struct {
	ln       *net.TCPListener
	password string
}

// Listen starts an encrypted TCP listener on the given port.
func Listen(port int, password string) (*Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln, password: password}, nil
}

// Accept waits for and returns the next encrypted connection.
func (ln *Listener) Accept() (*Conn, error) {
	conn, err := ln.ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	applySocketOpts(conn)
	otp, err := serverHandshake(conn, ln.password)
	if err != nil {
		return nil, err
	}
	ivA, ivB := deriveIVs(ln.password, otp)
	c := &Conn{tcp: conn, cipher: newConnCipher(ln.password, ivA[:], ivB[:])}
	c.br = bufio.NewReaderSize(conn, 256*1024)
	c.bw = bufio.NewWriterSize(conn, 256*1024)
	return c, nil
}

// SetDeadline sets the deadline for future Accept calls. A zero value disables
// the deadline.
func (ln *Listener) SetDeadline(t time.Time) error {
	return ln.ln.SetDeadline(t)
}

// Close stops listening.
func (ln *Listener) Close() error {
	return ln.ln.Close()
}

// Addr returns the listener's network address.
func (ln *Listener) Addr() net.Addr {
	return ln.ln.Addr()
}
