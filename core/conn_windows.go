//go:build windows

package core

import (
	"bufio"
	"fmt"
	"net"
)

// Connect dials an encrypted TCP connection.
func Connect(ip string, port int, password string) (*Conn, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, err
	}
	conn.SetNoDelay(true)
	otp, err := clientHandshake(conn, password)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ivA, ivB := deriveIVs(password, otp)
	c := &Conn{tcp: conn, cipher: newCipher(password, ivB[:], ivA[:])}
	c.br = bufio.NewReaderSize(conn, 256*1024)
	c.bw = bufio.NewWriterSize(conn, 256*1024)
	return c, nil
}

// Listener accepts encrypted TCP connections.
type Listener struct {
	ln       *net.TCPListener
	password string
}

// Accept waits for and returns the next encrypted connection.
func (ln *Listener) Accept() (*Conn, error) {
	conn, err := ln.ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	conn.SetNoDelay(true)
	otp, err := serverHandshake(conn, ln.password)
	if err != nil {
		return nil, err
	}
	ivA, ivB := deriveIVs(ln.password, otp)
	c := &Conn{tcp: conn, cipher: newCipher(ln.password, ivA[:], ivB[:])}
	c.br = bufio.NewReaderSize(conn, 256*1024)
	c.bw = bufio.NewWriterSize(conn, 256*1024)
	return c, nil
}

// Close stops listening.
func (ln *Listener) Close() error {
	return ln.ln.Close()
}

// Addr returns the listener's network address.
func (ln *Listener) Addr() net.Addr {
	return ln.ln.Addr()
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
