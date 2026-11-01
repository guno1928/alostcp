package core

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
)

const streamChunkSize = 64 << 10

var _ net.Conn = (*Conn)(nil)

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.hasPending() {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			c.dropPending()
		}
		return n, nil
	}
	if len(p) == 0 {
		return 0, c.stateErr()
	}
	for {
		msg, n, err := c.readMessage(p, readStream)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		if n <= len(p) {
			return n, nil
		}
		copied := copy(p, msg)
		c.pending = msg[copied:]
		return copied, nil
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeStateErr(); err != nil {
		return 0, err
	}
	if c.writeDeadlinePassed() {
		return 0, &net.OpError{Op: "write", Net: "tcp", Source: c.tcp.LocalAddr(), Addr: c.tcp.RemoteAddr(), Err: os.ErrDeadlineExceeded}
	}
	chunk := min(streamChunkSize, c.sendLimit)
	accepted := 0
	for len(p) > 0 {
		n := min(len(p), chunk)
		frameLen := n + frameOverhead
		if frameLen > len(c.wbuf)-c.wn {
			if err := c.flushStream(); err != nil {
				return accepted, err
			}
		}
		c.sealFrame(c.wbuf[c.wn:c.wn+frameLen], p[:n], frameHeader(n, 0))
		c.wn += frameLen
		accepted += n
		p = p[n:]
	}
	return accepted, c.flushStream()
}

func (c *Conn) flushStream() error {
	err := c.flushLocked()
	if err == nil || resumableWriteTimeouts && errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return c.failWrite(err)
}

type netListener struct {
	ln *Listener
}

func (l netListener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (l netListener) Close() error   { return l.ln.Close() }
func (l netListener) Addr() net.Addr { return l.ln.Addr() }

func (ln *Listener) NetListener() net.Listener {
	return netListener{ln: ln}
}

func DialContextFunc(password string, cfg *Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
		}
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: err}
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: &net.AddrError{Err: "invalid port", Addr: addr}}
		}
		c, err := DialConfig(ctx, host, port, password, cfg)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}
