package core

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

var randReader = rand.Reader

var ErrConnClosed = errors.New("alostcp: connection closed")

// Conn is an encrypted TCP connection.
type Conn struct {
	closed  atomic.Bool
	tcp     *net.TCPConn
	cipher  *Cipher
	br      *bufio.Reader
	bw      *bufio.Writer
	wmu sync.Mutex
	rmu     sync.Mutex
}

// Send encrypts and transmits a framed message.
func (c *Conn) Send(data []byte) error {
	if c.closed.Load() {
		return ErrConnClosed
	}

	cipherLen := len(data)
	frame := getFrame(4 + cipherLen)

	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))
	c.cipher.encrypt(frame[4:], data)

	c.wmu.Lock()
	if c.closed.Load() {
		c.wmu.Unlock()
		putFrame(frame)
		return ErrConnClosed
	}
	_, err := c.bw.Write(frame)
	if err != nil {
		c.wmu.Unlock()
		putFrame(frame)
		return err
	}
	err = c.bw.Flush()
	c.wmu.Unlock()
	putFrame(frame)
	return err
}

// SendBuffered encrypts and queues a framed message without flushing.
// Call Flush to transmit the batch.
func (c *Conn) SendBuffered(data []byte) error {
	if c.closed.Load() {
		return ErrConnClosed
	}

	cipherLen := len(data)
	frame := getFrame(4 + cipherLen)

	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))
	c.cipher.encrypt(frame[4:], data)

	c.wmu.Lock()
	if c.closed.Load() {
		c.wmu.Unlock()
		putFrame(frame)
		return ErrConnClosed
	}
	_, err := c.bw.Write(frame)
	c.wmu.Unlock()
	putFrame(frame)
	return err
}

// Flush writes any buffered data to the underlying TCP connection.
func (c *Conn) Flush() error {
	c.wmu.Lock()
	if c.closed.Load() {
		c.wmu.Unlock()
		return ErrConnClosed
	}
	err := c.bw.Flush()
	c.wmu.Unlock()
	return err
}

// SendString encrypts and transmits a string message.
func (c *Conn) SendString(s string) error {
	return c.Send(stringToBytes(s))
}

// Recv reads and decrypts one framed message.
func (c *Conn) Recv() ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}

	c.rmu.Lock()
	if c.closed.Load() {
		c.rmu.Unlock()
		return nil, ErrConnClosed
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.br, lenBuf[:]); err != nil {
		c.rmu.Unlock()
		return nil, err
	}
	cipherLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if cipherLen < 0 || cipherLen > 1024*1024*64 {
		c.rmu.Unlock()
		return nil, errors.New("alostcp: invalid frame length")
	}

	plain := make([]byte, cipherLen)
	if _, err := io.ReadFull(c.br, plain); err != nil {
		c.rmu.Unlock()
		return nil, err
	}

	c.cipher.decrypt(plain, plain)
	c.rmu.Unlock()
	return plain, nil
}

// RecvInto reads and decrypts one framed message into the provided buffer.
// It returns the number of bytes written to buf. If the message is larger
// than len(buf), it returns an error.
func (c *Conn) RecvInto(buf []byte) (int, error) {
	if c.closed.Load() {
		return 0, ErrConnClosed
	}

	c.rmu.Lock()
	if c.closed.Load() {
		c.rmu.Unlock()
		return 0, ErrConnClosed
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.br, lenBuf[:]); err != nil {
		c.rmu.Unlock()
		return 0, err
	}
	cipherLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if cipherLen < 0 || cipherLen > 1024*1024*64 {
		c.rmu.Unlock()
		return 0, errors.New("alostcp: invalid frame length")
	}
	if cipherLen > len(buf) {
		c.rmu.Unlock()
		return 0, errors.New("alostcp: message larger than provided buffer")
	}

	if _, err := io.ReadFull(c.br, buf[:cipherLen]); err != nil {
		c.rmu.Unlock()
		return 0, err
	}

	c.cipher.decrypt(buf[:cipherLen], buf[:cipherLen])
	c.rmu.Unlock()
	return cipherLen, nil
}

// RecvString reads and decrypts one framed message as a string.
func (c *Conn) RecvString() (string, error) {
	b, err := c.Recv()
	if err != nil {
		return "", err
	}
	return bytesToString(b), nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.tcp.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr { return c.tcp.RemoteAddr() }

// Close closes the connection.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.tcp.Close()
}

// SetNoDelay controls whether the operating system delays packet
// transmission in hopes of sending fewer packets (Nagle's algorithm).
func (c *Conn) SetNoDelay(noDelay bool) error {
	return c.tcp.SetNoDelay(noDelay)
}
