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
	"time"
)

var randReader = rand.Reader

var ErrConnClosed = errors.New("alostcp: connection closed")

// ErrConnBroken is returned once a framed read or write has failed partway
// through. Because the AEGIS stream cannot be resynchronized after a partial
// frame, the connection is poisoned and all further operations fail.
var ErrConnBroken = errors.New("alostcp: connection broken")

// Conn is an encrypted TCP connection.
type Conn struct {
	closed  atomic.Bool
	broken  atomic.Bool
	tcp     *net.TCPConn
	cipher  *aeadCipher
	br      *bufio.Reader
	bw      *bufio.Writer
	wmu sync.Mutex
	rmu     sync.Mutex
}

func (c *Conn) stateErr() error {
	if c.broken.Load() {
		return ErrConnBroken
	}
	if c.closed.Load() {
		return ErrConnClosed
	}
	return nil
}

// poison marks the connection broken after a partial framed I/O failure and
// closes the underlying socket. It returns ErrConnBroken if err is nil.
func (c *Conn) poison(err error) error {
	c.broken.Store(true)
	c.tcp.Close()
	if err == nil {
		return ErrConnBroken
	}
	return err
}

// Send encrypts and transmits a framed message.
func (c *Conn) Send(data []byte) error {
	if err := c.stateErr(); err != nil {
		return err
	}

	cipherLen := len(data) + tagSize
	frame := getFrame(4 + cipherLen)

	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))

	c.wmu.Lock()
	if err := c.stateErr(); err != nil {
		c.wmu.Unlock()
		putFrame(frame)
		return err
	}
	c.cipher.seal(frame[4:], data, frame[0:4])
	_, err := c.bw.Write(frame)
	if err != nil {
		err = c.poison(err)
		c.wmu.Unlock()
		putFrame(frame)
		return err
	}
	if err = c.bw.Flush(); err != nil {
		err = c.poison(err)
	}
	c.wmu.Unlock()
	putFrame(frame)
	return err
}

// SendBuffered encrypts and queues a framed message without flushing.
// Call Flush to transmit the batch.
func (c *Conn) SendBuffered(data []byte) error {
	if err := c.stateErr(); err != nil {
		return err
	}

	cipherLen := len(data) + tagSize
	frame := getFrame(4 + cipherLen)

	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))

	c.wmu.Lock()
	if err := c.stateErr(); err != nil {
		c.wmu.Unlock()
		putFrame(frame)
		return err
	}
	c.cipher.seal(frame[4:], data, frame[0:4])
	_, err := c.bw.Write(frame)
	if err != nil {
		err = c.poison(err)
	}
	c.wmu.Unlock()
	putFrame(frame)
	return err
}

// Flush writes any buffered data to the underlying TCP connection.
func (c *Conn) Flush() error {
	c.wmu.Lock()
	if err := c.stateErr(); err != nil {
		c.wmu.Unlock()
		return err
	}
	err := c.bw.Flush()
	if err != nil {
		err = c.poison(err)
	}
	c.wmu.Unlock()
	return err
}

// SendString encrypts and transmits a string message.
func (c *Conn) SendString(s string) error {
	return c.Send(stringToBytes(s))
}

// Recv reads and decrypts one framed message.
func (c *Conn) Recv() ([]byte, error) {
	if err := c.stateErr(); err != nil {
		return nil, err
	}

	c.rmu.Lock()
	if err := c.stateErr(); err != nil {
		c.rmu.Unlock()
		return nil, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.br, lenBuf[:]); err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		return nil, err
	}
	cipherLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if cipherLen < tagSize || cipherLen > 1024*1024*64 {
		err := c.poison(errors.New("alostcp: invalid frame length"))
		c.rmu.Unlock()
		return nil, err
	}

	buf := make([]byte, cipherLen)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		return nil, err
	}

	plain, err := c.cipher.open(buf[:0], buf, lenBuf[:])
	if err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		return nil, err
	}
	c.rmu.Unlock()
	return plain, nil
}

// RecvInto reads and decrypts one framed message into the provided buffer.
// It returns the number of bytes written to buf. If the message is larger
// than len(buf), it returns an error.
func (c *Conn) RecvInto(buf []byte) (int, error) {
	if err := c.stateErr(); err != nil {
		return 0, err
	}

	c.rmu.Lock()
	if err := c.stateErr(); err != nil {
		c.rmu.Unlock()
		return 0, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.br, lenBuf[:]); err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		return 0, err
	}
	cipherLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if cipherLen < tagSize || cipherLen > 1024*1024*64 {
		err := c.poison(errors.New("alostcp: invalid frame length"))
		c.rmu.Unlock()
		return 0, err
	}
	plainLen := cipherLen - tagSize
	if plainLen > len(buf) {
		err := c.poison(errors.New("alostcp: message larger than provided buffer"))
		c.rmu.Unlock()
		return 0, err
	}

	tmp := getFrame(cipherLen)
	if _, err := io.ReadFull(c.br, tmp); err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		putFrame(tmp)
		return 0, err
	}

	_, err := c.cipher.open(buf[:0], tmp, lenBuf[:])
	if err != nil {
		err = c.poison(err)
		c.rmu.Unlock()
		putFrame(tmp)
		return 0, err
	}
	c.rmu.Unlock()
	putFrame(tmp)
	return plainLen, nil
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

// SetDeadline sets the read and write deadlines on the connection.
//
// If a Send or Recv exceeds a deadline mid-frame, the encrypted stream can no
// longer be resynchronized: the connection is poisoned and all further
// operations return ErrConnBroken.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.tcp.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Recv and RecvInto calls.
// See SetDeadline for the consequences of a mid-frame timeout.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.tcp.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Send, SendBuffered, and Flush
// calls. See SetDeadline for the consequences of a mid-frame timeout.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tcp.SetWriteDeadline(t)
}
