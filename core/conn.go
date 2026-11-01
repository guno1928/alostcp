package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/cpu"
)

const (
	frameHeaderSize      = 4
	maxCiphertextSize    = 64 << 20
	closeNotifyFlag      = uint32(1) << 31
	connBufferSize       = 256 << 10
	readBufferSize       = connBufferSize + frameHeaderSize + tagSize
	largeFrameReadChunk  = 2 * connBufferSize
	gracefulCloseTimeout = time.Second
)

const MaxMessageSize = maxCiphertextSize - tagSize

var ErrConnClosed = errors.New("alostcp: connection closed")

// ErrConnBroken is returned once a framed read or write has failed partway
// through. Because the AEGIS stream cannot be resynchronized after a partial
// frame, the connection is poisoned and all further operations fail.
var ErrConnBroken = errors.New("alostcp: connection broken")

var ErrMessageTooLarge = errors.New("alostcp: message exceeds MaxMessageSize")

var (
	errInvalidFrame = errors.New("alostcp: invalid frame header")
	errAuthFailed   = errors.New("alostcp: message authentication failed")
	errTruncated    = fmt.Errorf("alostcp: connection ended without a close notification: %w", io.ErrUnexpectedEOF)
)

// Conn is an encrypted TCP connection.
type Conn struct {
	tcp           *net.TCPConn
	closed        atomic.Bool
	broken        atomic.Bool
	brokenErr     atomic.Pointer[brokenError]
	writeDeadline atomic.Int64

	_         cpu.CacheLinePad
	wmu       sync.Mutex
	sealer    sealer
	wbuf      []byte
	wn        int
	sendLimit int

	_               cpu.CacheLinePad
	rmu             sync.Mutex
	opener          opener
	br              *bufio.Reader
	largeHdr        [frameHeaderSize]byte
	peerClosed      bool
	recvCipherLimit int
	largeReadChunk  int
	pending         []byte
	streamBuf       []byte
	streamRetain    int
}

type readMode uint8

const (
	readAlloc readMode = iota
	readInto
	readStream
)

func newConn(tcp *net.TCPConn, keys *sessionKeys, settings *connSettings) *Conn {
	c := &Conn{
		tcp:             tcp,
		sealer:          sealer{engine: newAEGISEngine(&keys.send)},
		opener:          opener{engine: newAEGISEngine(&keys.recv)},
		wbuf:            make([]byte, settings.writeBufferSize),
		sendLimit:       min(settings.recvLimit, keys.peerRecvLimit),
		br:              bufio.NewReaderSize(tcp, settings.readBufferSize+frameOverhead),
		recvCipherLimit: settings.recvLimit + tagSize,
		largeReadChunk:  2 * settings.readBufferSize,
		streamRetain:    settings.readBufferSize,
	}
	clear(keys.send[:])
	clear(keys.recv[:])
	return c
}

func (c *Conn) stateErr() error {
	if c.closed.Load() {
		return ErrConnClosed
	}
	if c.broken.Load() {
		if err := c.brokenErr.Load(); err != nil {
			return err
		}
		return ErrConnBroken
	}
	return nil
}

// poison marks the connection broken after a partial framed I/O failure and
// closes the underlying socket. It returns ErrConnBroken if err is nil.
func (c *Conn) poison(err error) error {
	if err == nil {
		c.broken.Store(true)
		_ = c.tcp.Close()
		return ErrConnBroken
	}
	broken := &brokenError{cause: err}
	if !c.brokenErr.CompareAndSwap(nil, broken) {
		broken = c.brokenErr.Load()
	}
	c.broken.Store(true)
	_ = c.tcp.Close()
	return broken
}

func (c *Conn) writeStateErr() error {
	err := c.stateErr()
	if err != nil {
		c.sealer.wipe()
	}
	return err
}

func (c *Conn) failWrite(err error) error {
	c.sealer.wipe()
	if c.closed.Load() {
		return ErrConnClosed
	}
	return c.poison(err)
}

func (c *Conn) failRead(err error) error {
	c.opener.wipe()
	if c.closed.Load() {
		return ErrConnClosed
	}
	return c.poison(err)
}

func frameHeader(plaintextLen int, flags uint32) uint32 {
	return uint32(plaintextLen+tagSize) | flags
}

// Send encrypts and transmits a framed message.
func (c *Conn) Send(data []byte) error {
	if len(data) > c.sendLimit {
		return ErrMessageTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeStateErr(); err != nil {
		return err
	}
	if err := c.writeFrame(data, frameHeader(len(data), 0)); err != nil {
		return c.failWrite(err)
	}
	if err := c.flushLocked(); err != nil {
		return c.failWrite(err)
	}
	return nil
}

// SendBuffered encrypts and queues a framed message without flushing.
// Call Flush to transmit the batch.
func (c *Conn) SendBuffered(data []byte) error {
	if len(data) > c.sendLimit {
		return ErrMessageTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeStateErr(); err != nil {
		return err
	}
	if err := c.writeFrame(data, frameHeader(len(data), 0)); err != nil {
		return c.failWrite(err)
	}
	return nil
}

// Flush writes any buffered data to the underlying TCP connection.
func (c *Conn) Flush() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeStateErr(); err != nil {
		return err
	}
	if err := c.flushLocked(); err != nil {
		return c.failWrite(err)
	}
	return nil
}

// SendString encrypts and transmits a string message.
func (c *Conn) SendString(s string) error {
	return c.Send(stringToBytes(s))
}

func (c *Conn) writeFrame(plaintext []byte, header uint32) error {
	frameLen := frameHeaderSize + len(plaintext) + tagSize
	if frameLen <= len(c.wbuf)-c.wn {
		c.sealFrame(c.wbuf[c.wn:c.wn+frameLen], plaintext, header)
		c.wn += frameLen
		return nil
	}
	frame := getFrame(frameLen)
	c.sealFrame(*frame, plaintext, header)
	err := c.writeThroughBuffer(*frame)
	putFrame(frame)
	return err
}

func (c *Conn) sealFrame(frame, plaintext []byte, header uint32) {
	binary.BigEndian.PutUint32(frame[:frameHeaderSize], header)
	c.sealer.seal(frame[frameHeaderSize:], plaintext, frame[:frameHeaderSize])
}

func (c *Conn) writeThroughBuffer(p []byte) error {
	for len(p) > len(c.wbuf)-c.wn {
		if c.wn == 0 {
			_, err := c.tcp.Write(p)
			return err
		}
		n := copy(c.wbuf[c.wn:], p)
		c.wn += n
		p = p[n:]
		if err := c.flushLocked(); err != nil {
			return err
		}
	}
	c.wn += copy(c.wbuf[c.wn:], p)
	return nil
}

func (c *Conn) flushLocked() error {
	if c.wn == 0 {
		return nil
	}
	n, err := c.tcp.Write(c.wbuf[:c.wn])
	if err != nil {
		c.wn = copy(c.wbuf, c.wbuf[n:c.wn])
		return err
	}
	c.wn = 0
	return nil
}

// Recv reads and decrypts one framed message.
func (c *Conn) Recv() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.hasPending() {
		msg := slices.Clone(c.pending)
		c.dropPending()
		return msg, nil
	}
	msg, _, err := c.readMessage(nil, readAlloc)
	return msg, err
}

// RecvInto reads and decrypts one framed message into the provided buffer.
// It returns the number of bytes written to buf. If the message is larger
// than len(buf), it returns an error.
func (c *Conn) RecvInto(buf []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.hasPending() {
		if len(c.pending) > len(buf) {
			return len(c.pending), shortBufferError(len(c.pending))
		}
		n := copy(buf, c.pending)
		c.dropPending()
		return n, nil
	}
	_, n, err := c.readMessage(buf, readInto)
	return n, err
}

func (c *Conn) hasPending() bool {
	return len(c.pending) > 0 && c.stateErr() == nil
}

func (c *Conn) dropPending() {
	c.pending = nil
	if cap(c.streamBuf) > c.streamRetain {
		c.streamBuf = nil
	}
}

func (c *Conn) streamBuffer(size int) []byte {
	if cap(c.streamBuf) < size {
		c.streamBuf = make([]byte, size)
	}
	return c.streamBuf[:size]
}

func shortBufferError(size int) error {
	return fmt.Errorf("alostcp: %d-byte message: %w", size, io.ErrShortBuffer)
}

// RecvString reads and decrypts one framed message as a string.
func (c *Conn) RecvString() (string, error) {
	b, err := c.Recv()
	if err != nil {
		return "", err
	}
	return bytesToString(b), nil
}

func (c *Conn) readMessage(dst []byte, mode readMode) ([]byte, int, error) {
	if err := c.stateErr(); err != nil {
		c.opener.wipe()
		return nil, 0, err
	}
	if c.peerClosed {
		return nil, 0, io.EOF
	}

	header, err := c.br.Peek(frameHeaderSize)
	if err != nil {
		return nil, 0, c.failBeforeFrame(err, len(header))
	}
	word := binary.BigEndian.Uint32(header)
	closeNotify := word&closeNotifyFlag != 0
	cipherLen := int(word &^ closeNotifyFlag)
	if cipherLen < tagSize || cipherLen > c.recvCipherLimit || (closeNotify && cipherLen != tagSize) {
		return nil, 0, c.failRead(errInvalidFrame)
	}
	plainLen := cipherLen - tagSize
	if mode == readInto && plainLen > len(dst) {
		return nil, plainLen, shortBufferError(plainLen)
	}

	frameLen := frameHeaderSize + cipherLen
	var msg []byte
	switch {
	case mode == readInto, mode == readStream && plainLen <= len(dst):
		msg = dst[:plainLen]
	case mode == readStream && frameLen <= c.br.Size():
		msg = c.streamBuffer(plainLen)
	}
	if frameLen <= c.br.Size() {
		frame, err := c.br.Peek(frameLen)
		if err != nil {
			return nil, 0, c.failBeforeFrame(err, len(frame))
		}
		if msg == nil {
			msg = make([]byte, plainLen)
		}
		body := frame[frameHeaderSize:]
		if !c.opener.open(msg, body[:plainLen], body[plainLen:], frame[:frameHeaderSize]) {
			return nil, 0, c.failRead(errAuthFailed)
		}
		_, _ = c.br.Discard(frameLen)
	} else {
		copy(c.largeHdr[:], header)
		_, _ = c.br.Discard(frameHeaderSize)
		if msg, err = c.readLargeFrame(msg, plainLen); err != nil {
			return nil, 0, c.failRead(err)
		}
	}

	if closeNotify {
		c.peerClosed = true
		return nil, 0, io.EOF
	}
	return msg, plainLen, nil
}

func (c *Conn) failBeforeFrame(err error, buffered int) error {
	if c.closed.Load() {
		c.opener.wipe()
		return ErrConnClosed
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	if errors.Is(err, io.EOF) {
		if buffered == 0 {
			return c.failRead(errTruncated)
		}
		return c.failRead(io.ErrUnexpectedEOF)
	}
	return c.failRead(err)
}

func (c *Conn) readLargeFrame(msg []byte, plainLen int) ([]byte, error) {
	if msg == nil {
		sealed, err := c.readGrowing(plainLen + tagSize)
		if err != nil {
			return nil, err
		}
		msg = sealed[:plainLen]
		if !c.opener.open(msg, msg, sealed[plainLen:], c.largeHdr[:]) {
			return nil, errAuthFailed
		}
		return msg, nil
	}
	if _, err := io.ReadFull(c.br, msg); err != nil {
		return nil, err
	}
	tag, err := c.br.Peek(tagSize)
	if err != nil {
		return nil, err
	}
	if !c.opener.open(msg, msg, tag, c.largeHdr[:]) {
		return nil, errAuthFailed
	}
	_, _ = c.br.Discard(tagSize)
	return msg, nil
}

func (c *Conn) readGrowing(size int) ([]byte, error) {
	buf := make([]byte, 0, min(size, c.largeReadChunk))
	for len(buf) < size {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(len(buf), size-len(buf)))
		}
		end := min(cap(buf), size)
		n, err := io.ReadFull(c.br, buf[len(buf):end])
		buf = buf[:len(buf)+n]
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
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
	if c.wmu.TryLock() {
		if !c.broken.Load() {
			c.sendCloseNotify()
		}
		c.sealer.wipe()
		c.wmu.Unlock()
	}
	if c.rmu.TryLock() {
		c.opener.wipe()
		c.rmu.Unlock()
	}
	if err := c.tcp.Close(); err != nil && !c.broken.Load() {
		return err
	}
	return nil
}

func (c *Conn) sendCloseNotify() {
	if c.SetWriteDeadline(time.Now().Add(gracefulCloseTimeout)) != nil {
		return
	}
	if c.writeFrame(nil, frameHeader(0, closeNotifyFlag)) != nil {
		return
	}
	_ = c.flushLocked()
}

func (c *Conn) abort() {
	c.closed.Store(true)
	_ = c.tcp.Close()
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
	c.storeWriteDeadline(t)
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
	c.storeWriteDeadline(t)
	return c.tcp.SetWriteDeadline(t)
}

func (c *Conn) storeWriteDeadline(t time.Time) {
	if t.IsZero() {
		c.writeDeadline.Store(0)
		return
	}
	c.writeDeadline.Store(t.UnixNano())
}

func (c *Conn) writeDeadlinePassed() bool {
	deadline := c.writeDeadline.Load()
	return deadline != 0 && time.Now().UnixNano() >= deadline
}
