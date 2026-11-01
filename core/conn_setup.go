package core

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHandshakeTimeout     = 5 * time.Second
	defaultMaxPendingHandshakes = 1024
	minAcceptBackoff            = 5 * time.Millisecond
	maxAcceptBackoff            = time.Second
)

var deadlineInThePast = time.Unix(1, 0)

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
	return DialConfig(ctx, ip, port, password, nil)
}

func DialConfig(ctx context.Context, ip string, port int, password string, cfg *Config) (*Conn, error) {
	if !hardwareAEGIS {
		return nil, ErrUnsupportedCPU
	}
	settings, _, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	pwKey, err := derivePasswordKeyContext(ctx, password)
	if err != nil {
		return nil, err
	}
	d := dialerFor(&settings)
	nc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	conn := nc.(*net.TCPConn)
	keys, err := clientHandshakeContext(ctx, conn, &pwKey, settings.recvLimit)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return newConn(conn, &keys, &settings), nil
}

func clientHandshakeContext(ctx context.Context, conn *net.TCPConn, pwKey *passwordKey, recvLimit int) (sessionKeys, error) {
	if err := applySocketOpts(conn); err != nil {
		return sessionKeys{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return sessionKeys{}, err
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(deadlineInThePast)
	})
	keys, err := clientHandshake(conn, pwKey, recvLimit)
	if !stop() || (err != nil && ctx.Err() != nil) {
		return sessionKeys{}, handshakeIOError(ctx.Err())
	}
	if err != nil {
		return sessionKeys{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return sessionKeys{}, err
	}
	return keys, nil
}

// Listener accepts encrypted TCP connections.
type Listener struct {
	ln               *net.TCPListener
	pwKey            passwordKey
	settings         connSettings
	acceptFilter     func(net.Addr) bool
	handshakeTimeout atomic.Int64

	acceptStarted atomic.Bool
	startOnce     sync.Once
	ready         chan *Conn
	done          chan struct{}
	slots         chan struct{}
	closeOnce     sync.Once
	closeErr      error
	wg            sync.WaitGroup

	mu              sync.Mutex
	deadline        time.Time
	deadlineChanged chan struct{}
	closed          bool
	pending         map[*net.TCPConn]struct{}
}

// Listen starts an encrypted TCP listener on the given port.
func Listen(port int, password string) (*Listener, error) {
	return ListenHost("", port, password)
}

func ListenHost(host string, port int, password string) (*Listener, error) {
	return ListenConfig(host, port, password, nil)
}

func ListenConfig(host string, port int, password string, cfg *Config) (*Listener, error) {
	if !hardwareAEGIS {
		return nil, ErrUnsupportedCPU
	}
	settings, listen, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	pwKey, err := derivePasswordKey(password)
	if err != nil {
		return nil, err
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		ln:              ln,
		pwKey:           pwKey,
		settings:        settings,
		acceptFilter:    listen.acceptFilter,
		ready:           make(chan *Conn),
		done:            make(chan struct{}),
		slots:           make(chan struct{}, listen.maxPending),
		deadlineChanged: make(chan struct{}),
		pending:         make(map[*net.TCPConn]struct{}),
	}
	l.handshakeTimeout.Store(int64(listen.handshakeTimeout))
	return l, nil
}

func (ln *Listener) SetHandshakeTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	ln.handshakeTimeout.Store(int64(timeout))
}

// Accept waits for and returns the next encrypted connection.
func (ln *Listener) Accept() (*Conn, error) {
	ln.startOnce.Do(ln.startAcceptLoop)
	for {
		select {
		case <-ln.done:
			return nil, ln.acceptError(net.ErrClosed)
		default:
		}
		ln.mu.Lock()
		deadline := ln.deadline
		deadlineChanged := ln.deadlineChanged
		ln.mu.Unlock()

		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return nil, ln.acceptError(os.ErrDeadlineExceeded)
			}
			timer = time.NewTimer(wait)
			expired = timer.C
		}

		select {
		case c := <-ln.ready:
			stopTimer(timer)
			return c, nil
		case <-ln.done:
			stopTimer(timer)
			return nil, ln.acceptError(net.ErrClosed)
		case <-expired:
		case <-deadlineChanged:
			stopTimer(timer)
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func (ln *Listener) acceptError(err error) error {
	return &net.OpError{Op: "accept", Net: "tcp", Addr: ln.ln.Addr(), Err: err}
}

func (ln *Listener) startAcceptLoop() {
	ln.mu.Lock()
	if ln.closed {
		ln.mu.Unlock()
		return
	}
	ln.acceptStarted.Store(true)
	ln.wg.Add(1)
	ln.mu.Unlock()
	_ = ln.ln.SetDeadline(time.Time{})
	go ln.acceptLoop()
}

func (ln *Listener) acceptLoop() {
	defer ln.wg.Done()
	var backoff time.Duration
	for {
		select {
		case ln.slots <- struct{}{}:
		case <-ln.done:
			return
		}
		raw, err := ln.ln.AcceptTCP()
		if err != nil {
			<-ln.slots
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				_ = ln.ln.SetDeadline(time.Time{})
				continue
			}
			backoff = nextAcceptBackoff(backoff)
			if !ln.sleep(backoff) {
				return
			}
			continue
		}
		backoff = 0
		if ln.acceptFilter != nil && !ln.acceptFilter(raw.RemoteAddr()) {
			_ = raw.Close()
			<-ln.slots
			continue
		}
		if !ln.track(raw) {
			_ = raw.Close()
			<-ln.slots
			return
		}
		go ln.serveHandshake(raw)
	}
}

func nextAcceptBackoff(previous time.Duration) time.Duration {
	if previous == 0 {
		return minAcceptBackoff
	}
	return min(2*previous, maxAcceptBackoff)
}

func (ln *Listener) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ln.done:
		return false
	}
}

func (ln *Listener) track(conn *net.TCPConn) bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.closed {
		return false
	}
	ln.pending[conn] = struct{}{}
	ln.wg.Add(1)
	return true
}

func (ln *Listener) untrack(conn *net.TCPConn) {
	ln.mu.Lock()
	delete(ln.pending, conn)
	ln.mu.Unlock()
}

func (ln *Listener) serveHandshake(raw *net.TCPConn) {
	defer ln.wg.Done()
	defer func() { <-ln.slots }()
	c, err := ln.Handshake(raw)
	ln.untrack(raw)
	if err != nil {
		return
	}
	select {
	case ln.ready <- c:
	case <-ln.done:
		c.abort()
	}
}

func (ln *Listener) AcceptRaw() (*net.TCPConn, error) {
	return ln.ln.AcceptTCP()
}

func (ln *Listener) Handshake(conn *net.TCPConn) (*Conn, error) {
	keys, err := ln.serverHandshakeWithDeadline(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return newConn(conn, &keys, &ln.settings), nil
}

func (ln *Listener) serverHandshakeWithDeadline(conn *net.TCPConn) (sessionKeys, error) {
	if err := applySocketOpts(conn); err != nil {
		return sessionKeys{}, err
	}
	if err := applyKeepAlive(conn, &ln.settings); err != nil {
		return sessionKeys{}, err
	}
	timeout := time.Duration(ln.handshakeTimeout.Load())
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return sessionKeys{}, err
	}
	keys, err := serverHandshake(conn, &ln.pwKey, ln.settings.recvLimit)
	if err != nil {
		return sessionKeys{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return sessionKeys{}, err
	}
	return keys, nil
}

// SetDeadline sets the deadline for future Accept calls. A zero value disables
// the deadline.
func (ln *Listener) SetDeadline(t time.Time) error {
	ln.mu.Lock()
	ln.deadline = t
	close(ln.deadlineChanged)
	ln.deadlineChanged = make(chan struct{})
	ln.mu.Unlock()
	if ln.acceptStarted.Load() {
		return nil
	}
	return ln.ln.SetDeadline(t)
}

// Close stops listening.
func (ln *Listener) Close() error {
	ln.closeOnce.Do(func() {
		ln.mu.Lock()
		ln.closed = true
		for conn := range ln.pending {
			_ = conn.Close()
		}
		ln.mu.Unlock()
		close(ln.done)
		ln.closeErr = ln.ln.Close()
		ln.wg.Wait()
	})
	return ln.closeErr
}

// Addr returns the listener's network address.
func (ln *Listener) Addr() net.Addr {
	return ln.ln.Addr()
}
