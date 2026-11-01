package core

import (
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	frameOverhead             = frameHeaderSize + tagSize
	minBufferSize             = 64 << 10
	maxBufferSize             = 64 << 20
	minMessageLimit           = 1 << 10
	maxPendingHandshakesLimit = 65536
)

var ErrInvalidConfig = errors.New("alostcp: invalid config")

type Config struct {
	ReadBufferSize       int
	WriteBufferSize      int
	MaxMessageSize       int
	HandshakeTimeout     time.Duration
	MaxPendingHandshakes int
	KeepAlive            *net.KeepAliveConfig
	AcceptFilter         func(remote net.Addr) bool
}

type connSettings struct {
	readBufferSize  int
	writeBufferSize int
	recvLimit       int
	keepAlive       *net.KeepAliveConfig
}

type listenSettings struct {
	handshakeTimeout time.Duration
	maxPending       int
	acceptFilter     func(net.Addr) bool
}

func defaultConnSettings() connSettings {
	return connSettings{
		readBufferSize:  connBufferSize,
		writeBufferSize: connBufferSize,
		recvLimit:       MaxMessageSize,
	}
}

func (c *Config) normalize() (connSettings, listenSettings, error) {
	conn := defaultConnSettings()
	listen := listenSettings{
		handshakeTimeout: defaultHandshakeTimeout,
		maxPending:       defaultMaxPendingHandshakes,
	}
	if c == nil {
		return conn, listen, nil
	}

	var err error
	if conn.readBufferSize, err = intSetting("ReadBufferSize", c.ReadBufferSize, conn.readBufferSize, minBufferSize, maxBufferSize); err != nil {
		return connSettings{}, listenSettings{}, err
	}
	if conn.writeBufferSize, err = intSetting("WriteBufferSize", c.WriteBufferSize, conn.writeBufferSize, minBufferSize, maxBufferSize); err != nil {
		return connSettings{}, listenSettings{}, err
	}
	if conn.recvLimit, err = intSetting("MaxMessageSize", c.MaxMessageSize, conn.recvLimit, minMessageLimit, MaxMessageSize); err != nil {
		return connSettings{}, listenSettings{}, err
	}
	if listen.maxPending, err = intSetting("MaxPendingHandshakes", c.MaxPendingHandshakes, listen.maxPending, 1, maxPendingHandshakesLimit); err != nil {
		return connSettings{}, listenSettings{}, err
	}
	switch {
	case c.HandshakeTimeout < 0:
		return connSettings{}, listenSettings{}, fmt.Errorf("%w: HandshakeTimeout %v is negative", ErrInvalidConfig, c.HandshakeTimeout)
	case c.HandshakeTimeout > 0:
		listen.handshakeTimeout = c.HandshakeTimeout
	}
	if ka := c.KeepAlive; ka != nil {
		if ka.Idle < 0 || ka.Interval < 0 || ka.Count < 0 {
			return connSettings{}, listenSettings{}, fmt.Errorf("%w: KeepAlive fields must not be negative", ErrInvalidConfig)
		}
		copied := *ka
		conn.keepAlive = &copied
	}
	listen.acceptFilter = c.AcceptFilter
	return conn, listen, nil
}

func intSetting(name string, value, fallback, lo, hi int) (int, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < lo || value > hi {
		return 0, fmt.Errorf("%w: %s %d outside [%d, %d]", ErrInvalidConfig, name, value, lo, hi)
	}
	return value, nil
}

func dialerFor(settings *connSettings) net.Dialer {
	ka := settings.keepAlive
	switch {
	case ka == nil:
		return net.Dialer{}
	case !ka.Enable:
		return net.Dialer{KeepAlive: -1}
	default:
		return net.Dialer{KeepAliveConfig: *ka}
	}
}

func applyKeepAlive(conn *net.TCPConn, settings *connSettings) error {
	if settings.keepAlive == nil {
		return nil
	}
	return conn.SetKeepAliveConfig(*settings.keepAlive)
}
