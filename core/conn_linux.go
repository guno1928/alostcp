//go:build linux

package core

import (
	"net"

	"golang.org/x/sys/unix"
)

func applySocketOpts(conn *net.TCPConn) error {
	if err := conn.SetNoDelay(true); err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockoptErr error
	if err := raw.Control(func(fd uintptr) {
		sockoptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
	}); err != nil {
		return err
	}
	return sockoptErr
}
