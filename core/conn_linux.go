//go:build linux

package core

import (
	"net"

	"golang.org/x/sys/unix"
)

func applySocketOpts(conn *net.TCPConn) {
	conn.SetNoDelay(true)
	raw, _ := conn.SyscallConn()
	raw.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
	})
}
