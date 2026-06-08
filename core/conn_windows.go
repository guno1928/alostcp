//go:build windows

package core

import "net"

func applySocketOpts(conn *net.TCPConn) {
	conn.SetNoDelay(true)
}
