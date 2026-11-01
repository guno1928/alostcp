//go:build !linux

package core

import "net"

func applySocketOpts(conn *net.TCPConn) error {
	return conn.SetNoDelay(true)
}
