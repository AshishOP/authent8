// Package net provides network utility functions.
package net

import (
	"net"
	"time"
)

// HasInternet performs a fast connectivity check by dialing Cloudflare DNS.
func HasInternet(timeout time.Duration) bool {
	if timeout == 0 {
		timeout = 2500 * time.Millisecond
	}
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
