//go:build !linux
// +build !linux

package gohpts

import (
	"net"
	"time"
)

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	_ = mark
	return &net.Dialer{Timeout: timeout}
}
