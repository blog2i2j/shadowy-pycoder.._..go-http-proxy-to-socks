//go:build !linux
// +build !linux

package gohpts

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

type tproxyServer struct {
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
	pa       *proxyapp
}

func newTproxyServer(pa *proxyapp) *tproxyServer {
	_ = pa
	return nil
}

func (ts *tproxyServer) ListenAndServe() {
	ts.serve()
}

func (ts *tproxyServer) serve() {
	ts.handleConnection(nil)
}

func (ts *tproxyServer) getOriginalDst(rawConn syscall.RawConn) (string, error) {
	_ = rawConn
	return "", nil
}

func (ts *tproxyServer) handleConnection(srcConn net.Conn) {
	_ = srcConn
	ts.getOriginalDst(nil)
}

func (ts *tproxyServer) Shutdown() {}

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	_ = mark
	return &net.Dialer{Timeout: timeout}
}

func getDefaultInterface() (*net.Interface, error) {
	return nil, fmt.Errorf("not implemented")
}
