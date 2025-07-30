//go:build !linux
// +build !linux

package gohpts

import (
	"net"
	"sync"
	"syscall"
	"time"
)

type tproxyServer struct {
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
	p        *proxyapp
}

func newTproxyServer(p *proxyapp) *tproxyServer {
	_ = p
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

func (ts *tproxyServer) applyRedirectRules() string {
	return ""
}

func (ts *tproxyServer) clearRedirectRules(output string) error {
	_ = output
	return nil
}
