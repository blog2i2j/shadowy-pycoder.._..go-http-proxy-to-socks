//go:build !linux
// +build !linux

package gohpts

import (
	"net"
	"os/exec"
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

func (ts *tproxyServer) createSysctlOptCmd(opt, value, setex string, opts map[string]string) *exec.Cmd {
	_ = opt
	_ = value
	_ = setex
	_ = opts
	return nil
}

func (ts *tproxyServer) applyRedirectRules() map[string]string {
	_ = ts.createSysctlOptCmd("", "", "", nil)
	return nil
}

func (ts *tproxyServer) clearRedirectRules(opts map[string]string) error {
	_ = opts
	return nil
}
