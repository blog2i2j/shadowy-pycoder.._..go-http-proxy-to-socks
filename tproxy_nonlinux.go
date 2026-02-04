//go:build !linux && !(android && arm)

package gohpts

import (
	"net"
	"sync"
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
}

func (ts *tproxyServer) Shutdown() {}

func (ts *tproxyServer) ApplyRedirectRules(opts map[string]string) map[string]string {
	_ = opts
	return nil
}

func (ts *tproxyServer) ClearRedirectRules() error {
	return nil
}
