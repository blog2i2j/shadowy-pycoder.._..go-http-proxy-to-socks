//go:build !linux
// +build !linux

package gohpts

type tproxyServerUDP struct{}

func newTproxyServerUDP(p *proxyapp) *tproxyServerUDP {
	_ = p
	return nil
}

func (tsu *tproxyServerUDP) ListenAndServe() {
}

func (tsu *tproxyServerUDP) Shutdown() {
}

func (tsu *tproxyServerUDP) ApplyRedirectRules(opts map[string]string) {
	_ = opts
}

func (tsu *tproxyServerUDP) ClearRedirectRules() error {
	return nil
}
